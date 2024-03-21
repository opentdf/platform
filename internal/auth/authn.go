package auth

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/internal/db"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	dpopJWKContextKey = authContextKey("dpop-jwk")
)

type authContextKey string

var (
	// Set of allowed gRPC endpoints that do not require authentication
	allowedGRPCEndpoints = [...]string{
		"/grpc.health.v1.Health/Check",
		"/wellknownconfiguration.WellKnownService/GetWellKnownConfiguration",
		"/kas.AccessService/PublicKey",
	}
	// Set of allowed HTTP endpoints that do not require authentication
	allowedHTTPEndpoints = [...]string{
		"/healthz",
		"/.well-known/opentdf-configuration",
		"/kas/v2/kas_public_key",
	}
	// only asymmetric algorithms and no 'none'
	allowedSignatureAlgorithms = map[jwa.SignatureAlgorithm]bool{
		jwa.RS256: true,
		jwa.RS384: true,
		jwa.RS512: true,
		jwa.ES256: true,
		jwa.ES384: true,
		jwa.ES512: true,
		jwa.PS256: true,
		jwa.PS384: true,
		jwa.PS512: true,
	}
)

// Authentication holds a jwks cache and information about the openid configuration
type Authentication struct {
	// cache holds the jwks cache
	cache *jwk.Cache
	// openidConfigurations holds the openid configuration for each issuer
	oidcConfigurations map[string]AuthNConfig
	// Casbin enforcer
	enforcer *Enforcer
}

// Creates new authN which is used to verify tokens for a set of given issuers
func NewAuthenticator(cfg AuthNConfig, d *db.Client) (*Authentication, error) {
	a := &Authentication{}
	a.oidcConfigurations = make(map[string]AuthNConfig)

	// validate the configuration
	if err := cfg.validateAuthNConfig(); err != nil {
		return nil, err
	}

	ctx := context.Background()

	a.cache = jwk.NewCache(ctx)

	// Build new cache
	// Discover OIDC Configuration
	oidcConfig, err := DiscoverOIDCConfiguration(ctx, cfg.Issuer)
	if err != nil {
		return nil, err
	}

	cfg.OIDCConfiguration = *oidcConfig

	// Register the jwks_uri with the cache
	if err := a.cache.Register(cfg.JwksURI, jwk.WithMinRefreshInterval(15*time.Minute)); err != nil {
		return nil, err
	}

	casbinConfig := CasbinConfig{
		PolicyConfig: cfg.Policy,
	}
	if d != nil && d.SqlDB != nil {
		casbinConfig.Db = d.SqlDB
	}
	slog.Info("initializing casbin enforcer")
	if a.enforcer, err = NewCasbinEnforcer(casbinConfig); err != nil {
		return nil, fmt.Errorf("failed to initialize casbin enforcer: %w", err)
	}

	// Need to refresh the cache to verify jwks is available
	_, err = a.cache.Refresh(ctx, cfg.JwksURI)
	if err != nil {
		return nil, err
	}

	a.oidcConfigurations[cfg.Issuer] = cfg

	return a, nil
}

type dpopInfo struct {
	headers []string
	path    string
	method  string
}

// verifyTokenHandler is a http handler that verifies the token
func (a Authentication) MuxHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if slices.Contains(allowedHTTPEndpoints[:], r.URL.Path) {
			handler.ServeHTTP(w, r)
			return
		}

		// Verify the token
		header := r.Header["Authorization"]
		if len(header) < 1 {
			http.Error(w, "missing authorization header", http.StatusUnauthorized)
			return
		}
		tok, dpopKey, err := a.checkToken(r.Context(), header, dpopInfo{
			headers: r.Header["Dpop"],
			path:    r.URL.Path,
			method:  r.Method,
		})

		if err != nil {
			slog.WarnContext(r.Context(), "failed to validate token", slog.String("error", err.Error()))
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}

		// Check if the token is allowed to access the resource
		action := ""
		switch r.Method {
		case http.MethodGet:
			action = "read"
		case http.MethodPost, http.MethodPut, http.MethodPatch:
			action = "write"
		case http.MethodDelete:
			action = "delete"
		default:
			action = "unsafe"
		}
		if allow, err := a.enforcer.Enforce(tok, r.URL.Path, action); err != nil {
			if err.Error() == "permission denied" {
				slog.WarnContext(r.Context(), "permission denied", slog.String("azp", tok.Subject()), slog.String("error", err.Error()))
				http.Error(w, "permission denied", http.StatusForbidden)
				return
			}
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		} else if !allow {
			slog.WarnContext(r.Context(), "permission denied", slog.String("azp", tok.Subject()))
			http.Error(w, "permission denied", http.StatusForbidden)
			return
		}

		handler.ServeHTTP(w, r.WithContext(ContextWithJWK(r.Context(), dpopKey)))
	})
}

// UnaryServerInterceptor is a grpc interceptor that verifies the token in the metadata
func (a Authentication) UnaryServerInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	// Allow health checks to pass through
	if slices.Contains(allowedGRPCEndpoints[:], info.FullMethod) {
		return handler(ctx, req)
	}

	// Get the metadata from the context
	// The keys within metadata.MD are normalized to lowercase.
	// See: https://godoc.org/google.golang.org/grpc/metadata#New
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing metadata")
	}

	// Verify the token
	header := md["authorization"]
	if len(header) < 1 {
		return nil, status.Error(codes.Unauthenticated, "missing authorization header")
	}

	// parse the rpc method
	p := strings.Split(info.FullMethod, "/")
	resource := p[1] + "/" + p[2]
	action := ""
	if strings.HasPrefix(p[2], "List") || strings.HasPrefix(p[2], "Get") {
		action = "read"
	} else if strings.HasPrefix(p[2], "Create") || strings.HasPrefix(p[2], "Update") {
		action = "write"
	} else if strings.HasPrefix(p[2], "Delete") {
		action = "delete"
	} else if strings.HasPrefix(p[2], "Unsafe") {
		action = "unsafe"
	} else {
		action = "other"
	}

	token, dpopJWK, err := a.checkToken(
		ctx,
		header,
		dpopInfo{
			headers: md["dpop"],
			path:    info.FullMethod,
			method:  "POST",
		},
	)
	if err != nil {
		slog.Warn("failed to validate token", slog.String("error", err.Error()))
		return nil, status.Errorf(codes.Unauthenticated, "unauthenticated")
	}

	// Check if the token is allowed to access the resource
	if allowed, err := a.enforcer.Enforce(token, resource, action); err != nil {
		if err.Error() == "permission denied" {
			slog.Warn("permission denied", slog.String("azp", token.Subject()), slog.String("error", err.Error()))
			return nil, status.Errorf(codes.PermissionDenied, "permission denied")
		}
		return nil, err
	} else if !allowed {
		slog.Warn("permission denied", slog.String("azp", token.Subject()))
		return nil, status.Errorf(codes.PermissionDenied, "permission denied")
	}

	return handler(ContextWithJWK(ctx, dpopJWK), req)
}

// checkToken is a helper function to verify the token.
func (a Authentication) checkToken(ctx context.Context, authHeader []string, dpopInfo dpopInfo) (jwt.Token, jwk.Key, error) {
	var (
		tokenRaw  string
		tokenType string
	)

	// If we don't get a DPoP/Bearer token type, we can't proceed
	switch {
	case strings.HasPrefix(authHeader[0], "DPoP "):
		tokenType = "DPoP"
		tokenRaw = strings.TrimPrefix(authHeader[0], "DPoP ")
	case strings.HasPrefix(authHeader[0], "Bearer "):
		tokenType = "Bearer"
		tokenRaw = strings.TrimPrefix(authHeader[0], "Bearer ")
	default:
		return nil, nil, fmt.Errorf("not of type bearer or dpop")
	}

	// We have to get iss from the token first to verify the signature
	unverifiedToken, err := jwt.Parse([]byte(tokenRaw), jwt.WithVerify(false))
	if err != nil {
		return nil, nil, err
	}

	// Get issuer from unverified token
	issuer := unverifiedToken.Issuer()
	if issuer == "" {
		return nil, nil, fmt.Errorf("missing issuer")
	}

	// Get the openid configuration for the issuer
	// Because we get an interface we need to cast it to a string
	// and jwx expects it as a string so we should never hit this error if the token is valid
	oidc, exists := a.oidcConfigurations[issuer]
	if !exists {
		return nil, nil, fmt.Errorf("invalid issuer")
	}

	// Get key set from cache that matches the jwks_uri
	keySet, err := a.cache.Get(ctx, oidc.JwksURI)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get jwks from cache")
	}

	// Now we verify the token signature
	accessToken, err := jwt.Parse([]byte(tokenRaw),
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
		jwt.WithIssuer(issuer),
		jwt.WithAudience(oidc.Audience),
		jwt.WithValidator(jwt.ValidatorFunc(a.claimsValidator)),
	)

	if err != nil {
		return nil, nil, err
	}

	if tokenType == "Bearer" {
		slog.Warn("Presented bearer token. validating as DPoP")
	}

	key, err := validateDPoP(accessToken, tokenRaw, dpopInfo)
	if err != nil {
		return nil, nil, err
	}

	return accessToken, *key, nil
}

func ContextWithJWK(ctx context.Context, key jwk.Key) context.Context {
	return context.WithValue(ctx, dpopJWKContextKey, key)
}

func GetJWKFromContext(ctx context.Context) jwk.Key {
	key := ctx.Value(dpopJWKContextKey)
	if key == nil {
		return nil
	}
	if jwk, ok := key.(jwk.Key); ok {
		return jwk
	}

	return nil
}

func validateDPoP(accessToken jwt.Token, acessTokenRaw string, dpopInfo dpopInfo) (*jwk.Key, error) {
	if len(dpopInfo.headers) != 1 {
		return nil, fmt.Errorf("got %d dpop headers, should have 1", len(dpopInfo.headers))
	}
	dpopHeader := dpopInfo.headers[0]

	cnf, ok := accessToken.Get("cnf")
	if !ok {
		return nil, fmt.Errorf("missing `cnf` claim in access token")
	}

	cnfDict, ok := cnf.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("got `cnf` in an invalid format")
	}

	jktI, ok := cnfDict["jkt"]
	if !ok {
		return nil, fmt.Errorf("missing `jkt` field in `cnf` claim. only thumbprint JWK confirmation is supported")
	}

	jkt, ok := jktI.(string)
	if !ok {
		return nil, fmt.Errorf("invalid `jkt` field in `cnf` claim: %v. the value must be a JWK thumbprint", jkt)
	}

	dpop, err := jws.Parse([]byte(dpopHeader))
	if err != nil {
		slog.Error("error parsing JWT: %w", err)
		return nil, fmt.Errorf("invalid DPoP JWT")
	}
	if len(dpop.Signatures()) != 1 {
		return nil, fmt.Errorf("expected one signature on DPoP JWT, got %d", len(dpop.Signatures()))
	}
	sig := dpop.Signatures()[0]
	protectedHeaders := sig.ProtectedHeaders()
	if protectedHeaders.Type() != "dpop+jwt" {
		return nil, fmt.Errorf("invalid typ on DPoP JWT: %v", protectedHeaders.Type())
	}

	if _, exists := allowedSignatureAlgorithms[protectedHeaders.Algorithm()]; !exists {
		return nil, fmt.Errorf("unsupported algorithm specified: %v", protectedHeaders.Algorithm())
	}

	dpopKey := protectedHeaders.JWK()
	if dpopKey == nil {
		return nil, fmt.Errorf("JWK missing in DPoP JWT")
	}

	isPrivate, err := jwk.IsPrivateKey(dpopKey)
	if err != nil {
		slog.Error("error checking if key is private", err)
		return nil, fmt.Errorf("invalid DPoP key specified")
	}

	if isPrivate {
		return nil, fmt.Errorf("cannot use a private key for DPoP")
	}

	thumbprint, err := dpopKey.Thumbprint(crypto.SHA256)
	if err != nil {
		slog.Error("error computing thumbprint for key", err)
		return nil, fmt.Errorf("couldn't compute thumbprint for key in `jwk` in DPoP JWT")
	}

	if base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(thumbprint) != jkt {
		return nil, fmt.Errorf("the `jkt` from the DPoP JWT didn't match the thumbprint from the access token")
	}

	// at this point we have the right key because its thumbprint matches the `jkt` claim
	// in the validated access token
	dpopToken, err := jwt.Parse([]byte(dpopHeader), jwt.WithKey(protectedHeaders.Algorithm(), dpopKey))

	if err != nil {
		slog.Error("error validating DPoP JWT", err)
		return nil, fmt.Errorf("failed to verify signature on DPoP JWT")
	}

	issuedAt := dpopToken.IssuedAt()
	if issuedAt.IsZero() {
		return nil, fmt.Errorf("missing `iat` claim in the DPoP JWT")
	}

	if issuedAt.Add(time.Hour).Before(time.Now()) {
		return nil, fmt.Errorf("the DPoP JWT has expired")
	}

	htm, ok := dpopToken.Get("htm")
	if !ok {
		return nil, fmt.Errorf("`htm` claim missing in DPoP JWT")
	}

	if htm != dpopInfo.method {
		return nil, fmt.Errorf("incorrect `htm` claim in DPoP JWT")
	}

	htu, ok := dpopToken.Get("htu")
	if !ok {
		return nil, fmt.Errorf("`htu` claim missing in DPoP JWT")
	}

	if htu != dpopInfo.path {
		return nil, fmt.Errorf("incorrect `htu` claim in DPoP JWT")
	}

	ath, ok := dpopToken.Get("ath")
	if !ok {
		return nil, fmt.Errorf("missing `ath` claim in DPoP JWT")
	}

	h := sha256.New()
	h.Write([]byte(acessTokenRaw))
	if ath != base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(h.Sum(nil)) {
		return nil, fmt.Errorf("incorrect `ath` claim in DPoP JWT")
	}
	return &dpopKey, nil
}

// claimsValidator is a custom validator to check extra claims in the token.
// right now it only checks for client_id
func (a Authentication) claimsValidator(_ context.Context, token jwt.Token) jwt.ValidationError {
	var (
		clientID string
	)

	// Need to check for cid and client_id as this claim seems to be different between idp's
	cidClaim, cidExists := token.Get("cid")
	clientIDClaim, clientIDExists := token.Get("client_id")

	// Check to see if we have a client id claim
	switch {
	case cidExists:
		if cid, ok := cidClaim.(string); ok {
			clientID = cid
			break
		}
	case clientIDExists:
		if cid, ok := clientIDClaim.(string); ok {
			clientID = cid
			break
		}
	default:
		return jwt.NewValidationError(fmt.Errorf("client id required"))
	}

	// Check if the client id is allowed in list of clients
	foundClientID := false
	for _, c := range a.oidcConfigurations[token.Issuer()].Clients {
		if c == clientID {
			foundClientID = true
			break
		}
	}
	if !foundClientID {
		return jwt.NewValidationError(fmt.Errorf("invalid client id"))
	}

	return nil
}
