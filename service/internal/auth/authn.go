package auth

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"

	sdkAudit "github.com/opentdf/platform/sdk/audit"
	"github.com/opentdf/platform/service/internal/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	authnContextKey = authContextKey("dpop-jwk")
)

type authContextKey string

type authContext struct {
	key         jwk.Key
	accessToken jwt.Token
	rawToken    string
}

var (
	// Set of allowed public endpoints that do not require authentication
	allowedPublicEndpoints = [...]string{
		// Well Known Configuration Endpoints
		"/wellknownconfiguration.WellKnownService/GetWellKnownConfiguration",
		"/.well-known/opentdf-configuration",
		// KAS Public Key Endpoints
		"/kas.AccessService/PublicKey",
		"/kas.AccessService/LegacyPublicKey",
		"/kas/kas_public_key",
		"/kas/v2/kas_public_key",
		// HealthZ
		"/healthz",
		"/grpc.health.v1.Health/Check",
	}
	// only asymmetric algorithms and no 'none'
	allowedSignatureAlgorithms = map[jwa.SignatureAlgorithm]bool{ //nolint:exhaustive // only asymmetric algorithms
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

const refreshInterval = 15 * time.Minute

// Authentication holds a jwks cache and information about the openid configuration
type Authentication struct {
	enforceDPoP bool
	// keySet holds a cached key set
	cachedKeySet jwk.Set
	// openidConfigurations holds the openid configuration for the issuer
	oidcConfiguration AuthNConfig
	// Casbin enforcer
	enforcer *Enforcer
	// Public Routes HTTP & gRPC
	publicRoutes []string
	// Custom Logger
	logger *logger.Logger
}

// Creates new authN which is used to verify tokens for a set of given issuers
func NewAuthenticator(ctx context.Context, cfg Config, logr *logger.Logger, wellknownRegistration func(namespace string, config any) error) (*Authentication, error) {
	a := &Authentication{
		enforceDPoP: cfg.EnforceDPoP,
		logger:      logr,
	}

	// validate the configuration
	if err := cfg.validateAuthNConfig(); err != nil {
		return nil, err
	}

	cache := jwk.NewCache(ctx)

	// Build new cache
	// Discover OIDC Configuration
	oidcConfig, err := DiscoverOIDCConfiguration(ctx, cfg.Issuer)
	if err != nil {
		return nil, err
	}

	// If the issuer is different from the one in the configuration, update the configuration
	// This could happen if we are hitting an internal endpoint. Example we might point to https://keycloak.opentdf.svc/realms/opentdf
	// but the external facing issuer is https://keycloak.opentdf.local/realms/opentdf
	if oidcConfig.Issuer != cfg.Issuer {
		cfg.Issuer = oidcConfig.Issuer
	}

	cacheInterval, err := time.ParseDuration(cfg.CacheRefresh)
	if err != nil {
		logr.ErrorContext(ctx, fmt.Sprintf("Invalid cache_refresh_interval [%s]", cfg.CacheRefresh), "err", err)
		cacheInterval = refreshInterval
	}

	// Register the jwks_uri with the cache
	if err := cache.Register(oidcConfig.JwksURI, jwk.WithMinRefreshInterval(cacheInterval)); err != nil {
		return nil, err
	}

	casbinConfig := CasbinConfig{
		PolicyConfig: cfg.Policy,
	}
	logr.Info("initializing casbin enforcer")
	if a.enforcer, err = NewCasbinEnforcer(casbinConfig); err != nil {
		return nil, fmt.Errorf("failed to initialize casbin enforcer: %w", err)
	}

	// Need to refresh the cache to verify jwks is available
	_, err = cache.Refresh(ctx, oidcConfig.JwksURI)
	if err != nil {
		return nil, err
	}

	// Set the cache
	a.cachedKeySet = jwk.NewCachedSet(cache, oidcConfig.JwksURI)

	// Combine public routes
	a.publicRoutes = append(a.publicRoutes, cfg.PublicRoutes...)
	a.publicRoutes = append(a.publicRoutes, allowedPublicEndpoints[:]...)

	a.oidcConfiguration = cfg.AuthNConfig

	// Try an register oidc issuer to wellknown service but don't return an error if it fails
	if err := wellknownRegistration("platform_issuer", cfg.Issuer); err != nil {
		logr.Warn("failed to register platform issuer", slog.String("error", err.Error()))
	}

	var oidcConfigMap map[string]any

	// Create a map of the oidc configuration
	oidcConfigBytes, err := json.Marshal(oidcConfig)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(oidcConfigBytes, &oidcConfigMap); err != nil {
		return nil, err
	}

	if err := wellknownRegistration("idp", oidcConfigMap); err != nil {
		logr.Warn("failed to register platform idp information", slog.String("error", err.Error()))
	}

	return a, nil
}

type receiverInfo struct {
	// The URI of the request
	u string
	// The HTTP method of the request
	m string
}

func normalizeURL(o string, u *url.URL) string {
	// Currently this does not do a full normatlization
	ou, err := url.Parse(o)
	if err != nil {
		return u.String()
	}
	ou.Path = u.Path
	return ou.String()
}

// verifyTokenHandler is a http handler that verifies the token
func (a Authentication) MuxHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if slices.ContainsFunc(a.publicRoutes, a.isPublicRoute(r.URL.Path)) { //nolint:contextcheck // There is no way to pass a context here
			handler.ServeHTTP(w, r)
			return
		}

		// Verify the token
		header := r.Header["Authorization"]
		if len(header) < 1 {
			http.Error(w, "missing authorization header", http.StatusUnauthorized)
			return
		}
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = r.Host
			if r.TLS != nil {
				origin = "https://" + strings.TrimSuffix(origin, ":443")
			} else {
				origin = "http://" + strings.TrimSuffix(origin, ":80")
			}
		}
		accessTok, ctxWithJWK, err := a.checkToken(r.Context(), header, receiverInfo{
			u: normalizeURL(origin, r.URL),
			m: r.Method,
		}, r.Header["Dpop"])

		if err != nil {
			a.logger.WarnContext(r.Context(), "failed to validate token", slog.String("error", err.Error()))
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}

		// Check if the token is allowed to access the resource
		var action string
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
		if allow, err := a.enforcer.Enforce(accessTok, r.URL.Path, action); err != nil {
			if err.Error() == "permission denied" {
				a.logger.WarnContext(r.Context(), "permission denied", slog.String("azp", accessTok.Subject()), slog.String("error", err.Error()))
				http.Error(w, "permission denied", http.StatusForbidden)
				return
			}
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		} else if !allow {
			a.logger.WarnContext(r.Context(), "permission denied", slog.String("azp", accessTok.Subject()))
			http.Error(w, "permission denied", http.StatusForbidden)
			return
		}

		handler.ServeHTTP(w, r.WithContext(ctxWithJWK))
	})
}

// UnaryServerInterceptor is a grpc interceptor that verifies the token in the metadata
func (a Authentication) UnaryServerInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	// Allow health checks and other public routes to pass through
	if slices.ContainsFunc(a.publicRoutes, a.isPublicRoute(info.FullMethod)) { //nolint:contextcheck // There is no way to pass a context here
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
	var action string
	switch {
	case strings.HasPrefix(p[2], "List") || strings.HasPrefix(p[2], "Get"):
		action = "read"
	case strings.HasPrefix(p[2], "Create") || strings.HasPrefix(p[2], "Update"):
		action = "write"
	case strings.HasPrefix(p[2], "Delete"):
		action = "delete"
	case strings.HasPrefix(p[2], "Unsafe"):
		action = "unsafe"
	default:
		action = "other"
	}

	token, newCtx, err := a.checkToken(
		ctx,
		header,
		receiverInfo{
			u: info.FullMethod,
			m: http.MethodPost,
		},
		md["dpop"],
	)
	if err != nil {
		a.logger.Warn("failed to validate token", slog.String("error", err.Error()))
		return nil, status.Errorf(codes.Unauthenticated, "unauthenticated")
	}

	// Check if the token is allowed to access the resource
	if allowed, err := a.enforcer.Enforce(token, resource, action); err != nil {
		if err.Error() == "permission denied" {
			a.logger.Warn("permission denied", slog.String("azp", token.Subject()), slog.String("error", err.Error()))
			return nil, status.Errorf(codes.PermissionDenied, "permission denied")
		}
		return nil, err
	} else if !allowed {
		a.logger.Warn("permission denied", slog.String("azp", token.Subject()))
		return nil, status.Errorf(codes.PermissionDenied, "permission denied")
	}

	return handler(newCtx, req)
}

// checkToken is a helper function to verify the token.
func (a Authentication) checkToken(ctx context.Context, authHeader []string, dpopInfo receiverInfo, dpopHeader []string) (jwt.Token, context.Context, error) {
	var (
		tokenRaw string
	)

	// If we don't get a DPoP/Bearer token type, we can't proceed
	switch {
	case strings.HasPrefix(authHeader[0], "DPoP "):
		tokenRaw = strings.TrimPrefix(authHeader[0], "DPoP ")
	case strings.HasPrefix(authHeader[0], "Bearer "):
		tokenRaw = strings.TrimPrefix(authHeader[0], "Bearer ")
	default:
		return nil, nil, fmt.Errorf("not of type bearer or dpop")
	}

	// Now we verify the token signature
	accessToken, err := jwt.Parse([]byte(tokenRaw),
		jwt.WithKeySet(a.cachedKeySet),
		jwt.WithValidate(true),
		jwt.WithIssuer(a.oidcConfiguration.Issuer),
		jwt.WithAudience(a.oidcConfiguration.Audience),
	)

	if err != nil {
		return nil, nil, err
	}

	// Get actor ID (sub) from unverified token for audit and add to context
	// Only set the actor ID if it is not already defined
	existingActorID := ctx.Value(sdkAudit.ActorIDContextKey)
	if existingActorID == nil {
		actorID := accessToken.Subject()
		ctx = context.WithValue(ctx, sdkAudit.ActorIDContextKey, actorID)
	}

	_, tokenHasCNF := accessToken.Get("cnf")
	if !tokenHasCNF && !a.enforceDPoP {
		// this condition is not quite tight because it's possible that the `cnf` claim may
		// come from token introspection
		ctx = ContextWithAuthNInfo(ctx, nil, accessToken, tokenRaw)
		return accessToken, ctx, nil
	}
	key, err := validateDPoP(accessToken, tokenRaw, dpopInfo, dpopHeader)
	if err != nil {
		return nil, nil, err
	}
	ctx = ContextWithAuthNInfo(ctx, key, accessToken, tokenRaw)
	return accessToken, ctx, nil
}

func ContextWithAuthNInfo(ctx context.Context, key jwk.Key, accessToken jwt.Token, raw string) context.Context {
	return context.WithValue(ctx, authnContextKey, &authContext{
		key,
		accessToken,
		raw,
	})
}

func getContextDetails(ctx context.Context) *authContext {
	key := ctx.Value(authnContextKey)
	if key == nil {
		return nil
	}
	if c, ok := key.(*authContext); ok {
		return c
	}

	// We should probably return an error here?
	slog.ErrorContext(ctx, "invalid authContext")
	return nil
}

func GetJWKFromContext(ctx context.Context) jwk.Key {
	if c := getContextDetails(ctx); c != nil {
		return c.key
	}
	return nil
}

func GetAccessTokenFromContext(ctx context.Context) jwt.Token {
	if c := getContextDetails(ctx); c != nil {
		return c.accessToken
	}
	return nil
}

func GetRawAccessTokenFromContext(ctx context.Context) string {
	if c := getContextDetails(ctx); c != nil {
		return c.rawToken
	}
	return ""
}

func validateDPoP(accessToken jwt.Token, acessTokenRaw string, dpopInfo receiverInfo, headers []string) (jwk.Key, error) {
	if len(headers) != 1 {
		return nil, fmt.Errorf("got %d dpop headers, should have 1", len(headers))
	}
	dpopHeader := headers[0]

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
		slog.Error("error parsing JWT", "error", err)
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
		slog.Error("error checking if key is private", "error", err)
		return nil, fmt.Errorf("invalid DPoP key specified")
	}

	if isPrivate {
		return nil, fmt.Errorf("cannot use a private key for DPoP")
	}

	thumbprint, err := dpopKey.Thumbprint(crypto.SHA256)
	if err != nil {
		slog.Error("error computing thumbprint for key", "error", err)
		return nil, fmt.Errorf("couldn't compute thumbprint for key in `jwk` in DPoP JWT")
	}

	thumbprintStr := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(thumbprint)
	if thumbprintStr != jkt {
		return nil, fmt.Errorf("the `jkt` from the DPoP JWT didn't match the thumbprint from the access token; cnf.jkt=[%v], computed=[%v]", jkt, thumbprintStr)
	}

	// at this point we have the right key because its thumbprint matches the `jkt` claim
	// in the validated access token
	dpopToken, err := jwt.Parse([]byte(dpopHeader), jwt.WithKey(protectedHeaders.Algorithm(), dpopKey))
	if err != nil {
		slog.Error("error validating DPoP JWT", "error", err)
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

	if htm != dpopInfo.m {
		return nil, fmt.Errorf("incorrect `htm` claim in DPoP JWT; received [%v], but should match [%v]", htm, dpopInfo.m)
	}

	htu, ok := dpopToken.Get("htu")
	if !ok {
		return nil, fmt.Errorf("`htu` claim missing in DPoP JWT")
	}

	if htu != dpopInfo.u {
		return nil, fmt.Errorf("incorrect `htu` claim in DPoP JWT; received [%v], but should match [%v]", htu, dpopInfo.u)
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
	return dpopKey, nil
}

func (a Authentication) isPublicRoute(path string) func(string) bool {
	return func(route string) bool {
		matched, err := doublestar.Match(route, path)
		if err != nil {
			a.logger.Warn("error matching route", slog.String("route", route), slog.String("path", path), slog.String("error", err.Error()))
			return false
		}
		a.logger.Trace("matching route", slog.String("route", route), slog.String("path", path), slog.Bool("matched", matched))
		return matched
	}
}
