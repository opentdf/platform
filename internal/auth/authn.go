package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var (
	// Set of allowed gRPC endpoints that do not require authentication
	allowedGRPCEndpoints = [...]string{
		"/grpc.health.v1.Health/Check",
		"/wellknownconfiguration.WellKnownService/GetWellKnownConfiguration",
	}
	// Set of allowed HTTP endpoints that do not require authentication
	allowedHTTPEndpoints = [...]string{
		"/healthz",
		"/.well-known/opentdf-configuration",
	}
)

// Authentication holds a jwks cache and information about the openid configuration
type authentication struct {
	// cache holds the jwks cache
	cache *jwk.Cache
	// openidConfigurations holds the openid configuration for each issuer
	oidcConfigurations map[string]AuthNConfig
}

// Creates new authN which is used to verify tokens for a set of given issuers
func NewAuthenticator(cfg AuthNConfig) (*authentication, error) {
	a := &authentication{}
	a.oidcConfigurations = make(map[string]AuthNConfig)

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

	// Need to refresh the cache to verify jwks is available
	_, err = a.cache.Refresh(ctx, cfg.JwksURI)
	if err != nil {
		return nil, err
	}

	a.oidcConfigurations[cfg.Issuer] = cfg

	return a, nil
}

// verifyTokenHandler is a http handler that verifies the token
func (a authentication) VerifyTokenHandler(handler http.Handler) http.Handler {
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
		err := checkToken(r.Context(), header, a)
		if err != nil {
			slog.WarnContext(r.Context(), "failed to validate token", slog.String("error", err.Error()))
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}

		handler.ServeHTTP(w, r)
	})
}

// verifyTokenInterceptor is a grpc interceptor that verifies the token in the metadata
func (a authentication) VerifyTokenInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
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

	err := checkToken(ctx, header, a)
	if err != nil {
		slog.Warn("failed to validate token", slog.String("error", err.Error()))
		return nil, status.Errorf(codes.Unauthenticated, "unauthenticated")
	}

	return handler(ctx, req)
}

// checkToken is a helper function to verify the token.
func checkToken(ctx context.Context, authHeader []string, auth authentication) error {
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
		return fmt.Errorf("not of type bearer or dpop")
	}

	// Future work is to validate DPoP proof if token type is DPoP
	//nolint:staticcheck
	if tokenType == "DPoP" {
		// Implement in the future here or as separate interceptor
	}

	// We have to get iss from the token first to verify the signature
	unverifiedToken, err := jwt.Parse([]byte(tokenRaw), jwt.WithVerify(false))
	if err != nil {
		return err
	}

	// Get issuer from unverified token
	issuer, exists := unverifiedToken.Get("iss")
	if !exists {
		return fmt.Errorf("missing issuer")
	}

	// Get the openid configuration for the issuer
	// Because we get an interface we need to cast it to a string
	// and jwx expects it as a string so we should never hit this error if the token is valid
	issuerStr, ok := issuer.(string)
	if !ok {
		return fmt.Errorf("invalid issuer")
	}
	oidc, exists := auth.oidcConfigurations[issuerStr]
	if !exists {
		return fmt.Errorf("invalid issuer")
	}

	// Get key set from cache that matches the jwks_uri
	keySet, err := auth.cache.Get(ctx, oidc.JwksURI)
	if err != nil {
		return fmt.Errorf("failed to get jwks from cache")
	}

	// Now we verify the token signature
	_, err = jwt.Parse([]byte(tokenRaw),
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
		jwt.WithIssuer(issuerStr),
		jwt.WithAudience(oidc.Audience),
		jwt.WithValidator(jwt.ValidatorFunc(auth.claimsValidator)),
	)
	if err != nil {
		return err
	}

	return nil
}

// claimsValidator is a custom validator to check extra claims in the token.
// right now it only checks for client_id
func (a authentication) claimsValidator(ctx context.Context, token jwt.Token) jwt.ValidationError {
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
