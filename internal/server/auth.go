package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type authN struct {
	cache *jwk.Cache
	cfg   map[string]openidConfiguraton
}

type openidConfiguraton struct {
	AuthConfig
	Jwks_uri string `json:"jwks_uri"`
}

// Creates new authN which is used to verify tokens for a set of given issuers
func newAuthNInterceptor(cfg []AuthConfig) (*authN, error) {
	a := &authN{}
	a.cfg = make(map[string]openidConfiguraton)

	ctx := context.Background()

	a.cache = jwk.NewCache(ctx)

	// Build new cache for each trusted issuer
	for _, c := range cfg {
		// Discover IDP
		oidc, err := discoverIDP(ctx, c.Issuer)
		if err != nil {
			return nil, err
		}
		oidc.AuthConfig = c

		// Register the jwks_uri with the cache
		if err := a.cache.Register(oidc.Jwks_uri, jwk.WithMinRefreshInterval(15*time.Minute)); err != nil {
			return nil, err
		}

		// Need to refresh the cache to verify jwks is available
		_, err = a.cache.Refresh(ctx, oidc.Jwks_uri)
		if err != nil {
			return nil, err
		}

		a.cfg[c.Issuer] = *oidc
	}

	return a, nil
}

// Discovers the openid configuration for the issuer provided
func discoverIDP(ctx context.Context, issuer string) (*openidConfiguraton, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/.well-known/openid-configuration", issuer), nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to discover idp: %s", resp.Status)
	}
	defer resp.Body.Close()

	cfg := &openidConfiguraton{}
	err = json.NewDecoder(resp.Body).Decode(&cfg)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

// verifyTokenInterceptor is a grpc interceptor that verifies the token in the metadata
func (a authN) verifyTokenInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	// Allow health checks to pass through
	if info.FullMethod == "/grpc.health.v1.Health/Check" {
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
	err := checkToken(ctx, md, a)
	if err != nil {
		slog.Warn("failed to validate token", slog.String("error", err.Error()))
		return nil, status.Errorf(codes.Unauthenticated, "invalid token")
	}

	return handler(ctx, req)
}

func checkToken(ctx context.Context, headers map[string][]string, auth authN) error {
	var (
		tokenRaw  string
		tokenType string
	)

	authHeader := headers["authorization"]
	if len(authHeader) < 1 {
		return fmt.Errorf("missing authorization header")
	}

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
	oidc, exists := auth.cfg[issuer.(string)]
	if !exists {
		return fmt.Errorf("invalid issuer")
	}

	// Get key set from cache that matches the jwks_uri
	keySet, err := auth.cache.Get(ctx, oidc.Jwks_uri)
	if err != nil {
		return fmt.Errorf("failed to get jwks from cache")
	}

	// Now we verify the token signature
	_, err = jwt.Parse([]byte(tokenRaw),
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
		jwt.WithIssuer(issuer.(string)),
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
func (a authN) claimsValidator(ctx context.Context, token jwt.Token) jwt.ValidationError {
	var (
		clientID string
	)

	// Need to check for cid and client_id as this claim seems to be different between idp's
	cidClaim, cidExists := token.Get("cid")
	clientIDClaim, clientIDExists := token.Get("client_id")

	// Check to see if we have a client id claim
	switch {
	case cidExists:
		clientID = cidClaim.(string)
	case clientIDExists:
		clientID = clientIDClaim.(string)
	default:
		return jwt.NewValidationError(fmt.Errorf("client id required"))
	}

	// Check if the client id is allowed in list of clients
	foundClientID := false
	for _, c := range a.cfg[token.Issuer()].Clients {
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
