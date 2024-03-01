package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type authN struct {
	cache *jwk.Cache
	cfg   map[string]openidConfiguraton
}

type openidConfiguraton struct {
	Audience string `json:",omitempty"`
	Issuer   string `json:"issuer"`
	Jwks_uri string `json:"jwks_uri"`
}

var testIDP = "http://localhost:8888/auth/realms/opentdf/protocol/openid-connect/certs"

func newAuthNInterceptor(cfg []AuthConfig) (*authN, error) {
	a := &authN{}
	a.cfg = make(map[string]openidConfiguraton)

	ctx := context.Background()

	a.cache = jwk.NewCache(ctx)

	for _, c := range cfg {
		// Discover IDP
		oidc, err := discoverIDP(ctx, c.Issuer)
		if err != nil {
			return nil, err
		}
		oidc.Audience = c.Audience

		if err := a.cache.Register(oidc.Jwks_uri, jwk.WithMinRefreshInterval(15*time.Minute)); err != nil {
			return nil, err
		}

		_, err = a.cache.Refresh(ctx, oidc.Jwks_uri)
		if err != nil {
			return nil, err
		}

		a.cfg[c.Issuer] = *oidc
	}

	return a, nil
}

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

func (a authN) verifyTokenInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	// Allow health checks to pass through
	if info.FullMethod == "/grpc.health.v1.Health/Check" {
		return handler(ctx, req)
	}

	// Get the metadata from the context
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("missing metadata")
	}

	// The keys within metadata.MD are normalized to lowercase.
	// See: https://godoc.org/google.golang.org/grpc/metadata#New
	// Get authorization header
	authHeader := md["authorization"]
	if len(authHeader) < 1 {
		return nil, fmt.Errorf("missing authorization header")
	}

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
		return nil, fmt.Errorf("invalid authorization header")
	}

	// Parse Token Without Verification to get issuer
	unverifiedToken, err := jwt.Parse([]byte(tokenRaw), jwt.WithVerify(false))
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	issuer, exists := unverifiedToken.Get("iss")
	if !exists {
		return nil, fmt.Errorf("iss required")
	}

	// Get the openid configuration for the issuer
	oidc, exists := a.cfg[issuer.(string)]
	if !exists {
		return nil, fmt.Errorf("issuer not allowed")
	}

	// If DPoP token is used, we need to verify the DPoP Proof
	// Implement in the future
	if tokenType == "DPoP" {
	}

	// Verify the token
	keySet, err := a.cache.Get(ctx, oidc.Jwks_uri)
	if err != nil {
		return nil, fmt.Errorf("failed to get jwk: %w", err)
	}

	_, err = jwt.Parse([]byte(tokenRaw), jwt.WithKeySet(keySet), jwt.WithValidate(true), jwt.WithAudience(oidc.Audience), jwt.WithValidator(jwt.ValidatorFunc(func(ctx context.Context, token jwt.Token) jwt.ValidationError {
		if cid, exists := token.Get("client_id"); !exists || cid.(string) != "opentdf" {
			return jwt.NewValidationError(fmt.Errorf("invalid client id"))
		}
		return nil
	})))
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	return handler(ctx, req)
}
