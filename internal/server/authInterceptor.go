package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type authN struct {
	cache *jwk.Cache
}

func newAuthNInterceptor() (*authN, error) {
	a := &authN{}
	ctx := context.Background()

	a.cache = jwk.NewCache(ctx)
	a.cache.Register("https://www.googleapis.com/oauth2/v3/certs", jwk.WithMinRefreshInterval(15*time.Minute))

	_, err := a.cache.Refresh(ctx, "https://www.googleapis.com/oauth2/v3/certs")
	if err != nil {
		return nil, err
	}

	return a, nil
}

func (a authN) verifyToken(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	// Allow health checks to pass through
	if info.FullMethod == "/grpc.health.v1.Health/Check" {
		return handler(ctx, req)
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("missing metadata")
	}
	// The keys within metadata.MD are normalized to lowercase.
	// See: https://godoc.org/google.golang.org/grpc/metadata#New
	authHeader := md["authorization"]
	if len(authHeader) < 1 {
		return nil, fmt.Errorf("missing authorization header")
	}

	var (
		tokenRaw  string
		tokenType string
	)

	// If we don't get a DPoP/Bearer token, we can't proceed
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

	// If DPoP token is used, we need to verify the DPoP Proof
	// Implement in the future
	if tokenType == "DPoP" {
	}

	// Verify the token
	keySet, err := a.cache.Get(ctx, "https://www.googleapis.com/oauth2/v3/certs")
	if err != nil {
		return nil, fmt.Errorf("failed to get jwk: %w", err)
	}

	_, err = jwt.Parse([]byte(tokenRaw), jwt.WithKeySet(keySet), jwt.WithValidate(true))
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	return handler(ctx, req)
}
