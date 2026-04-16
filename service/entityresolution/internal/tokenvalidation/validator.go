package tokenvalidation

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwt"
	authn "github.com/opentdf/platform/service/internal/auth"
	"github.com/opentdf/platform/service/logger"
)

var (
	ErrTokenVerifierNotConfigured = errors.New("entity resolution token validation is not configured")
	ErrTokenValidationFailed      = errors.New("entity resolution token validation failed")
)

// Verifier validates raw access tokens and returns the parsed JWT on success.
type Verifier interface {
	VerifyAccessToken(ctx context.Context, tokenRaw string) (jwt.Token, error)
}

// NewPlatformVerifier builds a verifier from the platform auth configuration.
// ErrTokenVerifierNotConfigured is returned when the platform auth config is incomplete.
func NewPlatformVerifier(ctx context.Context, cfg authn.AuthNConfig, logger *logger.Logger) (Verifier, error) {
	if cfg.Issuer == "" || cfg.Audience == "" {
		return nil, ErrTokenVerifierNotConfigured
	}

	return authn.NewTokenVerifier(ctx, cfg, logger)
}

// Verify validates the raw token with the configured verifier.
func Verify(ctx context.Context, verifier Verifier, tokenRaw string) (jwt.Token, error) {
	if verifier == nil {
		return nil, ErrTokenVerifierNotConfigured
	}

	token, err := verifier.VerifyAccessToken(ctx, tokenRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTokenValidationFailed, err)
	}

	return token, nil
}

// ConnectCode maps token validation failures to appropriate RPC error codes.
func ConnectCode(err error) connect.Code {
	switch {
	case errors.Is(err, ErrTokenVerifierNotConfigured):
		return connect.CodeFailedPrecondition
	case errors.Is(err, ErrTokenValidationFailed):
		return connect.CodeUnauthenticated
	default:
		return connect.CodeUnknown
	}
}

// ClaimsStructMap returns claims in a form compatible with structpb.NewStruct.
func ClaimsStructMap(token jwt.Token) map[string]interface{} {
	claims := token.PrivateClaims()

	if sub := token.Subject(); sub != "" {
		claims["sub"] = sub
	}
	if iss := token.Issuer(); iss != "" {
		claims["iss"] = iss
	}
	if jti := token.JwtID(); jti != "" {
		claims["jti"] = jti
	}
	if aud := token.Audience(); len(aud) > 0 {
		audSlice := make([]interface{}, len(aud))
		for i, audience := range aud {
			audSlice[i] = audience
		}
		claims["aud"] = audSlice
	}

	return claims
}
