package tokenvalidation

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwt"
	authn "github.com/opentdf/platform/service/internal/auth"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubVerifier struct {
	token jwt.Token
	err   error
}

func (s stubVerifier) VerifyAccessToken(_ context.Context, _ string) (jwt.Token, error) {
	if s.err != nil {
		return nil, s.err
	}

	return s.token, nil
}

func TestNewPlatformVerifier_WhenConfigMissing(t *testing.T) {
	verifier, err := NewPlatformVerifier(context.Background(), authn.AuthNConfig{}, logger.CreateTestLogger())
	require.Nil(t, verifier)
	require.ErrorIs(t, err, ErrTokenVerifierNotConfigured)
}

func TestVerify(t *testing.T) {
	t.Run("nil verifier", func(t *testing.T) {
		_, err := Verify(context.Background(), nil, "token")
		require.ErrorIs(t, err, ErrTokenVerifierNotConfigured)
		assert.Equal(t, connect.CodeFailedPrecondition, ConnectCode(err))
	})

	t.Run("validation failure", func(t *testing.T) {
		verifyErr := errors.New("signature mismatch")

		_, err := Verify(context.Background(), stubVerifier{err: verifyErr}, "token")
		require.ErrorIs(t, err, ErrTokenValidationFailed)
		require.ErrorIs(t, err, verifyErr)
		assert.Equal(t, connect.CodeUnauthenticated, ConnectCode(err))
	})

	t.Run("success", func(t *testing.T) {
		token := jwt.New()
		require.NoError(t, token.Set("role", "admin"))

		verifiedToken, err := Verify(context.Background(), stubVerifier{token: token}, "token")
		require.NoError(t, err)
		assert.Same(t, token, verifiedToken)
	})
}

func TestConnectCode_WhenUnknown(t *testing.T) {
	assert.Equal(t, connect.CodeUnknown, ConnectCode(errors.New("other")))
}

func TestClaimsStructMap_IncludesStandardClaims(t *testing.T) {
	token := jwt.New()
	require.NoError(t, token.Set("role", "admin"))
	require.NoError(t, token.Set(jwt.SubjectKey, "user-123"))
	require.NoError(t, token.Set(jwt.IssuerKey, "issuer"))
	require.NoError(t, token.Set(jwt.JwtIDKey, "jwt-id"))
	require.NoError(t, token.Set(jwt.AudienceKey, []string{"aud-1", "aud-2"}))

	claims := ClaimsStructMap(token)

	assert.Equal(t, "admin", claims["role"])
	assert.Equal(t, "user-123", claims["sub"])
	assert.Equal(t, "issuer", claims["iss"])
	assert.Equal(t, "jwt-id", claims["jti"])
	assert.Equal(t, []interface{}{"aud-1", "aud-2"}, claims["aud"])
}
