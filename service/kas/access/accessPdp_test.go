package access

import (
	"context"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/entity"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestToken(t *testing.T, subject string) *entity.Token {
	t.Helper()

	token := jwt.New()
	require.NoError(t, token.Set("sub", subject))

	raw, err := jwt.Sign(token, jwa.HS256, []byte("secret"))
	require.NoError(t, err)

	return &entity.Token{Jwt: string(raw)}
}

func TestCanAccessDissemMatch(t *testing.T) {
	p := &Provider{Logger: logger.CreateTestLogger()}
	tok := newTestToken(t, "user@example.com")
	policy := &Policy{Body: PolicyBody{Dissem: []string{"user@example.com"}}}

	result, err := p.canAccess(context.Background(), tok, []*Policy{policy})
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.True(t, result[0].Access)
}

func TestCanAccessDissemMismatch(t *testing.T) {
	p := &Provider{Logger: logger.CreateTestLogger()}
	tok := newTestToken(t, "user@example.com")
	policy := &Policy{Body: PolicyBody{Dissem: []string{"other@example.com"}}}

	result, err := p.canAccess(context.Background(), tok, []*Policy{policy})
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.False(t, result[0].Access)
}

func TestCanAccessDissemInvalidToken(t *testing.T) {
	p := &Provider{Logger: logger.CreateTestLogger()}
	tok := &entity.Token{Jwt: "not-a-jwt"}
	policy := &Policy{Body: PolicyBody{Dissem: []string{"user@example.com"}}}

	_, err := p.canAccess(context.Background(), tok, []*Policy{policy})
	require.ErrorIs(t, err, ErrPolicyDissemInvalid)
}
