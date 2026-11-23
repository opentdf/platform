package jwtclaims

import (
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFieldAndMap(t *testing.T) {
	exp := time.Unix(1_900_000_000, 0).UTC()
	tok, err := jwt.NewBuilder().
		Subject("alice").
		Expiration(exp).
		Claim("cnf", map[string]any{"jkt": "thumb"}).
		Build()
	require.NoError(t, err)

	sub, ok := Field(tok, jwt.SubjectKey)
	require.True(t, ok)
	assert.Equal(t, "alice", sub)

	cnf, ok := Field(tok, "cnf")
	require.True(t, ok)
	assert.Equal(t, map[string]any{"jkt": "thumb"}, cnf)

	_, ok = Field(tok, "missing")
	assert.False(t, ok)

	claims := Map(tok)
	assert.Equal(t, "alice", claims[jwt.SubjectKey])
	assert.Equal(t, exp, claims[jwt.ExpirationKey])
	assert.Contains(t, claims, "cnf")
	assert.Len(t, claims, 3)
}
