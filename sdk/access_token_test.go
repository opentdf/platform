package sdk

import (
	"context"
	"testing"

	"github.com/opentdf/platform/sdk/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccessToken_ReturnsTokenFromSource(t *testing.T) {
	s := &SDK{tokenSource: FakeAccessTokenSource{accessToken: "test-token"}}

	tok, err := s.Auth().AccessToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, auth.AccessToken("test-token"), tok)
}

func TestAccessToken_NoTokenSource(t *testing.T) {
	s := &SDK{}

	tok, err := s.Auth().AccessToken(context.Background())
	require.ErrorIs(t, err, ErrNoAccessTokenSource)
	assert.Empty(t, tok)
}

func TestAccessToken_EmptyToken(t *testing.T) {
	s := &SDK{tokenSource: FakeAccessTokenSource{accessToken: ""}}

	tok, err := s.Auth().AccessToken(context.Background())
	require.ErrorIs(t, err, ErrAccessTokenInvalid)
	assert.Empty(t, tok)
}
