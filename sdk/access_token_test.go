package sdk

import (
	"context"
	"net/http"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
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

type recordCtxKey struct{}

// recordingTokenSource captures what AccessToken forwards to it so tests can assert
// the context and HTTP client are passed through. It records a context value rather
// than the context itself (avoiding a context.Context struct field) and the client
// pointer for identity comparison.
type recordingTokenSource struct {
	token       string
	gotCtxValue any
	gotClient   *http.Client
}

func (r *recordingTokenSource) AccessToken(ctx context.Context, client *http.Client) (auth.AccessToken, error) {
	r.gotCtxValue = ctx.Value(recordCtxKey{})
	r.gotClient = client
	return auth.AccessToken(r.token), nil
}

func (r *recordingTokenSource) MakeToken(func(jwk.Key) ([]byte, error)) ([]byte, error) {
	return nil, nil
}

func TestAccessToken_ForwardsContextAndClient(t *testing.T) {
	ctx := context.WithValue(context.Background(), recordCtxKey{}, "value")
	client := &http.Client{}

	rec := &recordingTokenSource{token: "test-token"}
	s := &SDK{tokenSource: rec}
	s.httpClient = client

	tok, err := s.Auth().AccessToken(ctx)
	require.NoError(t, err)
	assert.Equal(t, auth.AccessToken("test-token"), tok)
	assert.Equal(t, "value", rec.gotCtxValue, "context should be forwarded unchanged")
	assert.Same(t, client, rec.gotClient, "http client should be forwarded unchanged")
}
