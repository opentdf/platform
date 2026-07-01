package sdk

import (
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/sdk/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestNewOAuthAccessTokenSource_Success(t *testing.T) {
	mockToken := "mockToken"
	// Expected
	mockSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: mockToken})
	mockScopes := []string{"scope1", "scope2"}
	mockKey, _ := ocrypto.NewRSAKeyPair(dpopKeySize)
	dpopPublicKeyPEM, dpopKey, asymDecryption, _ := getNewDPoPKey(&mockKey)

	// Testable
	tokenSource, err := NewOAuthAccessTokenSource(mockSource, mockScopes, &mockKey)

	// Sanity Checks
	require.NoError(t, err)
	assert.NotNil(t, tokenSource)
	assert.Equal(t, mockScopes, tokenSource.scopes)
	// DPoP values
	assert.Equal(t, asymDecryption, &tokenSource.asymDecryption)
	assert.Equal(t, dpopPublicKeyPEM, tokenSource.dpopPEM)
	assert.Equal(t, dpopKey, tokenSource.dpopKey)
	// Interface checks
	tok, err := tokenSource.AccessToken(t.Context(), nil)
	require.NoError(t, err)
	assert.Equal(t, tok, auth.AccessToken(mockToken))
	made, err := tokenSource.MakeToken(func(jwk.Key) ([]byte, error) { return []byte(mockToken), nil })
	require.NoError(t, err)
	assert.Equal(t, made, []byte(mockToken))
}

func TestNewOAuthAccessTokenSource_ExpiredToken(t *testing.T) {
	// Expected
	pastTime := time.Now().Add(-time.Hour)
	mockSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "mockToken", Expiry: pastTime})
	mockScopes := []string{"scope1"}
	mockKey, _ := ocrypto.NewRSAKeyPair(dpopKeySize)

	// Testable
	tokenSource, err := NewOAuthAccessTokenSource(mockSource, mockScopes, &mockKey)

	// Sanity Checks
	require.NoError(t, err)
	assert.NotNil(t, tokenSource)
	// Interface checks
	tok, err := tokenSource.AccessToken(t.Context(), nil)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrAccessTokenInvalid)
	assert.Empty(t, tok)
}

func TestNewOAuthAccessTokenSource_InvalidTokenSource(t *testing.T) {
	// Expected
	mockSource := oauth2.StaticTokenSource(&oauth2.Token{})
	mockScopes := []string{"scope1"}
	mockKey, _ := ocrypto.NewRSAKeyPair(dpopKeySize)

	// Testable
	tokenSource, err := NewOAuthAccessTokenSource(mockSource, mockScopes, &mockKey)

	// Sanity Checks
	require.NoError(t, err)
	assert.NotNil(t, tokenSource)
	// Interface checks
	tok, err := tokenSource.AccessToken(t.Context(), nil)
	require.Error(t, err)
	assert.Empty(t, tok)
}

// countingTokenSource records how many times the underlying source is queried,
// so tests can assert that valid tokens are cached rather than re-fetched.
type countingTokenSource struct {
	calls int
	tok   *oauth2.Token
}

func (c *countingTokenSource) Token() (*oauth2.Token, error) {
	c.calls++
	return c.tok, nil
}

func TestNewOAuthAccessTokenSource_CachesValidToken(t *testing.T) {
	counting := &countingTokenSource{
		tok: &oauth2.Token{AccessToken: "mockToken", Expiry: time.Now().Add(time.Hour)},
	}
	mockKey, _ := ocrypto.NewRSAKeyPair(dpopKeySize)

	tokenSource, err := NewOAuthAccessTokenSource(counting, []string{"scope1"}, &mockKey)
	require.NoError(t, err)

	for range 3 {
		tok, err := tokenSource.AccessToken(t.Context(), nil)
		require.NoError(t, err)
		assert.Equal(t, auth.AccessToken("mockToken"), tok)
	}

	assert.Equal(t, 1, counting.calls, "valid token should be fetched once and reused")
}

func TestNewOAuthAccessTokenSource_InvalidKey(t *testing.T) {
	// Expected
	mockSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "mockToken"})
	mockScopes := []string{"scope1"}
	badKey := ocrypto.RsaKeyPair{}

	// Testable
	tokenSource, err := NewOAuthAccessTokenSource(mockSource, mockScopes, &badKey)

	// Sanity Checks
	require.Error(t, err)
	assert.Nil(t, tokenSource)
}
