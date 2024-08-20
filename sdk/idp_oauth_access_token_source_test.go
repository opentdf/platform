package sdk

import (
	"context"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/sdk/auth"
	"github.com/stretchr/testify/assert"
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
	assert.NoError(t, err)
	assert.NotNil(t, tokenSource)
	assert.Equal(t, mockSource, tokenSource.source)
	assert.Equal(t, mockScopes, tokenSource.scopes)
	// DPoP values
	assert.Equal(t, asymDecryption, &tokenSource.asymDecryption)
	assert.Equal(t, dpopPublicKeyPEM, tokenSource.dpopPEM)
	assert.Equal(t, dpopKey, tokenSource.dpopKey)
	// Interface checks
	tok, err := tokenSource.AccessToken(context.Background(), nil)
	assert.NoError(t, err)
	assert.Equal(t, tok, auth.AccessToken(mockToken))
	made, err := tokenSource.MakeToken(func(jwk.Key) ([]byte, error) { return []byte(mockToken), nil })
	assert.NoError(t, err)
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
	assert.NoError(t, err)
	assert.NotNil(t, tokenSource)
	assert.Equal(t, mockSource, tokenSource.source)
	// Interface checks
	tok, err := tokenSource.AccessToken(context.Background(), nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAccessTokenInvalid)
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
	assert.NoError(t, err)
	assert.NotNil(t, tokenSource)
	assert.Equal(t, mockSource, tokenSource.source)
	// Interface checks
	tok, err := tokenSource.AccessToken(context.Background(), nil)
	assert.Error(t, err)
	assert.Empty(t, tok)
}

func TestNewOAuthAccessTokenSource_InvalidKey(t *testing.T) {
	// Expected
	mockSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "mockToken"})
	mockScopes := []string{"scope1"}
	badKey := ocrypto.RsaKeyPair{}

	// Testable
	tokenSource, err := NewOAuthAccessTokenSource(mockSource, mockScopes, &badKey)

	// Sanity Checks
	assert.Error(t, err)
	assert.Nil(t, tokenSource)
}
