package sdk

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/sdk/auth"
	"golang.org/x/oauth2"
)

// OAuthAccessTokenSource allows connecting to an IDP and obtaining an access token.
type OAuthAccessTokenSource struct {
	source         oauth2.TokenSource
	scopes         []string
	dpopKey        jwk.Key
	asymDecryption ocrypto.AsymDecryption
	dpopPEM        string
	dpopSupported  bool
	mutex          sync.RWMutex
}

func NewOAuthAccessTokenSource(
	source oauth2.TokenSource, scopes []string, key *ocrypto.RsaKeyPair,
) (*OAuthAccessTokenSource, error) {
	dpopPublicKeyPEM, dpopKey, asymDecryption, err := getNewDPoPKey(key)
	if err != nil {
		return nil, err
	}

	tokenSource := OAuthAccessTokenSource{
		source:         source,
		scopes:         scopes,
		asymDecryption: *asymDecryption,
		dpopKey:        dpopKey,
		dpopPEM:        dpopPublicKeyPEM,
	}

	return &tokenSource, nil
}

// AccessToken use a pointer receiver so that the token state is shared
func (t *OAuthAccessTokenSource) AccessToken(_ context.Context, _ *http.Client) (auth.AccessToken, error) { // must satisfy auth.AccessTokenSource interface
	tok, err := t.source.Token()
	if err != nil {
		return "", fmt.Errorf("error getting access token: %w", err)
	}

	// Non-nil with AccessToken and not Expired
	if !tok.Valid() {
		return "", ErrAccessTokenInvalid
		// TODO: refresh tokens if expired?
	}

	t.mutex.Lock()
	t.dpopSupported = strings.EqualFold(tok.Type(), "DPoP")
	t.mutex.Unlock()

	return auth.AccessToken(tok.AccessToken), nil
}

func (t *OAuthAccessTokenSource) MakeToken(tokenMaker func(jwk.Key) ([]byte, error)) ([]byte, error) {
	return tokenMaker(t.dpopKey)
}

// DPoPSupported reports whether the most recently retrieved access token is DPoP-bound.
func (t *OAuthAccessTokenSource) DPoPSupported() bool {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	return t.dpopSupported
}
