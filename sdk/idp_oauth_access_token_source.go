package sdk

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/sdk/auth"
	"golang.org/x/oauth2"
)

// OAuthAccessTokenSource allow connecting to an IDP and obtain a DPoP bound access token
type OAuthAccessTokenSource struct {
	source           oauth2.TokenSource
	idpTokenEndpoint url.URL
	scopes           []string
	dpopKey          jwk.Key
	asymDecryption   ocrypto.AsymDecryption
	dpopPEM          string
}

func NewOAuthAccessTokenSource(
	source oauth2.TokenSource, idpTokenEndpoint string, scopes []string, key *ocrypto.RsaKeyPair,
) (*OAuthAccessTokenSource, error) {
	endpoint, err := url.Parse(idpTokenEndpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid url [%s]: %w", idpTokenEndpoint, err)
	}
	if key == nil {
		key, err = buildRSAKeyPair(dpopKeySize)
		if err != nil {
			return nil, fmt.Errorf("error building RSA key pair for DPoP: %w", err)
		}
	}

	dpopPublicKeyPEM, dpopKey, asymDecryption, err := getNewDPoPKey(key)
	if err != nil {
		return nil, err
	}

	tokenSource := OAuthAccessTokenSource{
		source:           source,
		idpTokenEndpoint: *endpoint,
		scopes:           scopes,
		asymDecryption:   *asymDecryption,
		dpopKey:          dpopKey,
		dpopPEM:          dpopPublicKeyPEM,
	}

	return &tokenSource, nil
}

// AccessToken use a pointer receiver so that the token state is shared
func (t *OAuthAccessTokenSource) AccessToken(ctx context.Context, client *http.Client) (auth.AccessToken, error) {
	tok, err := t.source.Token()
	if err != nil {
		return "", fmt.Errorf("error getting access token: %w", err)
	}

	if tok.Expiry.Before(time.Now()) {
		return "", fmt.Errorf("access token expired. Please re-authenticate")
		// TODO: refresh tokens if expired?
	}

	return auth.AccessToken(tok.AccessToken), nil
}

func (t *OAuthAccessTokenSource) MakeToken(tokenMaker func(jwk.Key) ([]byte, error)) ([]byte, error) {
	return tokenMaker(t.dpopKey)
}
