package sdk

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/sdk/auth"
	"github.com/opentdf/platform/sdk/internal/oauth"
)

const (
	dpopKeySize = 2048
)

func getNewDPoPKey(dpopKeyPair *ocrypto.RsaKeyPair) (string, jwk.Key, *ocrypto.AsymDecryption, error) { //nolint:ireturn // this is only internal
	dpopPrivateKeyPEM, err := dpopKeyPair.PrivateKeyInPemFormat()
	if err != nil {
		return "", nil, nil, fmt.Errorf("error getting dpop of key: %w", err)
	}
	dpopPublicKeyPEM, err := dpopKeyPair.PrivateKeyInPemFormat()
	if err != nil {
		return "", nil, nil, fmt.Errorf("error getting dpop of key: %w", err)
	}

	dpopKey, err := jwk.ParseKey([]byte(dpopPrivateKeyPEM), jwk.WithPEM(true))
	if err != nil {
		return "", nil, nil, fmt.Errorf("error creating JWK: %w", err)
	}
	err = dpopKey.Set("alg", jwa.RS256)
	if err != nil {
		return "", nil, nil, fmt.Errorf("error setting the key algorithm: %w", err)
	}

	asymDecryption, err := ocrypto.NewAsymDecryption(dpopPrivateKeyPEM)
	if err != nil {
		return "", nil, nil, fmt.Errorf("error creating asymmetric decryptor: %w", err)
	}

	return dpopPublicKeyPEM, dpopKey, &asymDecryption, nil
}

// IDPAccessTokenSource credentials that allow us to connect to an IDP and obtain an access token that is bound
// to a DPoP key
type IDPAccessTokenSource struct {
	credentials      oauth.ClientCredentials
	idpTokenEndpoint url.URL
	token            *oauth.Token
	scopes           []string
	dpopKey          jwk.Key
	asymDecryption   ocrypto.AsymDecryption
	dpopPEM          string
	tokenMutex       *sync.Mutex
}

func NewIDPAccessTokenSource(
	credentials oauth.ClientCredentials, idpTokenEndpoint string, scopes []string, key *ocrypto.RsaKeyPair) (*IDPAccessTokenSource, error) {
	endpoint, err := url.Parse(idpTokenEndpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid url [%s]: %w", idpTokenEndpoint, err)
	}

	dpopPublicKeyPEM, dpopKey, asymDecryption, err := getNewDPoPKey(key)
	if err != nil {
		return nil, err
	}

	tokenSource := IDPAccessTokenSource{
		credentials:      credentials,
		idpTokenEndpoint: *endpoint,
		token:            nil,
		scopes:           scopes,
		asymDecryption:   *asymDecryption,
		dpopKey:          dpopKey,
		dpopPEM:          dpopPublicKeyPEM,
		tokenMutex:       &sync.Mutex{},
	}

	return &tokenSource, nil
}

// AccessToken use a pointer receiver so that the token state is shared
func (t *IDPAccessTokenSource) AccessToken(ctx context.Context, client *http.Client) (auth.AccessToken, error) {
	t.tokenMutex.Lock()
	defer t.tokenMutex.Unlock()

	if t.token == nil || t.token.Expired() {
		slog.DebugContext(ctx, "getting new access token")
		tok, err := oauth.GetAccessToken(client, t.idpTokenEndpoint.String(), t.scopes, t.credentials, t.dpopKey)
		if err != nil {
			return "", fmt.Errorf("error getting access token: %w", err)
		}
		t.token = tok
	}

	return auth.AccessToken(t.token.AccessToken), nil
}

func (t *IDPAccessTokenSource) MakeToken(tokenMaker func(jwk.Key) ([]byte, error)) ([]byte, error) {
	return tokenMaker(t.dpopKey)
}
