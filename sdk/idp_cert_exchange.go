package sdk

import (
	"context"
	"net/http"
	"sync"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opentdf/platform/sdk/auth"
	"github.com/opentdf/platform/sdk/internal/oauth"
)

type CertExchangeTokenSource struct {
	auth.AccessTokenSource
	IdpEndpoint string
	credentials oauth.ClientCredentials
	tokenMutex  *sync.Mutex
	info        oauth.CertExchangeInfo
	token       *oauth.Token
	key         jwk.Key
}

func NewCertExchangeTokenSource(info oauth.CertExchangeInfo, credentials oauth.ClientCredentials, idpTokenEndpoint string) (auth.AccessTokenSource, error) {
	_, dpopKey, _, err := getNewDPoPKey()
	if err != nil {
		return nil, err
	}

	exchangeSource := CertExchangeTokenSource{
		info:        info,
		IdpEndpoint: idpTokenEndpoint,
		credentials: credentials,
		tokenMutex:  &sync.Mutex{},
		key:         dpopKey,
	}

	return &exchangeSource, nil
}

func (c *CertExchangeTokenSource) AccessToken(ctx context.Context, client *http.Client) (auth.AccessToken, error) {
	c.tokenMutex.Lock()
	defer c.tokenMutex.Unlock()

	if c.token == nil || c.token.Expired() {
		tok, err := oauth.DoCertExchange(ctx, client, c.IdpEndpoint, c.info, c.credentials, c.key)
		if err != nil {
			return "", err
		}

		c.token = tok
	}

	return auth.AccessToken(c.token.AccessToken), nil
}

func (c *CertExchangeTokenSource) MakeToken(tokenMaker func(jwk.Key) ([]byte, error)) ([]byte, error) {
	return tokenMaker(c.key)
}
