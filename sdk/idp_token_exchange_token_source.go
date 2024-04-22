package sdk

import (
	"context"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opentdf/platform/sdk/auth"
	"github.com/opentdf/platform/sdk/internal/oauth"
)

type IDPTokenExchangeTokenSource struct {
	IDPAccessTokenSource
	oauth.TokenExchangeInfo
}

func NewIDPTokenExchangeTokenSource(exchangeInfo oauth.TokenExchangeInfo, credentials oauth.ClientCredentials, idpTokenEndpoint string, scopes []string) (*IDPTokenExchangeTokenSource, error) {
	idpSource, err := NewIDPAccessTokenSource(credentials, idpTokenEndpoint, scopes)
	if err != nil {
		return nil, err
	}

	exchangeSource := IDPTokenExchangeTokenSource{
		IDPAccessTokenSource: *idpSource,
		TokenExchangeInfo:    exchangeInfo,
	}

	return &exchangeSource, nil
}

func (i IDPTokenExchangeTokenSource) AccessToken() (auth.AccessToken, error) {
	i.IDPAccessTokenSource.tokenMutex.Lock()
	defer i.IDPAccessTokenSource.tokenMutex.Unlock()

	if i.IDPAccessTokenSource.token == nil || i.IDPAccessTokenSource.token.Expired() {
		tok, err := oauth.DoTokenExchange(context.TODO(), i.idpTokenEndpoint.String(), i.scopes, i.credentials, i.TokenExchangeInfo, i.dpopKey)

		if err != nil {
			return "", err
		}

		i.IDPAccessTokenSource.token = tok
	}

	return auth.AccessToken(i.IDPAccessTokenSource.token.AccessToken), nil
}

func (i IDPTokenExchangeTokenSource) MakeToken(keyMaker func(jwk.Key) ([]byte, error)) ([]byte, error) {
	return i.IDPAccessTokenSource.MakeToken(keyMaker)
}
