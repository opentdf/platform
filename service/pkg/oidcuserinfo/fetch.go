package oidcuserinfo

import (
	"context"
	"errors"
	"net/http"

	"github.com/zitadel/oidc/v3/oidc"
)

// ExchangeToken performs OAuth2 token exchange (RFC 8693) to obtain a backend-usable token.
func ExchangeToken(ctx context.Context, tokenEndpoint, clientID, clientSecret, subjectToken string) (string, error) {
	req := oidc.TokenExchangeRequest{
		TokenEndpoint:    tokenEndpoint,
		ClientID:         clientID,
		ClientSecret:     clientSecret,
		SubjectToken:     subjectToken,
		SubjectTokenType: oidc.TokenTypeAccessToken,
		GrantType:        oidc.GrantTypeTokenExchange,
	}
	resp, err := oidc.TokenExchange(ctx, http.DefaultClient, req)
	if err != nil {
		return "", err
	}
	if resp.AccessToken == "" {
		return "", errors.New("no access_token in token exchange response")
	}
	return resp.AccessToken, nil
}

// FetchUserInfo fetches userinfo for a given access token, issuer, and sub.
// It uses the cache if available, otherwise performs token exchange and fetches from the UserInfo endpoint.
func (c *UserInfo) FetchUserInfo(ctx context.Context, accessToken, issuer, sub, userInfoEndpoint, tokenEndpoint, clientID, clientSecret string) (map[string]interface{}, error) {
	if userinfo, found := c.Get(ctx, issuer, sub); found {
		return userinfo, nil
	}

	// 1. Token exchange (RFC 8693) if needed
	exchangedToken, err := ExchangeToken(ctx, tokenEndpoint, clientID, clientSecret, accessToken)
	if err != nil {
		// fallback: try original access token if exchange fails
		exchangedToken = accessToken
	}

	// 2. Fetch from UserInfo endpoint using zitadel/oidc
	userInfo, err := oidc.FetchUserInfo(ctx, http.DefaultClient, userInfoEndpoint, exchangedToken)
	if err != nil {
		return nil, err
	}
	var userinfo map[string]interface{}
	if err := userInfo.Claims(&userinfo); err != nil {
		return nil, err
	}
	// 3. Cache result
	c.Set(ctx, issuer, sub, userinfo)
	return userinfo, nil
}
