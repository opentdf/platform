package oidc

import (
	"context"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/zitadel/oidc/v3/pkg/client/tokenexchange"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// ExchangeToken performs OAuth2 token exchange (RFC 8693) using Zitadel's OIDC library.
// actorToken and actorTokenType may be empty if not used.
func ExchangeToken(ctx context.Context, issuer, clientID, clientSecret, subjectToken string, dpopKey jwk.Key) (string, error) {
	te, err := tokenexchange.NewTokenExchangerClientCredentials(ctx, issuer, clientID, clientSecret)
	if err != nil {
		return "", fmt.Errorf("failed to create token exchanger: %w", err)
	}

	// Not needed for client credentials flow
	actorToken := ""
	actorTokenType := ""

	resource := []string{}
	audience := []string{clientID}
	scopes := []string{"openid", "profile"}

	resp, err := tokenexchange.ExchangeToken(
		ctx,
		te,
		subjectToken,
		oidc.AccessTokenType,
		actorToken,
		oidc.TokenType(actorTokenType),
		resource,
		audience,
		scopes,
		oidc.AccessTokenType,
	)
	if err != nil {
		return "", fmt.Errorf("token exchange failed: %w", err)
	}
	if resp == nil || resp.AccessToken == "" {
		return "", errors.New("no access_token in token exchange response")
	}
	return resp.AccessToken, nil
}
