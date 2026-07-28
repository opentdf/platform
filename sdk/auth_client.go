package sdk

import (
	"context"

	"github.com/opentdf/platform/sdk/auth"
)

// Auth returns an AuthClient for authentication-related operations.
func (s *SDK) Auth() *AuthClient {
	return &AuthClient{sdk: s}
}

// AuthClient groups authentication operations for the SDK.
type AuthClient struct {
	sdk *SDK
}

// AccessToken returns a valid access token for the SDK's configured credentials.
// It returns ErrNoAccessTokenSource if the SDK was created without credentials, and
// ErrAccessTokenInvalid if the token source returns an empty token.
func (a *AuthClient) AccessToken(ctx context.Context) (auth.AccessToken, error) {
	if a.sdk.tokenSource == nil {
		return "", ErrNoAccessTokenSource
	}
	token, err := a.sdk.tokenSource.AccessToken(ctx, a.sdk.httpClient)
	if err != nil {
		return "", err
	}
	if token == "" {
		return "", ErrAccessTokenInvalid
	}
	return token, nil
}
