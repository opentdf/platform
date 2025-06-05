package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

const (
	// DefaultTokenExchangeTimeout is the default timeout for token exchange HTTP requests
	DefaultTokenExchangeTimeout = 30 * time.Second
)

// Package-level variables for testability
var newExchangeTokenHTTPClient = func() (*HTTPClient, error) {
	return NewHTTPClient(&http.Client{Timeout: DefaultTokenExchangeTimeout}, WithGeneratedDPoPKey(), WithOAuthFlow())
}

// ExchangeToken performs OAuth2 token exchange (RFC 8693) using private_key_jwk and optional DPoP.
// If dpopJWK is nil, DPoP is not used.
// If actorToken is required, pass a non-empty value (typically a client credentials access token).
func ExchangeToken(
	ctx context.Context,
	oidcConfig *DiscoveryConfiguration,
	clientID string,
	clientPrivateKey []byte,
	subjectToken string,
	audience []string,
	scopes []string,
) (string, jwk.Key, error) {
	tokenEndpoint := oidcConfig.TokenEndpoint
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	actorToken, err := ClientCredentialsToken(ctx, oidcConfig, clientID, []string{"okta.users.read"}, clientPrivateKey, false, DefaultTokenExchangeTimeout, nil)
	if err != nil {
		return "", nil, fmt.Errorf("failed to obtain client credentials for token exchange: %w", err)
	}

	httpClient, err := newExchangeTokenHTTPClient()
	if err != nil {
		return "", nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	key, err := parseKey(clientPrivateKey)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse client private key: %w", err)
	}

	params := OAuthFormParams{
		FormType:       OAuthFormTokenExchange,
		ClientID:       clientID,
		Scopes:         scopes,
		SubjectToken:   subjectToken,
		Audience:       audience,
		ActorToken:     actorToken, // Use the provided actor token (should be a client credentials access token)
		ActorTokenType: "urn:ietf:params:oauth:token-type:access_token",
	}

	// Only set ActorToken fields if an actor token is provided (non-empty)
	// If you want to support actor tokens, add them as function parameters and set here.
	// params.ActorToken = ...
	// params.ActorTokenType = ...
	req := httpClient.NewOAuthFormRequest(ctx, key, tokenEndpoint, params)
	resp, err := req.Do()
	if err != nil {
		return "", nil, fmt.Errorf("token exchange failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("token exchange failed: %s", resp.Status)
	}

	var respData struct {
		AccessToken string `json:"access_token"`
		Scopes      string `json:"scope"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return "", nil, fmt.Errorf("failed to decode token exchange response: %w", err)
	}
	if respData.AccessToken == "" {
		return "", nil, errors.New("no access_token in token exchange response")
	}

	return respData.AccessToken, httpClient.DPoPJWK, nil
}
