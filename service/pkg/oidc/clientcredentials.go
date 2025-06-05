package oidc

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// For testing purposes only
var skipValidation = false

// SetSkipValidationForTest sets the skipValidation flag for testing
// This should only be used in tests
func SetSkipValidationForTest(skip bool) {
	skipValidation = skip
}

// ClientCredentialsToken fetches a client credentials access token for the given client
func ClientCredentialsToken(ctx context.Context, oidcConfig *DiscoveryConfiguration, clientID string, clientScopes []string, clientKey []byte, tlsNoVerify bool, timeout time.Duration, _ jwk.Key) (string, error) {
	baseClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				//nolint:gosec // skip tls verification allowed if requested
				InsecureSkipVerify: tlsNoVerify,
			},
		},
		Timeout: timeout,
	}
	httpClient, err := NewHTTPClient(baseClient, WithGeneratedDPoPKey(), WithOAuthFlow())
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP client: %w", err)
	}

	key, err := parseKey(clientKey)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	params := OAuthFormParams{
		FormType: OAuthFormClientCredentials,
		ClientID: clientID,
		Scopes:   clientScopes,
	}
	req := httpClient.NewOAuthFormRequest(ctx, key, oidcConfig.TokenEndpoint, params)
	resp, err := req.Do()
	if err != nil {
		return "", fmt.Errorf("failed to obtain client credentials: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read token response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned status: %s, body: %s", resp.Status, string(bodyBytes))
	}

	var respData struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(bodyBytes, &respData); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}
	if respData.AccessToken == "" {
		return "", errors.New("invalid client credentials: no access token received")
	}
	return respData.AccessToken, nil
}

// ValidateClientCredentials now just calls ClientCredentialsToken and discards the token
func ValidateClientCredentials(ctx context.Context, oidcConfig *DiscoveryConfiguration, clientID string, clientScopes []string, clientKey []byte, tlsNoVerify bool, timeout time.Duration, dpopJWK jwk.Key) error {
	if skipValidation {
		return nil
	}
	_, err := ClientCredentialsToken(ctx, oidcConfig, clientID, clientScopes, clientKey, tlsNoVerify, timeout, dpopJWK)
	return err
}
