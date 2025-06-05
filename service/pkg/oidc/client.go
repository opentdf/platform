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

// ValidateClientCredentials checks if the provided client credentials are valid by making a request to the token endpoint
func ValidateClientCredentials(ctx context.Context, oidcConfig *DiscoveryConfiguration, clientID string, clientScopes []string, clientKey []byte, tlsNoVerify bool, timeout time.Duration, dpopJWK jwk.Key) error {
	if skipValidation {
		return nil
	}

	baseClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				//nolint:gosec // skip tls verification allowed if requested
				InsecureSkipVerify: tlsNoVerify,
			},
		},
		Timeout: timeout,
	}
	httpClient, err := NewHTTPClient(baseClient, WithGeneratedDPoPKey())
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %w", err)
	}

	key, err := ParseJWKFromPEM(clientKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	params := OAuthFormParams{
		FormType: OAuthFormClientCredentials,
		ClientID: clientID,
		Scopes:   clientScopes,
	}
	req := httpClient.NewOAuthFormRequestFactory(ctx, key, oidcConfig.TokenEndpoint, params)
	resp, err := req.Do(oidcConfig.TokenEndpoint)
	if err != nil {
		return fmt.Errorf("failed to obtain client credentials: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read token response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token endpoint returned status: %s, body: %s", resp.Status, string(bodyBytes))
	}

	var respData struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(bodyBytes, &respData); err != nil {
		return fmt.Errorf("failed to decode token response: %w", err)
	}
	if respData.AccessToken == "" {
		return errors.New("invalid client credentials: no access token received")
	}
	return nil
}
