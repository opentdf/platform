package oidc

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
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

	httpClient, err := NewHTTPClient(&http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				//nolint:gosec // skip tls verification allowed if requested
				InsecureSkipVerify: tlsNoVerify,
			},
		},
		Timeout: timeout,
	}, dpopJWK)
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %w", err)
	}

	key, err := ParseJWKFromPEM(clientKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	reqFactory := func(nonce string) (*http.Request, error) {
		form, err := createSignedClientCredentialsForm(key, oidcConfig.TokenEndpoint, clientID, clientScopes)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, oidcConfig.TokenEndpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, fmt.Errorf("failed to create token request: %w", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req, nil
	}

	resp, err := httpClient.DoWithDPoP(reqFactory, oidcConfig.TokenEndpoint)
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

func createSignedClientCredentialsForm(key jwk.Key, endpoint string, clientID string, clientScopes []string) (url.Values, error) {
	signedJWT, err := buildSignedJWTAssertion(key, clientID, endpoint)
	if err != nil {
		return nil, err
	}
	values := url.Values{}
	values.Set("grant_type", "client_credentials")
	values.Set("client_id", clientID)
	values.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	values.Set("scope", strings.Join(clientScopes, " "))
	values.Set("client_assertion", signedJWT)
	return values, nil
}

func buildSignedJWTAssertion(key jwk.Key, clientID, tokenEndpoint string) (string, error) {
	jwtAssertion, err := BuildJWTAssertion(clientID, tokenEndpoint)
	if err != nil {
		return "", fmt.Errorf("failed to build private_key_jwt assertion: %w", err)
	}
	signedJWT, err := SignJWTAssertion(jwtAssertion, key, jwa.RS256)
	if err != nil {
		return "", fmt.Errorf("failed to sign private_key_jwt assertion: %w", err)
	}
	return string(signedJWT), nil
}
