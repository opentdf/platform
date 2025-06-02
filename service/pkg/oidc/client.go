package oidc

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
)

// For testing purposes only
var skipValidation = false

// SetSkipValidationForTest sets the skipValidation flag for testing
// This should only be used in tests
func SetSkipValidationForTest(skip bool) {
	skipValidation = skip
}

// ValidateClientCredentials checks if the provided client credentials are valid by making a request to the token endpoint
func ValidateClientCredentials(ctx context.Context, oidcConfig *DiscoveryConfiguration, clientID string, privateKeyPEM []byte, tlsNoVerify bool, timeout time.Duration) error {
	if skipValidation {
		return nil
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				//nolint:gosec // skip tls verification allowed if requested
				InsecureSkipVerify: tlsNoVerify,
			},
		},
		Timeout: timeout,
	}

	tokenEndpoint := oidcConfig.TokenEndpoint

	jwtAssertion, err := BuildJWTAssertion(clientID, tokenEndpoint)
	if err != nil {
		return fmt.Errorf("failed to build private_key_jwt assertion: %w", err)
	}

	key, err := ParseJWKFromPEM(privateKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	alg := jwa.RS256 // Always use RS256 for Okta

	signedJWT, err := SignJWTAssertion(jwtAssertion, key, alg)
	if err != nil {
		return fmt.Errorf("failed to sign private_key_jwt assertion: %w", err)
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", string(signedJWT))
	form.Set("scope", "okta.users.read")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to obtain client credentials: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("token endpoint returned status: %s\n", resp.Status)
		body := make([]byte, 1024)
		resp.Body.Read(body)
		fmt.Printf("response body: %s\n", body)
		return fmt.Errorf("token endpoint returned status: %s", resp.Status)
	}

	var respData struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return fmt.Errorf("failed to decode token response: %w", err)
	}
	if respData.AccessToken == "" {
		return errors.New("invalid client credentials: no access token received")
	}
	return nil
}
