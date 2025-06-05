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

	key, err := ParseJWKFromPEM(clientKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	alg := jwa.RS256 // Always use RS256 for Okta

	if dpopJWK == nil {
		dpopJWK, err = GenerateDPoPKey()
		if err != nil {
			return fmt.Errorf("failed to generate DPoP key: %w", err)
		}
	}

	jwtAssertion, err := BuildJWTAssertion(clientID, tokenEndpoint)
	if err != nil {
		return fmt.Errorf("failed to build private_key_jwt assertion: %w", err)
	}
	signedJWT, err := SignJWTAssertion(jwtAssertion, key, alg)
	if err != nil {
		return fmt.Errorf("failed to sign private_key_jwt assertion: %w", err)
	}
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", string(signedJWT))
	form.Set("scope", strings.Join(clientScopes, " "))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err := AttachDPoPHeader(req, dpopJWK, tokenEndpoint, ""); err != nil {
		return fmt.Errorf("failed to attach DPoP header: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to obtain client credentials: %w", err)
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)
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
