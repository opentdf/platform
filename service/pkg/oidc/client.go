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

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
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
	now := time.Now()
	jwtBuilder := jwt.NewBuilder().
		Issuer(clientID).
		Subject(clientID).
		Audience([]string{tokenEndpoint}).
		IssuedAt(now).
		Expiration(now.Add(5 * time.Minute)).
		JwtID(uuid.NewString())
	jwtAssertion, err := jwtBuilder.Build()
	if err != nil {
		return fmt.Errorf("failed to build private_key_jwt assertion: %w", err)
	}

	// Clean up JWK input: remove any comment lines (starting with //) and trim whitespace
	jwkStr := string(privateKeyPEM)
	lines := strings.Split(jwkStr, "\n")
	var jsonLines []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "//") && line != "" {
			jsonLines = append(jsonLines, line)
		}
	}
	jwkJSON := strings.Join(jsonLines, "\n")

	fmt.Printf("[DEBUG] Raw JWK input (first 200 chars): %q\n", jwkStr[:min(200, len(jwkStr))])
	fmt.Printf("[DEBUG] Cleaned JWK JSON (first 200 chars): %q\n", jwkJSON[:min(200, len(jwkJSON))])

	key, err := jwk.ParseKey([]byte(jwkJSON), jwk.WithPEM(false)) // Use jwk.WithPEM(false) for JWK
	if err != nil {
		fmt.Printf("[DEBUG] Failed JWK JSON: %s\n", jwkJSON)
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	alg := jwa.RS256 // Always use RS256 for Okta

	kid, _ := key.Get("kid")
	headers := jws.NewHeaders()
	_ = headers.Set(jws.AlgorithmKey, alg)
	if kid != nil {
		_ = headers.Set(jws.KeyIDKey, kid)
	}

	signedJWT, err := jwt.Sign(jwtAssertion, jwt.WithKey(alg, key, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return fmt.Errorf("failed to sign private_key_jwt assertion: %w", err)
	}
	fmt.Printf("[DEBUG] Signed JWT (first 80 chars): %q\n", string(signedJWT)[:80])

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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
