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
func ValidateClientCredentials(ctx context.Context, oidcConfig *DiscoveryConfiguration, clientID string, clientScopes []string, clientKey []byte, tlsNoVerify bool, timeout time.Duration, dpopJWK jwk.Key, nonce string) error {
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

	key, err := ParseJWKFromPEM(clientKey)
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
	form.Set("scope", strings.Join(clientScopes, " "))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// If dpopJWK is nil, generate a new EC key for DPoP
	if dpopJWK == nil {
		var err error
		dpopJWK, err = GenerateDPoPKey()
		if err != nil {
			return err
		}
	}

	if dpopJWK != nil {
		dpopProof, err := getDPoPAssertion(dpopJWK, http.MethodPost, tokenEndpoint, nonce)
		if err != nil {
			return fmt.Errorf("failed to generate DPoP proof: %w", err)
		}
		req.Header.Set("DPoP", dpopProof)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to obtain client credentials: %w", err)
	}
	defer resp.Body.Close()

	// Check for DPoP-Nonce header if request failed
	if resp.StatusCode != http.StatusOK {
		nonce := resp.Header.Get("DPoP-Nonce")
		if nonce != "" {
			// Retry once with the nonce and a fresh client_assertion JWT
			jwtAssertion2, err := BuildJWTAssertion(clientID, tokenEndpoint)
			if err != nil {
				return fmt.Errorf("failed to build private_key_jwt assertion (retry): %w", err)
			}
			signedJWT2, err := SignJWTAssertion(jwtAssertion2, key, alg)
			if err != nil {
				return fmt.Errorf("failed to sign private_key_jwt assertion (retry): %w", err)
			}
			form.Set("client_assertion", string(signedJWT2))
			dpopProof, err := getDPoPAssertion(dpopJWK, http.MethodPost, tokenEndpoint, nonce)
			if err != nil {
				return fmt.Errorf("failed to generate DPoP proof with nonce: %w", err)
			}
			req2, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
			if err != nil {
				return fmt.Errorf("failed to create token request (retry): %w", err)
			}
			req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req2.Header.Set("DPoP", dpopProof)
			resp2, err := httpClient.Do(req2)
			if err != nil {
				return fmt.Errorf("failed to obtain client credentials (retry): %w", err)
			}
			defer resp2.Body.Close()
			if resp2.StatusCode != http.StatusOK {
				body := make([]byte, 1024)
				resp2.Body.Read(body)
				return fmt.Errorf("token endpoint returned status (retry): %s, body: %s", resp2.Status, body)
			}
			var respData struct {
				AccessToken string `json:"access_token"`
			}
			if err := json.NewDecoder(resp2.Body).Decode(&respData); err != nil {
				return fmt.Errorf("failed to decode token response (retry): %w", err)
			}
			if respData.AccessToken == "" {
				return errors.New("invalid client credentials: no access token received (retry)")
			}
			return nil
		}
		body := make([]byte, 1024)
		resp.Body.Read(body)
		return fmt.Errorf("token endpoint returned status: %s, body: %s", resp.Status, body)
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
