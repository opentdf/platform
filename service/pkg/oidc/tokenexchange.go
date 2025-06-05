package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

const (
	// DefaultTokenExchangeTimeout is the default timeout for token exchange HTTP requests
	DefaultTokenExchangeTimeout = 30 * time.Second
)

// ExchangeToken performs OAuth2 token exchange (RFC 8693) using private_key_jwk and optional DPoP.
// If dpopJWK is nil, DPoP is not used.
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
	issuer := oidcConfig.Issuer
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	logger := log.New(os.Stderr, "[TOKEN_EXCHANGE] ", log.LstdFlags)
	logger.Printf("Starting token exchange: issuer=%s, clientID=%s", issuer, clientID)

	dpopJWK, err := GenerateDPoPKey()
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate DPoP key: %w", err)
	}

	httpClient := &http.Client{
		Timeout: DefaultTokenExchangeTimeout,
	}

	// Build JWT assertion for private_key_jwk
	jwtAssertion, err := BuildJWTAssertion(clientID, tokenEndpoint)
	if err != nil {
		return "", nil, fmt.Errorf("failed to build private_key_jwt assertion: %w", err)
	}
	key, err := ParseJWKFromPEM(clientPrivateKey)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse client private key: %w", err)
	}
	alg := jwa.RS256
	signedJWT, err := SignJWTAssertion(jwtAssertion, key, alg)
	if err != nil {
		return "", nil, fmt.Errorf("failed to sign private_key_jwt assertion: %w", err)
	}

	// Okta: Token exchange requires actor_token to be set to the private_key_jwk of the client app
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Set("client_id", clientID)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", string(signedJWT))
	// Add actor_token and actor_token_type for Okta
	form.Set("actor_token", string(signedJWT))
	form.Set("actor_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Set("scope", strings.Join(scopes, " "))
	if len(audience) > 0 {
		for _, a := range audience {
			form.Add("audience", a)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", nil, fmt.Errorf("failed to create token exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if dpopJWK != nil {
		dpopProof, err := getDPoPAssertion(dpopJWK, http.MethodPost, tokenEndpoint, "")
		if err != nil {
			return "", nil, fmt.Errorf("failed to generate DPoP proof: %w", err)
		}
		req.Header.Set("DPoP", dpopProof)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		logger.Printf("Token exchange failed: %v", err)
		return "", nil, fmt.Errorf("token exchange failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle DPoP nonce challenge
	if resp.StatusCode != http.StatusOK {
		nonce := resp.Header.Get("DPoP-Nonce")
		if nonce != "" {
			// Retry once with the nonce and a fresh client_assertion JWT
			jwtAssertion2, err := BuildJWTAssertion(clientID, tokenEndpoint)
			if err != nil {
				return "", nil, fmt.Errorf("failed to build private_key_jwt assertion (retry): %w", err)
			}
			signedJWT2, err := SignJWTAssertion(jwtAssertion2, key, alg)
			if err != nil {
				return "", nil, fmt.Errorf("failed to sign private_key_jwt assertion (retry): %w", err)
			}
			form.Set("client_assertion", string(signedJWT2))
			dpopProof, err := getDPoPAssertion(dpopJWK, http.MethodPost, tokenEndpoint, nonce)
			if err != nil {
				return "", nil, fmt.Errorf("failed to generate DPoP proof with nonce: %w", err)
			}
			req2, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
			if err != nil {
				return "", nil, fmt.Errorf("failed to create token exchange request (retry): %w", err)
			}
			req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req2.Header.Set("DPoP", dpopProof)
			resp2, err := httpClient.Do(req2)
			if err != nil {
				logger.Printf("Token exchange failed (retry): %v", err)
				return "", nil, fmt.Errorf("token exchange failed (retry): %w", err)
			}
			defer resp2.Body.Close()
			if resp2.StatusCode != http.StatusOK {
				logger.Printf("Token exchange failed (retry): status=%s", resp2.Status)
				body := make([]byte, 1024)
				resp2.Body.Read(body)
				logger.Printf("response body (retry): %s", body)
				return "", nil, fmt.Errorf("token exchange failed (retry): %s", resp2.Status)
			}
			var respData struct {
				AccessToken string `json:"access_token"`
				Scopes      string `json:"scope"`
			}
			if err := json.NewDecoder(resp2.Body).Decode(&respData); err != nil {
				return "", nil, fmt.Errorf("failed to decode token exchange response (retry): %w", err)
			}
			if respData.AccessToken == "" {
				return "", nil, errors.New("no access_token in token exchange response (retry)")
			}
			logger.Printf("Token exchange successful (retry): scope=%v", respData.Scopes)
			return respData.AccessToken, dpopJWK, nil
		}
		body := make([]byte, 1024)
		resp.Body.Read(body)
		logger.Printf("response body: %s", body)
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

	logger.Printf("Token exchange successful: scope=%v", respData.Scopes)
	return respData.AccessToken, dpopJWK, nil
}
