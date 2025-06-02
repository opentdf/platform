package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
		ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate DPoP EC key: %w", err)
		}
		dpopJWK, err = jwk.FromRaw(ecdsaKey)
		if err != nil {
			return fmt.Errorf("failed to convert EC key to JWK: %w", err)
		}
		dpopJWK.Set(jwk.AlgorithmKey, jwa.ES256)
	}

	if dpopJWK != nil {
		dpopProof, err := getDPoPAssertion(dpopJWK, http.MethodPost, tokenEndpoint, "")
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

// getDPoPAssertion generates a DPoP proof JWT for the given method and endpoint using the provided JWK.
func getDPoPAssertion(dpopJWK jwk.Key, method, endpoint, nonce string) (string, error) {
	const expirationTime = 5 * time.Minute

	publicKey, err := jwk.PublicKeyOf(dpopJWK)
	if err != nil {
		return "", err
	}

	tokenBuilder := jwt.NewBuilder().
		Claim("jti", uuid.NewString()).
		Claim("htm", method).
		Claim("htu", endpoint).
		Claim("iat", time.Now().Unix()).
		Claim("exp", time.Now().Add(expirationTime).Unix())

	if nonce != "" {
		tokenBuilder.Claim("nonce", nonce)
	}

	token, err := tokenBuilder.Build()
	if err != nil {
		return "", err
	}

	headers := jws.NewHeaders()
	err = headers.Set("jwk", publicKey)
	if err != nil {
		return "", err
	}
	err = headers.Set("typ", "dpop+jwt")
	if err != nil {
		return "", err
	}

	alg := dpopJWK.Algorithm()
	if alg == nil {
		alg = jwa.ES256 // Default to ES256 if not set
	}

	proof, err := jwt.Sign(token, jwt.WithKey(alg, dpopJWK, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", err
	}

	return string(proof), nil
}
