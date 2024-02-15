package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/opentdf/opentdf-v2-poc/sdk/internal/crypto"
)

type AuthConfig struct {
	signingPublicKey  string
	signingPrivateKey string
	authToken         string
}

// NewAuthConfig Create a new instance of authConfig
func NewAuthConfig() (*AuthConfig, error) {
	rsaKeyPair, err := crypto.NewRSAKeyPair(tdf3KeySize)
	if err != nil {
		return nil, fmt.Errorf("crypto.NewRSAKeyPair failed: %w", err)
	}

	publicKey, err := rsaKeyPair.PublicKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("crypto.PublicKeyInPemFormat failed: %w", err)
	}

	privateKey, err := rsaKeyPair.PrivateKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("crypto.PrivateKeyInPemFormat failed: %w", err)
	}

	return &AuthConfig{signingPublicKey: publicKey, signingPrivateKey: privateKey}, nil
}

func NewOIDCAuthConfig(ctx context.Context, host, realm, clientId, clientSecret, subjectToken string) (*AuthConfig, error) {
	authConfig, err := NewAuthConfig()
	if err != nil {
		return nil, err
	}

	authConfig.authToken, err = authConfig.fetchOIDCAccessToken(ctx, host, realm, clientId, clientSecret, subjectToken)
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch acces token:%w", err)
	}
	return authConfig, nil
}
func (a *AuthConfig) fetchOIDCAccessToken(ctx context.Context, host, realm, clientId, clientSecret, subjectToken string) (string, error) {
	data := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "client_id": {clientId}, "client_secret": {clientSecret}, "subject_token": {subjectToken}, "requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"}}

	body := strings.NewReader(data.Encode())
	kcURL := fmt.Sprintf("%s/auth/realms/%s/protocol/openid-connect/token", host, realm)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, kcURL, body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	certB64 := crypto.Base64Encode([]byte(a.signingPublicKey))
	req.Header.Set("X-VirtruPubKey", string(certB64))

	client := &http.Client{}
	resp, err := client.Do(req)
	type keycloakResponsePayload struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	keyResp := keycloakResponsePayload{}
	respBody, _ := io.ReadAll(resp.Body)
	err = json.Unmarshal(respBody, &keyResp)
	if err != nil {
		return "", err
	}
	return "Bearer " + keyResp.AccessToken, nil
}
