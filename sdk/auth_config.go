package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/opentdf/platform/lib/ocrypto"
)

type AuthConfig struct {
	dpopPublicKeyPEM  string
	dpopPrivateKeyPEM string
	accessToken       string
}

type RequestBody struct {
	KeyAccess       `json:"keyAccess"`
	ClientPublicKey string `json:"clientPublicKey"`
	Policy          string `json:"policy"`
}

type rewrapJWTClaims struct {
	jwt.RegisteredClaims
	Body string `json:"requestBody"`
}

// NewAuthConfig Create a new instance of authConfig
func NewAuthConfig() (*AuthConfig, error) {
	rsaKeyPair, err := ocrypto.NewRSAKeyPair(tdf3KeySize)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.NewRSAKeyPair failed: %w", err)
	}

	publicKey, err := rsaKeyPair.PublicKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("ocrypto.PublicKeyInPemFormat failed: %w", err)
	}

	privateKey, err := rsaKeyPair.PrivateKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("ocrypto.PrivateKeyInPemFormat failed: %w", err)
	}

	return &AuthConfig{dpopPublicKeyPEM: publicKey, dpopPrivateKeyPEM: privateKey}, nil
}

func NewOIDCAuthConfig(ctx context.Context, host, realm, clientID, clientSecret, subjectToken string) (*AuthConfig, error) {
	authConfig, err := NewAuthConfig()
	if err != nil {
		return nil, err
	}

	authConfig.accessToken, err = authConfig.fetchOIDCAccessToken(ctx, host, realm, clientID, clientSecret, subjectToken)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch acces token: %w", err)
	}
	return authConfig, nil
}
func (a *AuthConfig) fetchOIDCAccessToken(ctx context.Context, host, realm, clientID, clientSecret, subjectToken string) (string, error) {
	data := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "client_id": {clientID}, "client_secret": {clientSecret}, "subject_token": {subjectToken}, "requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"}}

	body := strings.NewReader(data.Encode())
	kcURL := fmt.Sprintf("%s/auth/realms/%s/protocol/openid-connect/token", host, realm)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, kcURL, body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	certB64 := ocrypto.Base64Encode([]byte(a.dpopPublicKeyPEM))
	req.Header.Set("X-VirtruPubKey", string(certB64))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error making request to IdP for token exchange: %w", err)
	}
	defer resp.Body.Close()

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
	return keyResp.AccessToken, nil
}

func (a *AuthConfig) makeKASRequest(kasPath string, body *RequestBody) (*http.Response, error) {
	kasURL := body.KasURL

	requestBodyData, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal failed: %w", err)
	}

	claims := rewrapJWTClaims{
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		string(requestBodyData),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	signingRSAPrivateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(a.dpopPrivateKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("jwt.ParseRSAPrivateKeyFromPEM failed: %w", err)
	}

	signedToken, err := token.SignedString(signingRSAPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("jwt.SignedString failed: %w", err)
	}

	signedTokenRequestBody, err := json.Marshal(map[string]string{
		kSignedRequestToken: signedToken,
	})
	if err != nil {
		return nil, fmt.Errorf("json.Marshal failed: %w", err)
	}

	kasRequestURL, err := url.JoinPath(fmt.Sprintf("%v", kasURL), kasPath)
	if err != nil {
		return nil, fmt.Errorf("url.JoinPath failed: %w", err)
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, kasRequestURL,
		bytes.NewBuffer(signedTokenRequestBody))
	if err != nil {
		return nil, fmt.Errorf("http.NewRequestWithContext failed: %w", err)
	}

	// add required headers
	request.Header = http.Header{
		kContentTypeKey:   {kContentTypeJSONValue},
		kAuthorizationKey: {fmt.Sprintf("Bearer %s", a.accessToken)},
		kAcceptKey:        {kContentTypeJSONValue},
	}

	client := &http.Client{}

	response, err := client.Do(request)
	if err != nil {
		slog.Error("failed http request")
		return nil, fmt.Errorf("http request failed: %w", err)
	}

	return response, nil
}

func (a *AuthConfig) unwrap(keyAccess KeyAccess, policy string) ([]byte, error) {
	requestBody := RequestBody{
		KeyAccess:       keyAccess,
		Policy:          policy,
		ClientPublicKey: a.dpopPublicKeyPEM,
	}

	response, err := a.makeKASRequest(kRewrapV2, &requestBody)
	defer func() {
		if response == nil {
			return
		}
		err := response.Body.Close()
		if err != nil {
			slog.Error("Fail to close HTTP response")
		}
	}()

	if err != nil {
		slog.Error("failed http request")
		return nil, err
	}
	if response.StatusCode != kHTTPOk {
		return nil, fmt.Errorf("http request failed status code:%d", response.StatusCode)
	}

	rewrapResponseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("io.ReadAll failed: %w", err)
	}

	key, err := getWrappedKey(rewrapResponseBody, a.dpopPrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap the wrapped key:%w", err)
	}

	return key, nil
}

func getWrappedKey(rewrapResponseBody []byte, clientPrivateKey string) ([]byte, error) {
	var data map[string]interface{}
	err := json.Unmarshal(rewrapResponseBody, &data)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal failed: %w", err)
	}

	entityWrappedKey, ok := data[kEntityWrappedKey]
	if !ok {
		return nil, fmt.Errorf("entityWrappedKey is missing in key access object")
	}

	asymDecrypt, err := ocrypto.NewAsymDecryption(clientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.NewAsymDecryption failed: %w", err)
	}

	entityWrappedKeyDecoded, err := ocrypto.Base64Decode([]byte(fmt.Sprintf("%v", entityWrappedKey)))
	if err != nil {
		return nil, fmt.Errorf("ocrypto.Base64Decode failed: %w", err)
	}

	key, err := asymDecrypt.Decrypt(entityWrappedKeyDecoded)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.Decrypt failed: %w", err)
	}

	return key, nil
}

func (*AuthConfig) getPublicKey(kasInfo KASInfo) (string, error) {
	kasPubKeyURL, err := url.JoinPath(kasInfo.URL, kasPublicKeyPath)
	if err != nil {
		return "", fmt.Errorf("url.Parse failed: %w", err)
	}

	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, kasPubKeyURL, nil)
	if err != nil {
		return "", fmt.Errorf("http.NewRequestWithContext failed: %w", err)
	}

	// add required headers
	request.Header = http.Header{
		kAcceptKey: {kContentTypeJSONValue},
	}

	client := &http.Client{}

	response, err := client.Do(request)
	defer func() {
		if response == nil {
			return
		}
		err := response.Body.Close()
		if err != nil {
			slog.Error("Fail to close HTTP response")
		}
	}()
	if err != nil {
		slog.Error("failed http request")
		return "", fmt.Errorf("client.Do error: %w", err)
	}
	if response.StatusCode != kHTTPOk {
		return "", fmt.Errorf("client.Do failed: %w", err)
	}

	var jsonResponse interface{}
	err = json.NewDecoder(response.Body).Decode(&jsonResponse)
	if err != nil {
		return "", fmt.Errorf("json.NewDecoder.Decode failed: %w", err)
	}

	return fmt.Sprintf("%s", jsonResponse), nil
}
