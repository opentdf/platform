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
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/opentdf/opentdf-v2-poc/internal/crypto"
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

func (authConfig AuthConfig) Unwrap(keyAccessObj KeyAccess, policy string) ([]byte, error) {
	requestBody, err := structToMap(keyAccessObj)
	if err != nil {
		return nil, fmt.Errorf("fail to convert key access object to map:%w", err)
	}

	requestBody[kPolicy] = policy
	kasURL, ok := requestBody[kKasURL]
	if !ok {
		return nil, fmt.Errorf("kas url is missing in key access object")
	}

	clientKeyPair, err := crypto.NewRSAKeyPair(tdf3KeySize)
	if err != nil {
		return nil, fmt.Errorf("crypto.NewRSAKeyPair failed: %w", err)
	}

	clientPubKey, err := clientKeyPair.PublicKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("crypto.PublicKeyInPemFormat failed: %w", err)
	}

	clientPrivateKey, err := clientKeyPair.PrivateKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("crypto.PrivateKeyInPemFormat failed: %w", err)
	}

	requestBody[kClientPublicKey] = clientPubKey
	requestBodyData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal failed: %w", err)
	}

	claims := rewrapJWTClaims{
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(60 * time.Second)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		string(requestBodyData),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	signingRSAPrivateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(authConfig.signingPrivateKey))
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

	kasRewrapURL, err := url.JoinPath(fmt.Sprintf("%v", kasURL), kRewrapV2)
	if err != nil {
		return nil, fmt.Errorf("url.JoinPath failed: %w", err)
	}

	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, kasRewrapURL,
		bytes.NewBuffer(signedTokenRequestBody))
	if err != nil {
		return nil, fmt.Errorf("http.NewRequestWithContext failed: %w", err)
	}

	// add required headers
	request.Header = http.Header{
		kContentTypeKey:   {kContentTypeJSONValue},
		kAuthorizationKey: {authConfig.authToken},
		kAcceptKey:        {kContentTypeJSONValue},
	}

	client := &http.Client{}

	response, err := client.Do(request)
	if response.StatusCode != kHTTPOk {
		return nil, fmt.Errorf("%s failed status code:%d", kasRewrapURL, response.StatusCode)
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			slog.Error("Fail to close HTTP response")
		}
	}(response.Body)

	rewrapResponseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("io.ReadAll failed: %w", err)
	}

	key, err := getWrappedKey(rewrapResponseBody, clientPrivateKey)
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

	asymDecrypt, err := crypto.NewAsymDecryption(clientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("crypto.NewAsymDecryption failed: %w", err)
	}

	entityWrappedKeyDecoded, err := crypto.Base64Decode([]byte(fmt.Sprintf("%v", entityWrappedKey)))
	if err != nil {
		return nil, fmt.Errorf("crypto.Base64Decode failed: %w", err)
	}

	key, err := asymDecrypt.Decrypt(entityWrappedKeyDecoded)
	if err != nil {
		return nil, fmt.Errorf("crypto.Decrypt failed: %w", err)
	}

	return key, nil
}

func structToMap(structObj interface{}) (map[string]interface{}, error) {
	structData, err := json.Marshal(structObj)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal failed: %w", err)
	}

	mapData := make(map[string]interface{})
	err = json.Unmarshal(structData, &mapData)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal failed: %w", err)
	}

	return mapData, nil
}
