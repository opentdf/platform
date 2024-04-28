package sdk

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/arkavo-org/opentdf-platform/lib/ocrypto"
	"github.com/golang-jwt/jwt/v4"
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
	// load private key
	privateKeyBytes, err := os.ReadFile("../pep.key")
	if err != nil {
		return nil, fmt.Errorf("private key not found: %w", err)
	}
	signingRSAPrivateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
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
		kContentTypeKey: {kContentTypeJSONValue},
		//kAuthorizationKey: {fmt.Sprintf("Bearer %s", a.accessToken)},
		kAcceptKey: {kContentTypeJSONValue},
	}
	// Load the client's certificate and private key
	certificate, err := tls.LoadX509KeyPair("../pep.crt", "../pep.key")
	if err != nil {
		log.Fatalf("could not load client key pair: %s", err)
	}
	caCert, err := os.ReadFile("../ca.crt")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
		RootCAs:      caCertPool,
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client := &http.Client{Transport: transport}

	// ++++++++++
	//kasPubKeyURL, err := url.JoinPath(fmt.Sprintf("%v/v2", kasURL), kasPath)
	//if err != nil {
	//	return nil, fmt.Errorf("url.Parse failed: %w", err)
	//}
	//request, err = http.NewRequestWithContext(context.Background(), http.MethodGet, kasPubKeyURL, nil)
	//if err != nil {
	//	return nil, fmt.Errorf("http.NewRequestWithContext failed: %w", err)
	//}
	//// add required headers
	//request.Header = http.Header{
	//	kAcceptKey: {kContentTypeJSONValue},
	//}
	// ++++++++++

	response, err := client.Do(request)
	if err != nil {
		slog.Error("failed http request")
		return nil, fmt.Errorf("http request failed: %w", err)
	}

	return response, nil
}

func (a *AuthConfig) unwrap(keyAccess KeyAccess, policy string) ([]byte, error) {
	// load certificate
	certificateBytes, err := os.ReadFile("../pep.crt")
	if err != nil {
		return nil, fmt.Errorf("private key not found: %w", err)
	}

	block, _ := pem.Decode(certificateBytes)
	if block == nil {
		log.Fatalf("Failed to parse the PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse the DER encoded certificate: %v", err)
	}

	pubKey := cert.PublicKey

	// Use the public key...
	pubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		log.Fatalf("It's not an RSA key")
	}
	// Marshal the public key to ASN.1 DER encoding.
	pubASN1, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		log.Fatalf("Cannot Marshal rsa key to DER format: %s", err)
	}
	// Create a pem.Block with the public key.
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})
	requestBody := RequestBody{
		KeyAccess: keyAccess,
		Policy:    policy,
		// replace with public key from certificate
		ClientPublicKey: string(pubBytes),
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

	privateKeyPEM, err := ioutil.ReadFile("../pep.key")
	if err != nil {
		log.Fatalf("Failed to read the PEM certificate: %v", err)
	}
	key, err := getWrappedKey(rewrapResponseBody, string(privateKeyPEM))
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

	// Load the client's certificate and private key
	certificate, err := tls.LoadX509KeyPair("../pep.crt", "../pep.key")
	if err != nil {
		log.Fatalf("could not load client key pair: %s", err)
	}
	caCert, err := os.ReadFile("../ca.crt")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
		RootCAs:      caCertPool,
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client := &http.Client{Transport: transport}

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
