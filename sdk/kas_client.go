package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/sdk/auth"
	"google.golang.org/grpc"
)

const (
	secondsPerMinute = 60
)

type RequestBody struct {
	KeyAccess       `json:"keyAccess"`
	ClientPublicKey string `json:"clientPublicKey"`
	Policy          string `json:"policy"`
}

type KASClient struct {
	accessTokenSource  auth.AccessTokenSource
	dialOptions        []grpc.DialOption
	clientPublicKeyPEM string
	asymDecryption     ocrypto.AsymDecryption
}

// once the backend moves over we should use the same type that the golang backend uses here
type rewrapRequestBody struct {
	KeyAccess       KeyAccess `json:"keyAccess"`
	Policy          string    `json:"policy,omitempty"`
	Algorithm       string    `json:"algorithm,omitempty"`
	ClientPublicKey string    `json:"clientPublicKey"`
	SchemaVersion   string    `json:"schemaVersion,omitempty"`
}

func newKASClient(dialOptions []grpc.DialOption, accessTokenSource auth.AccessTokenSource, sessionKey ocrypto.RsaKeyPair) (*KASClient, error) {
	clientPublicKey, err := sessionKey.PublicKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("ocrypto.PublicKeyInPemFormat failed: %w", err)
	}

	clientPrivateKey, err := sessionKey.PrivateKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("ocrypto.PrivateKeyInPemFormat failed: %w", err)
	}

	asymDecryption, err := ocrypto.NewAsymDecryption(clientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.NewAsymDecryption failed: %w", err)
	}

	return &KASClient{
		accessTokenSource:  accessTokenSource,
		dialOptions:        dialOptions,
		clientPublicKeyPEM: clientPublicKey,
		asymDecryption:     asymDecryption,
	}, nil
}

// there is no connection caching as of now
func (k *KASClient) makeRewrapRequest(keyAccess KeyAccess, policy string) (*kas.RewrapResponse, error) {
	rewrapRequest, err := k.getRewrapRequest(keyAccess, policy)
	if err != nil {
		return nil, err
	}
	grpcAddress, err := getGRPCAddress(keyAccess.KasURL)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.Dial(grpcAddress, k.dialOptions...)
	if err != nil {
		return nil, fmt.Errorf("error connecting to sas: %w", err)
	}
	defer conn.Close()

	ctx := context.Background()
	serviceClient := kas.NewAccessServiceClient(conn)

	response, err := serviceClient.Rewrap(ctx, rewrapRequest)
	if err != nil {
		return nil, fmt.Errorf("error making rewrap request: %w", err)
	}

	return response, nil
}

func (k *KASClient) unwrap(keyAccess KeyAccess, policy string) ([]byte, error) {
	response, err := k.makeRewrapRequest(keyAccess, policy)
	if err != nil {
		return nil, fmt.Errorf("error making request to kas: %w", err)
	}

	key, err := k.asymDecryption.Decrypt(response.GetEntityWrappedKey())
	if err != nil {
		return nil, fmt.Errorf("error decrypting payload from KAS: %w", err)
	}

	return key, nil
}

func (k *KASClient) getNanoTDFRewrapRequest(header string, kasURL string, pubKey string) (*kas.RewrapRequest, error) {
	kAccess := keyAccess{
		Header:        header,
		KeyAccessType: "remote",
		URL:           kasURL,
		Protocol:      "kas",
	}

	requestBody := requestBody{
		Algorithm:       "ec:secp256r1",
		KeyAccess:       kAccess,
		ClientPublicKey: pubKey,
	}

	requestBodyJSON, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("Error marshaling request body: %w", err)
	}

	tok, err := jwt.NewBuilder().
		Claim("requestBody", string(requestBodyJSON)).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(secondsPerMinute * time.Second)).
		Build()

	if err != nil {
		return nil, fmt.Errorf("failed to create jwt: %w", err)
	}

	signedToken, err := k.accessTokenSource.MakeToken(func(key jwk.Key) ([]byte, error) {
		signed, err := jwt.Sign(tok, jwt.WithKey(key.Algorithm(), key))
		if err != nil {
			return nil, fmt.Errorf("error signing DPoP token: %w", err)
		}

		return signed, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to sign the token: %w", err)
	}

	rewrapRequest := kas.RewrapRequest{
		SignedRequestToken: string(signedToken),
	}
	return &rewrapRequest, nil
}

func (k *KASClient) makeNanoTDFRewrapRequest(header string, kasURL string, pubKey string) (*kas.RewrapResponse, error) {
	rewrapRequest, err := k.getNanoTDFRewrapRequest(header, kasURL, pubKey)
	if err != nil {
		return nil, err
	}
	grpcAddress, err := getGRPCAddress(kasURL)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.Dial(grpcAddress, k.dialOptions...)
	if err != nil {
		return nil, fmt.Errorf("error connecting to kas: %w", err)
	}
	defer conn.Close()

	ctx := context.Background()
	serviceClient := kas.NewAccessServiceClient(conn)

	response, err := serviceClient.Rewrap(ctx, rewrapRequest)
	if err != nil {
		return nil, fmt.Errorf("error making rewrap request: %w", err)
	}

	return response, nil
}

func (k *KASClient) unwrapNanoTDF(header string, kasURL string) ([]byte, error) {
	keypair, err := ocrypto.NewECKeyPair(ocrypto.ECCModeSecp256r1)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.NewECKeyPair failed :%w", err)
	}

	publicKeyAsPem, err := keypair.PublicKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("ocrypto.NewECKeyPair.PublicKeyInPemFormat failed :%w", err)
	}

	privateKeyAsPem, err := keypair.PrivateKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("ocrypto.NewECKeyPair.PrivateKeyInPemFormat failed :%w", err)
	}

	response, err := k.makeNanoTDFRewrapRequest(header, kasURL, publicKeyAsPem)
	if err != nil {
		return nil, fmt.Errorf("error making request to kas: %w", err)
	}

	sessionKey, err := ocrypto.ComputeECDHKey([]byte(privateKeyAsPem), []byte(response.GetSessionPublicKey()))
	if err != nil {
		return nil, fmt.Errorf("ocrypto.ComputeECDHKey failed :%w", err)
	}

	sessionKey, err = ocrypto.CalculateHKDF(versionSalt(), sessionKey)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.CalculateHKDF failed:%w", err)
	}

	aesGcm, err := ocrypto.NewAESGcm(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.NewAESGcm failed:%w", err)
	}

	symmetricKey, err := aesGcm.Decrypt(response.GetEntityWrappedKey())
	if err != nil {
		return nil, fmt.Errorf("AesGcm.Decrypt failed:%w", err)
	}

	return symmetricKey, nil
}

func getGRPCAddress(kasURL string) (string, error) {
	parsedURL, err := url.Parse(kasURL)
	if err != nil {
		return "", fmt.Errorf("cannot parse kas url(%s): %w", kasURL, err)
	}

	// Needed to support buffconn for testing
	if parsedURL.Host == "" && parsedURL.Port() == "" {
		return "", nil
	}

	port := parsedURL.Port()
	// if port is empty, default to 443.
	if port == "" {
		port = "443"
	}

	return net.JoinHostPort(parsedURL.Hostname(), port), nil
}

func (k *KASClient) getRewrapRequest(keyAccess KeyAccess, policy string) (*kas.RewrapRequest, error) {
	requestBody := rewrapRequestBody{
		Policy:          policy,
		KeyAccess:       keyAccess,
		ClientPublicKey: k.clientPublicKeyPEM,
	}
	requestBodyJSON, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("Error marshaling request body: %w", err)
	}

	tok, err := jwt.NewBuilder().
		Claim("requestBody", string(requestBodyJSON)).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(secondsPerMinute * time.Second)).
		Build()

	if err != nil {
		return nil, fmt.Errorf("failed to create jwt: %w", err)
	}

	signedToken, err := k.accessTokenSource.MakeToken(func(key jwk.Key) ([]byte, error) {
		signed, err := jwt.Sign(tok, jwt.WithKey(key.Algorithm(), key))
		if err != nil {
			return nil, fmt.Errorf("error signing DPoP token: %w", err)
		}

		return signed, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to sign the token: %w", err)
	}

	rewrapRequest := kas.RewrapRequest{
		SignedRequestToken: string(signedToken),
	}
	return &rewrapRequest, nil
}

func getPublicKey(kasInfo KASInfo, opts ...grpc.DialOption) (string, error) {
	req := kas.PublicKeyRequest{}
	grpcAddress, err := getGRPCAddress(kasInfo.URL)
	if err != nil {
		return "", err
	}
	conn, err := grpc.Dial(grpcAddress, opts...)
	if err != nil {
		return "", fmt.Errorf("error connecting to grpc service at %s: %w", kasInfo.URL, err)
	}
	defer conn.Close()

	ctx := context.Background()
	serviceClient := kas.NewAccessServiceClient(conn)

	resp, err := serviceClient.PublicKey(ctx, &req)

	if err != nil {
		return "", fmt.Errorf("error making request to KAS: %w", err)
	}

	return resp.GetPublicKey(), nil
}
