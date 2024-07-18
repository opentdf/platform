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
func (k *KASClient) makeRewrapRequest(ctx context.Context, keyAccess KeyAccess, policy string) (*kas.RewrapResponse, error) {
	rewrapRequest, err := k.getRewrapRequest(keyAccess, policy)
	if err != nil {
		return nil, err
	}
	grpcAddress, err := getGRPCAddress(keyAccess.KasURL)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.NewClient(grpcAddress, k.dialOptions...)
	if err != nil {
		return nil, fmt.Errorf("error connecting to sas: %w", err)
	}
	defer conn.Close()

	serviceClient := kas.NewAccessServiceClient(conn)

	response, err := serviceClient.Rewrap(ctx, rewrapRequest)
	if err != nil {
		return nil, fmt.Errorf("error making rewrap request: %w", err)
	}

	return response, nil
}

func (k *KASClient) unwrap(ctx context.Context, keyAccess KeyAccess, policy string) ([]byte, error) {
	response, err := k.makeRewrapRequest(ctx, keyAccess, policy)
	if err != nil {
		return nil, fmt.Errorf("error making rewrap request to kas: %w", err)
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

	now := time.Now()
	tok, err := jwt.NewBuilder().
		Claim("requestBody", string(requestBodyJSON)).
		IssuedAt(now).
		Expiration(now.Add(secondsPerMinute * time.Second)).
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

func (k *KASClient) makeNanoTDFRewrapRequest(ctx context.Context, header string, kasURL string, pubKey string) (*kas.RewrapResponse, error) {
	rewrapRequest, err := k.getNanoTDFRewrapRequest(header, kasURL, pubKey)
	if err != nil {
		return nil, err
	}
	grpcAddress, err := getGRPCAddress(kasURL)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.NewClient(grpcAddress, k.dialOptions...)
	if err != nil {
		return nil, fmt.Errorf("error connecting to kas: %w", err)
	}
	defer conn.Close()

	serviceClient := kas.NewAccessServiceClient(conn)

	response, err := serviceClient.Rewrap(ctx, rewrapRequest)
	if err != nil {
		return nil, fmt.Errorf("error making rewrap request: %w", err)
	}

	return response, nil
}

func (k *KASClient) unwrapNanoTDF(ctx context.Context, header string, kasURL string) ([]byte, error) {
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

	response, err := k.makeNanoTDFRewrapRequest(ctx, header, kasURL, publicKeyAsPem)
	if err != nil {
		return nil, fmt.Errorf("error making nano rewrap request to kas: %w", err)
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

	now := time.Now()
	tok, err := jwt.NewBuilder().
		Claim("requestBody", string(requestBodyJSON)).
		IssuedAt(now).
		Expiration(now.Add(secondsPerMinute * time.Second)).
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

type kasKeyRequest struct {
	url, algorithm string
}

type timeStampedKASInfo struct {
	KASInfo
	time.Time
}

// Caches the most recent key info for a given KAS URL and algorithm
type kasKeyCache struct {
	c map[kasKeyRequest]timeStampedKASInfo
}

func newKasKeyCache() *kasKeyCache {
	return &kasKeyCache{make(map[kasKeyRequest]timeStampedKASInfo)}
}

func (c *kasKeyCache) clear() {
	c.c = make(map[kasKeyRequest]timeStampedKASInfo)
}

func (c *kasKeyCache) get(url, algorithm string) *KASInfo {
	cacheKey := kasKeyRequest{url, algorithm}
	now := time.Now()
	cv, ok := c.c[cacheKey]
	if !ok {
		return nil
	}
	ago := now.Add(-5 * time.Minute)
	if ago.After(cv.Time) {
		delete(c.c, cacheKey)
		return nil
	}
	return &cv.KASInfo
}

func (c *kasKeyCache) store(ki KASInfo) {
	cacheKey := kasKeyRequest{ki.URL, ki.Algorithm}
	c.c[cacheKey] = timeStampedKASInfo{ki, time.Now()}
}

func (s SDK) getPublicKey(ctx context.Context, url, algorithm string) (*KASInfo, error) {
	if s.kasKeyCache != nil {
		if cachedValue := s.kasKeyCache.get(url, algorithm); nil != cachedValue {
			return cachedValue, nil
		}
	}
	grpcAddress, err := getGRPCAddress(url)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(grpcAddress, s.dialOptions...)
	if err != nil {
		return nil, fmt.Errorf("error connecting to grpc service at %s: %w", url, err)
	}
	defer conn.Close()

	serviceClient := kas.NewAccessServiceClient(conn)

	req := kas.PublicKeyRequest{
		Algorithm: algorithm,
	}
	if s.config.tdfFeatures.noKID {
		req.V = "1"
	}
	resp, err := serviceClient.PublicKey(ctx, &req)
	if err != nil {
		return nil, fmt.Errorf("error making request to KAS: %w", err)
	}

	kid := resp.GetKid()
	if s.config.tdfFeatures.noKID {
		kid = ""
	}

	ki := KASInfo{
		URL:       url,
		Algorithm: algorithm,
		KID:       kid,
		PublicKey: resp.GetPublicKey(),
	}
	if s.kasKeyCache != nil {
		s.kasKeyCache.store(ki)
	}
	return &ki, nil
}
