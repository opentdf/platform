package sdk

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

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

type KASClient struct {
	accessTokenSource auth.AccessTokenSource
	dialOptions       []grpc.DialOption
	sessionKey        *ocrypto.RsaKeyPair
}

type kaoResult struct {
	SymmetricKey      []byte
	Error             error
	KeyAccessObjectID string
}

type decryptor interface {
	CreateRewrapRequest(ctx context.Context) (map[string]*kas.UnsignedRewrapRequest_WithPolicyRequest, error)
	Decrypt(ctx context.Context, results []kaoResult) (int, error)
}

func newKASClient(dialOptions []grpc.DialOption, accessTokenSource auth.AccessTokenSource, sessionKey *ocrypto.RsaKeyPair) *KASClient {
	return &KASClient{
		accessTokenSource: accessTokenSource,
		dialOptions:       dialOptions,
		sessionKey:        sessionKey,
	}
}

// there is no connection caching as of now
func (k *KASClient) makeRewrapRequest(ctx context.Context, requests []*kas.UnsignedRewrapRequest_WithPolicyRequest, pubKey string) (*kas.RewrapResponse, error) {
	rewrapRequest, err := k.getRewrapRequest(requests, pubKey)
	if err != nil {
		return nil, err
	}
	grpcAddress, err := getGRPCAddress(requests[0].GetKeyAccessObjects()[0].GetKeyAccessObject().GetKasUrl())
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

func (k *KASClient) nanoUnwrap(ctx context.Context, requests ...*kas.UnsignedRewrapRequest_WithPolicyRequest) (map[string][]kaoResult, error) {
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
	response, err := k.makeRewrapRequest(ctx, requests, publicKeyAsPem)
	if err != nil {
		return nil, err
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

	policyResults := make(map[string][]kaoResult)
	for _, results := range response.GetResponses() {
		var kaoKeys []kaoResult
		for _, kao := range results.GetResults() {
			if kao.GetStatus() == "permit" {
				wrappedKey := kao.GetKasWrappedKey()
				key, err := aesGcm.Decrypt(wrappedKey)
				if err != nil {
					kaoKeys = append(kaoKeys, kaoResult{KeyAccessObjectID: kao.GetKeyAccessObjectId(), Error: err})
				} else {
					kaoKeys = append(kaoKeys, kaoResult{KeyAccessObjectID: kao.GetKeyAccessObjectId(), SymmetricKey: key})
				}
			} else {
				kaoKeys = append(kaoKeys, kaoResult{KeyAccessObjectID: kao.GetKeyAccessObjectId(), Error: errors.New(kao.GetError())})
			}
		}
		policyResults[results.GetPolicyId()] = kaoKeys
	}

	return policyResults, nil
}

func (k *KASClient) unwrap(ctx context.Context, requests ...*kas.UnsignedRewrapRequest_WithPolicyRequest) (map[string][]kaoResult, error) {
	if k.sessionKey == nil {
		return nil, fmt.Errorf("session key is nil")
	}
	pubKey, err := k.sessionKey.PublicKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("ocrypto.PublicKeyInPermFormat failed: %w", err)
	}
	response, err := k.makeRewrapRequest(ctx, requests, pubKey)
	if err != nil {
		return nil, fmt.Errorf("error making rewrap request to kas: %w", err)
	}

	clientPrivateKey, err := k.sessionKey.PrivateKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("ocrypto.PrivateKeyInPemFormat failed: %w", err)
	}

	asymDecryption, err := ocrypto.NewAsymDecryption(clientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.NewAsymDecryption failed: %w", err)
	}

	policyResults := make(map[string][]kaoResult)
	for _, results := range response.GetResponses() {
		var kaoKeys []kaoResult
		for _, kao := range results.GetResults() {
			if kao.GetStatus() == "permit" {
				wrappedKey := kao.GetKasWrappedKey()
				key, err := asymDecryption.Decrypt(wrappedKey)
				if err != nil {
					kaoKeys = append(kaoKeys, kaoResult{KeyAccessObjectID: kao.GetKeyAccessObjectId(), Error: err})
				} else {
					kaoKeys = append(kaoKeys, kaoResult{KeyAccessObjectID: kao.GetKeyAccessObjectId(), SymmetricKey: key})
				}
			} else {
				kaoKeys = append(kaoKeys, kaoResult{KeyAccessObjectID: kao.GetKeyAccessObjectId(), Error: errors.New(kao.GetError())})
			}
		}
		policyResults[results.GetPolicyId()] = kaoKeys
	}

	return policyResults, nil
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

func (k *KASClient) getRewrapRequest(reqs []*kas.UnsignedRewrapRequest_WithPolicyRequest, pubKey string) (*kas.RewrapRequest, error) {
	requestBody := &kas.UnsignedRewrapRequest{
		ClientPublicKey: pubKey,
		Requests:        reqs,
	}

	requestBodyJSON, err := protojson.Marshal(requestBody)
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
