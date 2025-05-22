package sdk

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/protocol/go/kas/kasconnect"
	"github.com/opentdf/platform/sdk/auth"
)

const (
	secondsPerMinute = 60
	statusFail       = "fail"
	statusPermit     = "permit"
)

type KASClient struct {
	accessTokenSource auth.AccessTokenSource
	httpClient        *http.Client
	connectOptions    []connect.ClientOption
	sessionKey        ocrypto.KeyPair

	// Set this to enable legacy, non-batch rewrap requests
	supportSingleRewrapEndpoint bool
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

func newKASClient(httpClient *http.Client, options []connect.ClientOption, accessTokenSource auth.AccessTokenSource, sessionKey ocrypto.KeyPair) *KASClient {
	return &KASClient{
		accessTokenSource:           accessTokenSource,
		httpClient:                  httpClient,
		connectOptions:              options,
		sessionKey:                  sessionKey,
		supportSingleRewrapEndpoint: true,
	}
}

// there is no connection caching as of now
func (k *KASClient) makeRewrapRequest(ctx context.Context, requests []*kas.UnsignedRewrapRequest_WithPolicyRequest, pubKey string) (*kas.RewrapResponse, error) {
	rewrapRequest, err := k.getRewrapRequest(requests, pubKey)
	if err != nil {
		return nil, err
	}
	kasURL := requests[0].GetKeyAccessObjects()[0].GetKeyAccessObject().GetKasUrl()
	parsedURL, err := parseBaseURL(kasURL)
	if err != nil {
		return nil, fmt.Errorf("cannot parse kas url(%s): %w", kasURL, err)
	}

	serviceClient := kasconnect.NewAccessServiceClient(k.httpClient, parsedURL, k.connectOptions...)

	response, err := serviceClient.Rewrap(ctx, connect.NewRequest(rewrapRequest))
	if err != nil {
		return upgradeRewrapErrorV1(err, requests)
	}

	upgradeRewrapResponseV1(response.Msg, requests)

	return response.Msg, nil
}

// convert v1 responses to v2
func upgradeRewrapResponseV1(response *kas.RewrapResponse, requests []*kas.UnsignedRewrapRequest_WithPolicyRequest) {
	if len(response.GetResponses()) > 0 {
		return
	}
	if len(response.GetEntityWrappedKey()) == 0 { //nolint:staticcheck // SA1019: use of deprecated method required for compatibility
		return
	}
	if len(requests) == 0 {
		return
	}
	response.Responses = []*kas.PolicyRewrapResult{
		{
			PolicyId: requests[0].GetPolicy().GetId(),
			Results: []*kas.KeyAccessRewrapResult{
				{
					KeyAccessObjectId: requests[0].GetKeyAccessObjects()[0].GetKeyAccessObjectId(),
					Status:            statusPermit,
					Result: &kas.KeyAccessRewrapResult_KasWrappedKey{
						KasWrappedKey: response.GetEntityWrappedKey(), //nolint:staticcheck // SA1019: use of deprecated method
					},
				},
			},
		},
	}
}

// convert v1 errors to v2 responses
func upgradeRewrapErrorV1(err error, requests []*kas.UnsignedRewrapRequest_WithPolicyRequest) (*kas.RewrapResponse, error) {
	if len(requests) != 1 {
		return nil, fmt.Errorf("error making rewrap request: %w", err)
	}

	return &kas.RewrapResponse{
		Responses: []*kas.PolicyRewrapResult{
			{
				PolicyId: requests[0].GetPolicy().GetId(),
				Results: []*kas.KeyAccessRewrapResult{
					{
						KeyAccessObjectId: requests[0].GetKeyAccessObjects()[0].GetKeyAccessObjectId(),
						Status:            statusFail,
						Result: &kas.KeyAccessRewrapResult_Error{
							Error: err.Error(),
						},
					},
				},
			},
		},
	}, nil
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

	// If the session key is empty, all responses are errors
	spk := response.GetSessionPublicKey()
	if spk == "" {
		policyResults := make(map[string][]kaoResult)
		err = errors.New("nanoUnwrap: session public key is empty")
		for _, results := range response.GetResponses() {
			var kaoKeys []kaoResult
			for _, kao := range results.GetResults() {
				if kao.GetStatus() == statusPermit {
					kaoKeys = append(kaoKeys, kaoResult{KeyAccessObjectID: kao.GetKeyAccessObjectId(), Error: err})
				} else {
					kaoKeys = append(kaoKeys, kaoResult{KeyAccessObjectID: kao.GetKeyAccessObjectId(), Error: errors.New(kao.GetError())})
				}
			}
			policyResults[results.GetPolicyId()] = kaoKeys
		}

		return policyResults, nil
	}

	sessionKey, err := ocrypto.ComputeECDHKey([]byte(privateKeyAsPem), []byte(spk))
	if err != nil {
		return nil, fmt.Errorf("nanoUnwrap: ocrypto.ComputeECDHKey failed :%w", err)
	}

	sessionKey, err = ocrypto.CalculateHKDF(versionSalt(), sessionKey)
	if err != nil {
		return nil, fmt.Errorf("nanoUnwrap: ocrypto.CalculateHKDF failed:%w", err)
	}

	aesGcm, err := ocrypto.NewAESGcm(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("nanoUnwrap: ocrypto.NewAESGcm failed:%w", err)
	}

	policyResults := make(map[string][]kaoResult)
	for _, results := range response.GetResponses() {
		var kaoKeys []kaoResult
		for _, kao := range results.GetResults() {
			if kao.GetStatus() == statusPermit {
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
		return nil, errors.New("session key is nil")
	}
	pubKey, err := k.sessionKey.PublicKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("ocrypto.PublicKeyInPermFormat failed: %w", err)
	}
	response, err := k.makeRewrapRequest(ctx, requests, pubKey)
	if err != nil {
		return nil, fmt.Errorf("error making rewrap request to kas: %w", err)
	}

	if ocrypto.IsECKeyType(k.sessionKey.GetKeyType()) {
		return k.handleECKeyResponse(response)
	}
	return k.handleRSAKeyResponse(response)
}

func (k *KASClient) handleECKeyResponse(response *kas.RewrapResponse) (map[string][]kaoResult, error) {
	kasEphemeralPublicKey := response.GetSessionPublicKey()
	clientPrivateKey, err := k.sessionKey.PrivateKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}
	ecdhKey, err := ocrypto.ComputeECDHKey([]byte(clientPrivateKey), []byte(kasEphemeralPublicKey))
	if err != nil {
		return nil, fmt.Errorf("ocrypto.ComputeECDHKey failed: %w", err)
	}

	digest := sha256.New()
	digest.Write([]byte("TDF"))
	salt := digest.Sum(nil)
	sessionKey, err := ocrypto.CalculateHKDF(salt, ecdhKey)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.CalculateHKDF failed: %w", err)
	}

	aesGcm, err := ocrypto.NewAESGcm(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.NewAESGcm failed: %w", err)
	}

	return k.processECResponse(response, aesGcm)
}

func (k *KASClient) processECResponse(response *kas.RewrapResponse, aesGcm ocrypto.AesGcm) (map[string][]kaoResult, error) {
	policyResults := make(map[string][]kaoResult)
	for _, results := range response.GetResponses() {
		var kaoKeys []kaoResult
		for _, kao := range results.GetResults() {
			if kao.GetStatus() == statusPermit {
				key, err := aesGcm.Decrypt(kao.GetKasWrappedKey())
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

func (k *KASClient) handleRSAKeyResponse(response *kas.RewrapResponse) (map[string][]kaoResult, error) {
	clientPrivateKey, err := k.sessionKey.PrivateKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("ocrypto.PrivateKeyInPemFormat failed: %w", err)
	}

	asymDecryption, err := ocrypto.NewAsymDecryption(clientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.NewAsymDecryption failed: %w", err)
	}

	return k.processRSAResponse(response, asymDecryption)
}

func (k *KASClient) processRSAResponse(response *kas.RewrapResponse, asymDecryption ocrypto.AsymDecryption) (map[string][]kaoResult, error) {
	policyResults := make(map[string][]kaoResult)
	for _, results := range response.GetResponses() {
		var kaoKeys []kaoResult
		for _, kao := range results.GetResults() {
			if kao.GetStatus() == statusPermit {
				key, err := asymDecryption.Decrypt(kao.GetKasWrappedKey())
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

func parseBaseURL(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	host := u.Hostname()
	port := u.Port()

	// Add port only if it's present
	addr := host
	if port != "" {
		addr = net.JoinHostPort(host, port)
	}

	return fmt.Sprintf("%s://%s", u.Scheme, addr), nil
}

func (k *KASClient) getRewrapRequest(reqs []*kas.UnsignedRewrapRequest_WithPolicyRequest, pubKey string) (*kas.RewrapRequest, error) {
	if len(reqs) == 0 {
		return nil, errors.New("no requests provided")
	}
	requestBody := &kas.UnsignedRewrapRequest{
		ClientPublicKey: pubKey,
		Requests:        reqs,
	}
	if len(reqs) == 1 && len(reqs[0].GetKeyAccessObjects()) == 1 && k.supportSingleRewrapEndpoint {
		requestBody.KeyAccess = reqs[0].GetKeyAccessObjects()[0].GetKeyAccessObject() //nolint:staticcheck // SA1019: use of deprecated method
		requestBody.Policy = reqs[0].GetPolicy().GetBody()                            //nolint:staticcheck // SA1019: use of deprecated method
		requestBody.Algorithm = reqs[0].GetAlgorithm()                                //nolint:staticcheck // SA1019: use of deprecated method
	}

	requestBodyJSON, err := protojson.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request body: %w", err)
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

func (s SDK) getPublicKey(ctx context.Context, kasurl, algorithm string) (*KASInfo, error) {
	if s.kasKeyCache != nil {
		if cachedValue := s.kasKeyCache.get(kasurl, algorithm); nil != cachedValue {
			return cachedValue, nil
		}
	}
	parsedURL, err := parseBaseURL(kasurl)
	if err != nil {
		return nil, fmt.Errorf("cannot parse kas url(%s): %w", kasurl, err)
	}

	serviceClient := kasconnect.NewAccessServiceClient(s.conn.Client, parsedURL, s.conn.Options...)

	req := kas.PublicKeyRequest{
		Algorithm: algorithm,
	}
	if s.config.tdfFeatures.noKID {
		req.V = "1"
	}
	resp, err := serviceClient.PublicKey(ctx, connect.NewRequest(&req))
	if err != nil {
		return nil, fmt.Errorf("error making request to KAS: %w", err)
	}

	kid := resp.Msg.GetKid()
	if s.config.tdfFeatures.noKID {
		kid = ""
	}

	ki := KASInfo{
		URL:       kasurl,
		Algorithm: algorithm,
		KID:       kid,
		PublicKey: resp.Msg.GetPublicKey(),
	}
	if s.kasKeyCache != nil {
		s.kasKeyCache.store(ki)
	}
	return &ki, nil
}
