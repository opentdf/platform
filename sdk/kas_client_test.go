package sdk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/lib/ocrypto"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/sdk/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

type FakeAccessTokenSource struct {
	dpopKey        jwk.Key
	asymDecryption ocrypto.AsymDecryption
	asymEncryption ocrypto.AsymEncryption
	accessToken    string
}

func (fake FakeAccessTokenSource) AccessToken(context.Context, *http.Client) (auth.AccessToken, error) {
	return auth.AccessToken(fake.accessToken), nil
}

func (fake FakeAccessTokenSource) MakeToken(tokenMaker func(jwk.Key) ([]byte, error)) ([]byte, error) {
	return tokenMaker(fake.dpopKey)
}

func getTokenSource(t *testing.T) FakeAccessTokenSource {
	dpopKey, _ := ocrypto.NewRSAKeyPair(2048)
	dpopPEM, _ := dpopKey.PrivateKeyInPemFormat()
	decryption, _ := ocrypto.NewAsymDecryption(dpopPEM)
	dpopPEMPublic, _ := dpopKey.PublicKeyInPemFormat()
	encryption, _ := ocrypto.NewAsymEncryption(dpopPEMPublic)
	dpopJWK, err := jwk.ParseKey([]byte(dpopPEM), jwk.WithPEM(true))
	if err != nil {
		t.Fatalf("error creating JWK: %v", err)
	}
	err = dpopJWK.Set("alg", jwa.RS256.String())
	if err != nil {
		t.Fatalf("error setting DPoP key algorithm: %v", err)
	}

	return FakeAccessTokenSource{
		dpopKey:        dpopJWK,
		asymDecryption: decryption,
		asymEncryption: encryption,
		accessToken:    "thisistheaccesstoken",
	}
}

func TestCreatingRequest(t *testing.T) {
	var options []connect.ClientOption
	tokenSource := getTokenSource(t)
	kasKey, err := ocrypto.NewRSAKeyPair(tdf3KeySize)
	require.NoError(t, err, "error creating RSA Key")

	client := newKASClient(nil, options, tokenSource, &kasKey, []string{})
	require.NoError(t, err)

	keyAccess := []*kaspb.UnsignedRewrapRequest_WithPolicyRequest{
		{
			KeyAccessObjects: []*kaspb.UnsignedRewrapRequest_WithKeyAccessObject{
				{
					KeyAccessObject: &kaspb.KeyAccess{
						KeyType:    "type1",
						KasUrl:     "https://kas.example.org",
						Protocol:   "protocol one",
						WrappedKey: []byte("wrapped"),
						PolicyBinding: &kaspb.PolicyBinding{
							Hash:      "somehash",
							Algorithm: "HS256",
						},
						EncryptedMetadata: "encrypted",
					},
				},
			},
		},
	}
	kp, err := ocrypto.NewRSAKeyPair(1024)
	require.NoError(t, err, "failed to make pub key")
	pubkey, err := kp.PublicKeyInPemFormat()
	require.NoError(t, err, "failed to make pub key")

	req, err := client.getRewrapRequest(keyAccess, pubkey)
	require.NoError(t, err, "failed to create a rewrap request")
	if req.GetSignedRequestToken() == "" {
		t.Fatalf("didn't produce a signed request token")
	}

	pubKey, _ := tokenSource.dpopKey.PublicKey()

	tok, err := jwt.ParseString(req.GetSignedRequestToken(), jwt.WithKey(tokenSource.dpopKey.Algorithm(), pubKey))
	require.NoError(t, err, "couldn't parse signed token")

	rb, ok := tok.Get("requestBody")
	require.True(t, ok, "didn't contain a request body")
	requestBodyJSON, _ := rb.(string)
	var requestBody kaspb.UnsignedRewrapRequest

	require.NoError(t, protojson.Unmarshal([]byte(requestBodyJSON), &requestBody), "error unmarshaling request body")

	_, err = ocrypto.NewAsymEncryption(requestBody.GetClientPublicKey())
	require.NoError(t, err, "NewAsymEncryption failed, incorrect public key include")

	require.Len(t, requestBody.GetRequests(), 1)
	require.Len(t, requestBody.GetRequests()[0].GetKeyAccessObjects(), 1)
	kao := requestBody.GetRequests()[0].GetKeyAccessObjects()[0]
	policyBinding := kao.GetKeyAccessObject().GetPolicyBinding()

	assert.Equal(t, "https://kas.example.org", kao.GetKeyAccessObject().GetKasUrl(), "incorrect kasURL")
	assert.Equal(t, "protocol one", kao.GetKeyAccessObject().GetProtocol(), "incorrect protocol")
	assert.Equal(t, []byte("wrapped"), kao.GetKeyAccessObject().GetWrappedKey(), "incorrect wrapped key")
	assert.Equal(t, "HS256", policyBinding.GetAlgorithm(), "incorrect policy binding")
	assert.Equal(t, "somehash", policyBinding.GetHash(), "incorrect policy binding")
	assert.Equal(t, "encrypted", kao.GetKeyAccessObject().GetEncryptedMetadata(), "incorrect encrypted metadata")
}

func Test_StoreKASKeys(t *testing.T) {
	s, err := New("http://localhost:8080",
		WithPlatformConfiguration(PlatformConfiguration{
			"idp": map[string]interface{}{
				"issuer":                 "https://example.org",
				"authorization_endpoint": "https://example.org/auth",
				"token_endpoint":         "https://example.org/token",
			},
		}),
	)
	require.NoError(t, err)

	assert.Nil(t, s.kasKeyCache.get("https://localhost:8080", "ec:secp256r1", "e1"))
	assert.Nil(t, s.kasKeyCache.get("https://localhost:8080", "rsa:2048", "r1"))

	require.NoError(t, s.StoreKASKeys("https://localhost:8080", &policy.KasPublicKeySet{
		Keys: []*policy.KasPublicKey{
			{Pem: "sample", Kid: "e1", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1},
			{Pem: "sample", Kid: "r1", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048},
		},
	}))
	assert.Nil(t, s.kasKeyCache.get("https://nowhere", "alg:unknown", ""))
	assert.Nil(t, s.kasKeyCache.get("https://localhost:8080", "alg:unknown", ""))
	ecKey := s.kasKeyCache.get("https://localhost:8080", "ec:secp256r1", "e1")
	rsaKey := s.kasKeyCache.get("https://localhost:8080", "rsa:2048", "r1")
	require.NotNil(t, ecKey)
	require.Equal(t, "e1", ecKey.KID)
	require.NotNil(t, rsaKey)
	require.Equal(t, "r1", rsaKey.KID)

	k1, err := s.getPublicKey(t.Context(), "https://localhost:8080", "ec:secp256r1", "e1")
	require.NoError(t, err)
	assert.Equal(t, &KASInfo{
		URL:       "https://localhost:8080",
		PublicKey: "sample",
		KID:       "e1",
		Algorithm: "ec:secp256r1",
		Default:   false,
	}, k1)

	s.kasKeyCache = nil
	k2, err := s.getPublicKey(t.Context(), "https://localhost:54321", "ec:secp256r1", "")
	assert.Nil(t, k2)
	require.ErrorContains(t, err, "error making request")
}

type TestUpgradeRewrapRequestV1Suite struct {
	suite.Suite
}

func (suite *TestUpgradeRewrapRequestV1Suite) TestUpgradeRewrapRequestV1_Happy() {
	response := &kaspb.RewrapResponse{
		EntityWrappedKey: []byte("wrappedKey"),
	}
	requests := []*kaspb.UnsignedRewrapRequest_WithPolicyRequest{
		{
			KeyAccessObjects: []*kaspb.UnsignedRewrapRequest_WithKeyAccessObject{
				{
					KeyAccessObjectId: "kaoID",
				},
			},
			Policy: &kaspb.UnsignedRewrapRequest_WithPolicy{
				Id: "policyID",
			},
		},
	}

	upgradeRewrapResponseV1(response, requests)

	suite.Require().Len(response.GetResponses(), 1)
	policyResult := response.GetResponses()[0]
	suite.Equal("policyID", policyResult.GetPolicyId())

	suite.Require().Len(policyResult.GetResults(), 1)
	kaoResult := policyResult.GetResults()[0]

	suite.Equal("kaoID", kaoResult.GetKeyAccessObjectId())
	suite.NotNil(kaoResult.GetKasWrappedKey())
	suite.Empty(kaoResult.GetError())
}

func (suite *TestUpgradeRewrapRequestV1Suite) TestUpgradeRewrapRequestV1_Empty() {
	response := &kaspb.RewrapResponse{}
	requests := []*kaspb.UnsignedRewrapRequest_WithPolicyRequest{}

	upgradeRewrapResponseV1(response, requests)

	suite.EqualExportedValues(&kaspb.RewrapResponse{}, response)
}

func TestUpgradeRewrapRequestV1(t *testing.T) {
	suite.Run(t, new(TestUpgradeRewrapRequestV1Suite))
}

func TestParseBaseUrl(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string
		expectError bool
	}{
		{
			name:        "Valid URL with scheme and port",
			input:       "https://example.com:8080/path",
			expected:    "https://example.com:8080",
			expectError: false,
		},
		{
			name:        "Valid URL with scheme and no port",
			input:       "https://example.com/path",
			expected:    "https://example.com",
			expectError: false,
		},
		{
			name:        "Valid URL with default port",
			input:       "http://example.com",
			expected:    "http://example.com",
			expectError: false,
		},
		{
			name:        "Invalid URL with invalid characters",
			input:       "https://exa mple.com",
			expected:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseBaseURL(tt.input)
			if tt.expectError {
				require.Error(t, err, "Expected an error for test case: %s", tt.name)
			} else {
				require.NoError(t, err, "Did not expect an error for test case: %s", tt.name)
				assert.Equal(t, tt.expected, result, "Unexpected result for test case: %s", tt.name)
			}
		})
	}
}

func TestKasKeyCache_NoKID(t *testing.T) {
	// Create a new KAS key cache
	cache := newKasKeyCache()
	require.NotNil(t, cache, "Failed to create KAS key cache")

	// Define test data
	const (
		testURL       = "https://kas.example.org"
		testAlgorithm = "ec:secp256r1"
		testPubKey    = "test-public-key"
	)

	// Test 1: Store a key with a specific KID
	keyInfoWithKID := KASInfo{
		URL:       testURL,
		Algorithm: testAlgorithm,
		KID:       "specific-kid",
		PublicKey: testPubKey,
	}
	cache.store(keyInfoWithKID)

	// Check if we can retrieve the key when querying with the specific KID
	retrievedKey := cache.get(testURL, testAlgorithm, "specific-kid")
	require.NotNil(t, retrievedKey, "Failed to retrieve key with specific KID")
	assert.Equal(t, testPubKey, retrievedKey.PublicKey, "Retrieved key has incorrect public key")
	assert.Equal(t, "specific-kid", retrievedKey.KID, "Retrieved key has incorrect KID")

	// Check that with empty KID we can find a match through iteration
	retrievedWithEmptyKID := cache.get(testURL, testAlgorithm, "")
	require.NotNil(t, retrievedWithEmptyKID, "Failed to retrieve key with empty KID (should find through iteration)")
	assert.Equal(t, testPubKey, retrievedWithEmptyKID.PublicKey, "Retrieved key has incorrect public key")
	assert.Equal(t, keyInfoWithKID.KID, retrievedWithEmptyKID.KID, "Retrieved key should have the original KID")

	// Test 2: Store a key with a different KID but same URL and algorithm
	keyInfoWithDifferentKID := KASInfo{
		URL:       testURL,
		Algorithm: testAlgorithm,
		KID:       "different-kid",
		PublicKey: "another-public-key",
	}
	// First try to get the key with same URL and algo as pre-existing key to ensure it doesn't iterate over the map.
	specificKIDKey := cache.get(testURL, testAlgorithm, keyInfoWithDifferentKID.KID)
	require.Nil(t, specificKIDKey, "Should not retrieve key with different KID using specific KID lookup")

	cache.store(keyInfoWithDifferentKID)

	// Both keys should be retrievable with their specific KIDs
	specificKIDKey = cache.get(testURL, testAlgorithm, "specific-kid")
	differentKIDKey := cache.get(testURL, testAlgorithm, "different-kid")

	require.NotNil(t, specificKIDKey, "Failed to retrieve original key with specific KID")
	require.NotNil(t, differentKIDKey, "Failed to retrieve key with different KID")

	assert.Equal(t, testPubKey, specificKIDKey.PublicKey, "Retrieved key with specific KID has incorrect public key")
	assert.Equal(t, keyInfoWithDifferentKID.PublicKey, differentKIDKey.PublicKey, "Retrieved key with different KID has incorrect public key")

	// Empty KID lookup should find a key through iteration
	// Note: The implementation may return any key that matches URL and algorithm
	emptyKIDLookup := cache.get(testURL, testAlgorithm, "")
	require.NotNil(t, emptyKIDLookup, "Failed to retrieve key with empty KID")
	// We don't assert which key is returned as that depends on map iteration order

	// Test 3: Store a key with empty KID
	keyInfoWithEmptyKID := KASInfo{
		URL:       testURL,
		Algorithm: testAlgorithm,
		KID:       "", // Empty KID
		PublicKey: "empty-kid-public-key",
	}
	cache.store(keyInfoWithEmptyKID)

	// Empty KID lookup should return this key
	emptyKIDKey := cache.get(testURL, testAlgorithm, "")
	require.NotNil(t, emptyKIDKey, "Failed to retrieve key with empty KID")
	assert.Equal(t, "empty-kid-public-key", emptyKIDKey.PublicKey, "Retrieved key has incorrect public key")
	assert.Empty(t, emptyKIDKey.KID, "Retrieved key should have empty KID")
}

func TestKasKeyCache_Expiration(t *testing.T) {
	// Create a new KAS key cache
	cache := newKasKeyCache()
	require.NotNil(t, cache, "Failed to create KAS key cache")

	// Store a key with a specific KID
	keyInfo := KASInfo{
		URL:       "https://kas.example.org",
		Algorithm: "ec:secp256r1",
		KID:       "test-kid",
		PublicKey: "test-public-key",
	}
	cache.store(keyInfo)

	// Verify the entry is in cache
	retrievedKeyWithKID := cache.get(keyInfo.URL, keyInfo.Algorithm, keyInfo.KID)
	require.NotNil(t, retrievedKeyWithKID, "Key with specific KID should be in cache")

	// Verify we can retrieve the key with empty KID through iteration
	retrievedKeyNoKID := cache.get(keyInfo.URL, keyInfo.Algorithm, "")
	require.NotNil(t, retrievedKeyNoKID, "Key with empty KID lookup should be found through iteration")
	assert.Equal(t, keyInfo.KID, retrievedKeyNoKID.KID, "Empty KID lookup should return the key with the specific KID")

	// Manually modify the time to simulate expiration (beyond 5 minutes)
	cacheKey := kasKeyRequest{keyInfo.URL, keyInfo.Algorithm, keyInfo.KID}

	// Update entry to be expired
	cachedValue := cache.c[cacheKey]
	cachedValue.Time = time.Now().Add(-6 * time.Minute)
	cache.c[cacheKey] = cachedValue

	// Try to retrieve the expired key with specific KID
	retrievedKeyWithKID = cache.get(keyInfo.URL, keyInfo.Algorithm, keyInfo.KID)
	assert.Nil(t, retrievedKeyWithKID, "Expired key with specific KID should not be returned")

	// Try to retrieve with empty KID (should also find nothing since the key is expired)
	retrievedKeyNoKID = cache.get(keyInfo.URL, keyInfo.Algorithm, "")
	assert.Nil(t, retrievedKeyNoKID, "Expired key should not be found with empty KID lookup")

	// Verify the entry was actually removed from the cache
	_, exists := cache.c[cacheKey]
	assert.False(t, exists, "Expired key should be removed from cache")
}

func Test_newConnectRewrapRequest(t *testing.T) {
	c := newKASClient(nil, nil, nil, nil, []string{"https://example.com/attr/attr1/value/val1"})
	req := c.newConnectRewrapRequest(&kaspb.RewrapRequest{}, c.fulfillableObligations)
	require.Equal(t, "https://example.com/attr/attr1/value/val1", req.Header().Get(fulfillableObligationsHeader))
}

func Test_retrieveObligationsFromMetadata(t *testing.T) {
	c := newKASClient(nil, nil, nil, nil, nil)
	metadata := createMetadataWithObligations(map[string][]string{
		"policy1": {"https://example.com/attr/attr1/value/val1", "https://example.com/attr/attr2/value/val2"},
	})

	fqns := c.retrieveObligationsFromMetadata(metadata, "policy1")
	assert.Len(t, fqns, 2)
	assert.Equal(t, "https://example.com/attr/attr1/value/val1", fqns[0])
	assert.Equal(t, "https://example.com/attr/attr2/value/val2", fqns[1])
}

func Test_retrieveObligationsFromMetadata_NoObligations(t *testing.T) {
	c := newKASClient(nil, nil, nil, nil, nil)
	fqns := c.retrieveObligationsFromMetadata(createMetadataWithObligations(nil), "policy1")
	assert.Empty(t, fqns)
}

func Test_retrieveObligationsFromMetadata_NotStructValue(t *testing.T) {
	c := newKASClient(nil, nil, nil, nil, nil)
	metadata := make(map[string]*structpb.Value)
	metadata[triggeredObligationsHeader] = &structpb.Value{
		Kind: &structpb.Value_BoolValue{
			BoolValue: true,
		},
	}
	fqns := c.retrieveObligationsFromMetadata(metadata, "policy1")
	assert.Empty(t, fqns)
}

func Test_retrieveObligationsFromMetadata_PolicyNotPresent(t *testing.T) {
	c := newKASClient(nil, nil, nil, nil, nil)
	metadata := make(map[string]*structpb.Value)
	metadata[triggeredObligationsHeader] = &structpb.Value{
		Kind: &structpb.Value_StructValue{
			StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{}},
		},
	}
	fqns := c.retrieveObligationsFromMetadata(metadata, "policy1")
	assert.Empty(t, fqns)
}

func Test_retrieveObligationsFromMetadata_ListValuesNotPresent(t *testing.T) {
	c := newKASClient(nil, nil, nil, nil, nil)
	metadata := make(map[string]*structpb.Value)
	metadata[triggeredObligationsHeader] = &structpb.Value{
		Kind: &structpb.Value_StructValue{
			StructValue: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"not_a_list": {
						Kind: &structpb.Value_StringValue{StringValue: "not a list"},
					},
				},
			},
		},
	}
	fqns := c.retrieveObligationsFromMetadata(metadata, "policy1")
	assert.Empty(t, fqns)
}

func Test_processRSAResponse(t *testing.T) {
	c := newKASClient(nil, nil, nil, nil, nil)

	// Create a mock AsymDecryption
	mockPrivateKey, err := ocrypto.NewRSAKeyPair(2048)
	require.NoError(t, err)
	privateKeyPEM, err := mockPrivateKey.PrivateKeyInPemFormat()
	require.NoError(t, err)
	mockDecryptor, err := ocrypto.NewAsymDecryption(privateKeyPEM)
	require.NoError(t, err)

	// Create a mock AsymEncryption to create the wrapped key
	publicKeyPEM, err := mockPrivateKey.PublicKeyInPemFormat()
	require.NoError(t, err)
	mockEncryptor, err := ocrypto.NewAsymEncryption(publicKeyPEM)
	require.NoError(t, err)

	symmetricKey := []byte("supersecretkey")
	wrappedKey, err := mockEncryptor.Encrypt(symmetricKey)
	require.NoError(t, err)

	response := &kaspb.RewrapResponse{
		Responses: []*kaspb.PolicyRewrapResult{
			{
				PolicyId: "policy1",
				Results: []*kaspb.KeyAccessRewrapResult{
					{
						KeyAccessObjectId: "kao1",
						Status:            "permit",
						Result: &kaspb.KeyAccessRewrapResult_KasWrappedKey{
							KasWrappedKey: wrappedKey,
						},
					},
				},
			},
		},
		Metadata: createMetadataWithObligations(map[string][]string{
			"policy1": {"https://example.com/attr/attr1/value/val1"},
		}),
	}

	policyResults, err := c.processRSAResponse(response, mockDecryptor)
	require.NoError(t, err)
	require.Len(t, policyResults, 1)

	result, ok := policyResults["policy1"]
	require.True(t, ok)
	require.Equal(t, "policy1", result.policyID)
	require.Len(t, result.kaoRes, 1)
	require.Equal(t, symmetricKey, result.kaoRes[0].SymmetricKey)
	require.Len(t, result.obligations, 1)
	require.Equal(t, "https://example.com/attr/attr1/value/val1", result.obligations[0])
}

func Test_processECResponse(t *testing.T) {
	c := newKASClient(nil, nil, nil, nil, nil)

	// 1. Set up keys for encryption
	kasPublicKey, err := ocrypto.NewECKeyPair(ocrypto.ECCModeSecp256r1)
	require.NoError(t, err)
	kasPublicKeyPEM, err := kasPublicKey.PublicKeyInPemFormat()
	require.NoError(t, err)

	clientPrivateKey, err := ocrypto.NewECKeyPair(ocrypto.ECCModeSecp256r1)
	require.NoError(t, err)
	clientPrivateKeyPEM, err := clientPrivateKey.PrivateKeyInPemFormat()
	require.NoError(t, err)

	// 2. Compute shared secret and derive session key (for encryption)
	ecdhKey, err := ocrypto.ComputeECDHKey([]byte(clientPrivateKeyPEM), []byte(kasPublicKeyPEM))
	require.NoError(t, err)

	digest := sha256.New()
	digest.Write([]byte("TDF"))
	salt := digest.Sum(nil)
	sessionKey, err := ocrypto.CalculateHKDF(salt, ecdhKey)
	require.NoError(t, err)

	// 3. Create AES-GCM cipher for encryption
	encryptor, err := ocrypto.NewAESGcm(sessionKey)
	require.NoError(t, err)

	// 4. Encrypt a symmetric key
	symmetricKey1 := []byte("supersecretkey1")
	wrappedKey1, err := encryptor.Encrypt(symmetricKey1)
	require.NoError(t, err)

	symmetricKey2 := []byte("supersecretkey2")
	wrappedKey2, err := encryptor.Encrypt(symmetricKey2)
	require.NoError(t, err)

	// 5. Create mock response with multiple policies
	response := &kaspb.RewrapResponse{
		Responses: []*kaspb.PolicyRewrapResult{
			{
				PolicyId: "policy1",
				Results: []*kaspb.KeyAccessRewrapResult{
					{
						KeyAccessObjectId: "kao1",
						Status:            "permit",
						Result: &kaspb.KeyAccessRewrapResult_KasWrappedKey{
							KasWrappedKey: wrappedKey1,
						},
					},
				},
			},
			{
				PolicyId: "policy2",
				Results: []*kaspb.KeyAccessRewrapResult{
					{
						KeyAccessObjectId: "kao2",
						Status:            "permit",
						Result: &kaspb.KeyAccessRewrapResult_KasWrappedKey{
							KasWrappedKey: wrappedKey2,
						},
					},
				},
			},
		},
		Metadata: createMetadataWithObligations(map[string][]string{
			"policy1": {"https://example.com/attr/attr1/value/val1"},
			"policy2": {"https://example.com/attr/attr2/value/val2"},
		}),
	}

	// 6. Create AES-GCM cipher for decryption (using the same session key)
	decryptor, err := ocrypto.NewAESGcm(sessionKey)
	require.NoError(t, err)

	// 7. Process the response
	policyResults, err := c.processECResponse(response, decryptor)
	require.NoError(t, err)
	require.Len(t, policyResults, 2)

	// 8. Assertions for policy1
	result1, ok := policyResults["policy1"]
	require.True(t, ok)
	require.Equal(t, "policy1", result1.policyID)
	require.Len(t, result1.kaoRes, 1)
	require.Equal(t, symmetricKey1, result1.kaoRes[0].SymmetricKey)
	require.Len(t, result1.obligations, 1)
	require.Equal(t, "https://example.com/attr/attr1/value/val1", result1.obligations[0])

	// 9. Assertions for policy2
	result2, ok := policyResults["policy2"]
	require.True(t, ok)
	require.Equal(t, "policy2", result2.policyID)
	require.Len(t, result2.kaoRes, 1)
	require.Equal(t, symmetricKey2, result2.kaoRes[0].SymmetricKey)
	require.Len(t, result2.obligations, 1)
	require.Equal(t, "https://example.com/attr/attr2/value/val2", result2.obligations[0])
}

type mockService interface {
	Process(req *http.Request) (*http.Response, error)
}

type MockKas struct {
	t           *testing.T
	obligations map[string][]string // policyID -> obligations
}

func (f *MockKas) Process(req *http.Request) (*http.Response, error) {
	// 1. KAS generates its own ephemeral keypair for the ECDH exchange.
	kasKeypair, err := ocrypto.NewECKeyPair(ocrypto.ECCModeSecp256r1)
	require.NoError(f.t, err)
	kasPublicKeyPEM, err := kasKeypair.PublicKeyInPemFormat()
	require.NoError(f.t, err)
	kasPrivateKeyPEM, err := kasKeypair.PrivateKeyInPemFormat()
	require.NoError(f.t, err)

	// 2. Extract the client's public key from the incoming request.
	bodyBytes, err := io.ReadAll(req.Body)
	require.NoError(f.t, err)
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes)) // Restore body

	var bodyJSON map[string]interface{}
	err = json.Unmarshal(bodyBytes, &bodyJSON)
	require.NoError(f.t, err)
	signedRequestToken, ok := bodyJSON["signedRequestToken"].(string)
	require.True(f.t, ok)

	// We need a public key to verify the token, but for this mock we can parse without verification.
	token, err := jwt.ParseString(signedRequestToken, jwt.WithVerify(false))
	require.NoError(f.t, err)

	requestBodyClaim, _ := token.Get("requestBody")
	requestBodyJSON, _ := requestBodyClaim.(string)
	var unsignedReq kaspb.UnsignedRewrapRequest
	err = protojson.Unmarshal([]byte(requestBodyJSON), &unsignedReq)
	require.NoError(f.t, err)
	clientPublicKeyPEM := unsignedReq.GetClientPublicKey()

	// 3. Compute the shared secret (ECDH) and derive the session key (HKDF).
	ecdhKey, err := ocrypto.ComputeECDHKey([]byte(kasPrivateKeyPEM), []byte(clientPublicKeyPEM))
	require.NoError(f.t, err)
	sessionKey, err := ocrypto.CalculateHKDF(versionSalt(), ecdhKey)
	require.NoError(f.t, err)

	// 4. Encrypt the symmetric key using the derived session key.
	encryptor, err := ocrypto.NewAESGcm(sessionKey)
	require.NoError(f.t, err)
	symmetricKey := []byte("supersecretkey1")
	wrappedKey, err := encryptor.Encrypt(symmetricKey)
	require.NoError(f.t, err)

	// 5. Construct the KAS rewrap response.
	rewrapResponse := &kaspb.RewrapResponse{
		SessionPublicKey: kasPublicKeyPEM,
	}
	triggeredObligations := make(map[string][]string)
	for _, req := range unsignedReq.GetRequests() {
		policyID := req.GetPolicy().GetId()
		rewrapResponse.Responses = append(rewrapResponse.Responses, &kaspb.PolicyRewrapResult{
			PolicyId: policyID,
			Results: []*kaspb.KeyAccessRewrapResult{
				{
					KeyAccessObjectId: req.GetKeyAccessObjects()[0].GetKeyAccessObjectId(),
					Status:            "permit",
					Result: &kaspb.KeyAccessRewrapResult_KasWrappedKey{
						KasWrappedKey: wrappedKey,
					},
				},
			},
		})

		if fqns, exists := f.obligations[policyID]; exists {
			triggeredObligations[policyID] = fqns
		}
	}
	rewrapResponse.Metadata = createMetadataWithObligations(triggeredObligations)

	responseBody, err := protojson.Marshal(rewrapResponse)
	require.NoError(f.t, err)

	mockHTTPResponse := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(responseBody)),
		Header:     make(http.Header),
	}
	mockHTTPResponse.Header.Set("Content-Type", "application/json")

	return mockHTTPResponse, nil
}

// mockRoundTripper is a mock implementation of http.RoundTripper for testing.
type mockRoundTripper struct {
	Response    *http.Response
	mockService mockService
	Err         error
}

// RoundTrip implements the http.RoundTripper interface.
func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.Err != nil || m.Response != nil {
		return m.Response, m.Err
	}
	return m.mockService.Process(req)
}

func Test_nanoUnwrap(t *testing.T) {
	// 1. Set up the mock HTTP client
	mockClient := &http.Client{
		Transport: &mockRoundTripper{mockService: &MockKas{
			t: t,
			obligations: map[string][]string{
				"policy1": {"https://example.com/attr/attr1/value/val1"},
				"policy2": {"https://example.com/attr/attr2/value/val2"},
			},
		}},
	}

	// 2. Create the KAS client with the mocked HTTP client
	tokenSource := getTokenSource(t)
	c := newKASClient(mockClient, []connect.ClientOption{connect.WithProtoJSON()}, tokenSource, nil, nil)

	// 3. Define a dummy request.
	dummyKeyAccess := []*kaspb.UnsignedRewrapRequest_WithPolicyRequest{
		{
			Policy: &kaspb.UnsignedRewrapRequest_WithPolicy{
				Id: "policy1",
			},
			KeyAccessObjects: []*kaspb.UnsignedRewrapRequest_WithKeyAccessObject{
				{
					KeyAccessObject: &kaspb.KeyAccess{KasUrl: "https://kas.example.com"},
				},
			},
		},
		{
			Policy: &kaspb.UnsignedRewrapRequest_WithPolicy{
				Id: "policy2",
			},
			KeyAccessObjects: []*kaspb.UnsignedRewrapRequest_WithKeyAccessObject{
				{
					KeyAccessObject: &kaspb.KeyAccess{KasUrl: "https://kas.example.com"},
				},
			},
		},
	}

	// 4. Call nanoUnwrap
	policyResults, err := c.nanoUnwrap(t.Context(), dummyKeyAccess...)
	require.NoError(t, err)
	require.Len(t, policyResults, 2)

	// 5. Assertions
	result1, ok := policyResults["policy1"]
	require.True(t, ok)
	require.Equal(t, "policy1", result1.policyID)
	require.Len(t, result1.kaoRes, 1)
	require.Equal(t, []byte("supersecretkey1"), result1.kaoRes[0].SymmetricKey)
	require.NoError(t, result1.kaoRes[0].Error)
	require.Len(t, result1.obligations, 1)
	require.Equal(t, "https://example.com/attr/attr1/value/val1", result1.obligations[0])

	result2, ok := policyResults["policy2"]
	require.True(t, ok)
	require.Equal(t, "policy2", result2.policyID)
	require.Len(t, result2.kaoRes, 1)
	require.Equal(t, []byte("supersecretkey1"), result2.kaoRes[0].SymmetricKey)
	require.NoError(t, result2.kaoRes[0].Error)
	require.Len(t, result2.obligations, 1)
	require.Equal(t, "https://example.com/attr/attr2/value/val2", result2.obligations[0])
}

func createMetadataWithObligations(obligations map[string][]string) map[string]*structpb.Value {
	metadata := make(map[string]*structpb.Value)
	if len(obligations) == 0 {
		return metadata
	}

	fields := make(map[string]*structpb.Value)
	for policyID, fqns := range obligations {
		listValue := &structpb.ListValue{}
		for _, fqn := range fqns {
			listValue.Values = append(listValue.Values, structpb.NewStringValue(fqn))
		}
		fields[policyID] = structpb.NewListValue(listValue)
	}

	metadata[triggeredObligationsHeader] = &structpb.Value{
		Kind: &structpb.Value_StructValue{
			StructValue: &structpb.Struct{
				Fields: fields,
			},
		},
	}
	return metadata
}
