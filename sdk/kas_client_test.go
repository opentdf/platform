package sdk

import (
	"context"
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

	client := newKASClient(nil, options, tokenSource, &kasKey)
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

	// Store a key with no KID
	keyInfo := KASInfo{
		URL:       testURL,
		Algorithm: testAlgorithm,
		KID:       "", // Empty KID
		PublicKey: testPubKey,
	}
	cache.store(keyInfo)

	// Test 1: Check if we can retrieve the key when querying with an empty KID
	retrievedKey := cache.get(testURL, testAlgorithm, "")
	require.NotNil(t, retrievedKey, "Failed to retrieve key with empty KID")
	assert.Equal(t, testPubKey, retrievedKey.PublicKey, "Retrieved key has incorrect public key")
	assert.Empty(t, "", retrievedKey.KID, "Retrieved key should have empty KID")
	assert.Equal(t, testAlgorithm, retrievedKey.Algorithm, "Retrieved key has incorrect algorithm")
	assert.Equal(t, testURL, retrievedKey.URL, "Retrieved key has incorrect URL")

	// Test 2: Check that querying with a specific KID does not return the key with empty KID
	retrievedKey = cache.get(testURL, testAlgorithm, "specific-kid")
	assert.Nil(t, retrievedKey, "Should not retrieve a key when querying with a specific KID")

	// Test 3: Store a key with the same URL and algorithm but with a specific KID
	keyInfoWithKID := KASInfo{
		URL:       testURL,
		Algorithm: testAlgorithm,
		KID:       "specific-kid",
		PublicKey: "another-public-key",
	}
	cache.store(keyInfoWithKID)

	// Verify both keys can be retrieved with their respective KIDs
	emptyKIDKey := cache.get(testURL, testAlgorithm, "")
	specificKIDKey := cache.get(testURL, testAlgorithm, "specific-kid")

	require.NotNil(t, emptyKIDKey, "Failed to retrieve key with empty KID after storing a key with specific KID")
	require.NotNil(t, specificKIDKey, "Failed to retrieve key with specific KID")

	assert.Equal(t, testPubKey, emptyKIDKey.PublicKey, "Retrieved key with empty KID has incorrect public key")
	assert.Equal(t, "another-public-key", specificKIDKey.PublicKey, "Retrieved key with specific KID has incorrect public key")
}

func TestKasKeyCache_Expiration(t *testing.T) {
	// Create a new KAS key cache
	cache := newKasKeyCache()
	require.NotNil(t, cache, "Failed to create KAS key cache")

	// Store a key
	keyInfo := KASInfo{
		URL:       "https://kas.example.org",
		Algorithm: "ec:secp256r1",
		KID:       "",
		PublicKey: "test-public-key",
	}
	cache.store(keyInfo)

	// Verify key is in cache
	retrievedKey := cache.get("https://kas.example.org", "ec:secp256r1", "")
	require.NotNil(t, retrievedKey, "Key should be in cache")

	// Manually modify the time to simulate expiration (beyond 5 minutes)
	cacheKey := kasKeyRequest{"https://kas.example.org", "ec:secp256r1", ""}
	cachedValue := cache.c[cacheKey]
	cachedValue.Time = time.Now().Add(-6 * time.Minute)
	cache.c[cacheKey] = cachedValue

	// Try to retrieve the expired key
	retrievedKey = cache.get("https://kas.example.org", "ec:secp256r1", "")
	assert.Nil(t, retrievedKey, "Expired key should not be returned")

	// Verify the entry was actually removed from the cache
	_, exists := cache.c[cacheKey]
	assert.False(t, exists, "Expired key should be removed from cache")
}
