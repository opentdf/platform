package sdk

import (
	"context"
	"net/http"
	"testing"

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
				"public_client_id":       "myclient",
			},
		}),
	)
	require.NoError(t, err)

	assert.Nil(t, s.kasKeyCache.get("https://localhost:8080", "ec:secp256r1"))
	assert.Nil(t, s.kasKeyCache.get("https://localhost:8080", "rsa:2048"))

	require.NoError(t, s.StoreKASKeys("https://localhost:8080", &policy.KasPublicKeySet{
		Keys: []*policy.KasPublicKey{
			{Pem: "sample", Kid: "e1", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1},
			{Pem: "sample", Kid: "r1", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048},
		},
	}))
	assert.Nil(t, s.kasKeyCache.get("https://nowhere", "alg:unknown"))
	assert.Nil(t, s.kasKeyCache.get("https://localhost:8080", "alg:unknown"))
	assert.Equal(t, "e1", s.kasKeyCache.get("https://localhost:8080", "ec:secp256r1").KID)
	assert.Equal(t, "r1", s.kasKeyCache.get("https://localhost:8080", "rsa:2048").KID)

	k1, err := s.getPublicKey(t.Context(), "https://localhost:8080", "ec:secp256r1")
	require.NoError(t, err)
	assert.Equal(t, &KASInfo{
		URL:       "https://localhost:8080",
		PublicKey: "sample",
		KID:       "e1",
		Algorithm: "ec:secp256r1",
		Default:   false,
	}, k1)

	s.kasKeyCache = nil
	k2, err := s.getPublicKey(t.Context(), "https://localhost:54321", "ec:secp256r1")
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
