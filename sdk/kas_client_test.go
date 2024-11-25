package sdk

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/sdk/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

type FakeAccessTokenSource struct {
	dpopKey        jwk.Key
	asymDecryption ocrypto.AsymDecryption
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
		accessToken:    "thisistheaccesstoken",
	}
}

func TestCreatingRequest(t *testing.T) {
	var dialOption []grpc.DialOption
	tokenSource := getTokenSource(t)
	kasKey, err := ocrypto.NewRSAKeyPair(tdf3KeySize)
	require.NoError(t, err, "error creating RSA Key")

	client := newKASClient(dialOption, tokenSource, &kasKey)

	keyAccess := KeyAccess{
		KeyType:    "type1",
		KasURL:     "https://kas.example.org",
		Protocol:   "protocol one",
		WrappedKey: "wrapped",
		PolicyBinding: PolicyBinding{
			Alg:  "HS256",
			Hash: "somehash",
		},
		EncryptedMetadata: "encrypted",
	}

	req, err := client.getRewrapRequest(keyAccess, "a policy")
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
	var requestBody map[string]interface{}

	require.NoError(t, json.Unmarshal([]byte(requestBodyJSON), &requestBody), "error unmarshaling request body")

	cpk, ok := requestBody["clientPublicKey"].(string)
	require.True(t, ok)

	_, err = ocrypto.NewAsymEncryption(cpk)
	require.NoError(t, err, "NewAsymEncryption failed, incorrect public key include")

	assert.Equal(t, "a policy", requestBody["policy"])

	requestKeyAccess, ok := requestBody["keyAccess"].(map[string]interface{})
	require.True(t, ok)
	policyBinding, ok := requestKeyAccess["policyBinding"].(map[string]interface{})
	require.True(t, ok)

	assert.Equal(t, "https://kas.example.org", requestKeyAccess["url"], "incorrect kasURL")
	assert.Equal(t, "protocol one", requestKeyAccess["protocol"], "incorrect protocol")
	assert.Equal(t, "wrapped", requestKeyAccess["wrappedKey"], "incorrect wrapped key")
	assert.Equal(t, "HS256", policyBinding["alg"], "incorrect policy binding")
	assert.Equal(t, "somehash", policyBinding["hash"], "incorrect policy binding")
	assert.Equal(t, "encrypted", requestKeyAccess["encryptedMetadata"], "incorrect encrypted metadata")
}

func Test_StoreKASKeys(t *testing.T) {
	s, err := New("localhost:8080",
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

	k1, err := s.getPublicKey(context.Background(), "https://localhost:8080", "ec:secp256r1")
	require.NoError(t, err)
	assert.Equal(t, &KASInfo{
		URL:       "https://localhost:8080",
		PublicKey: "sample",
		KID:       "e1",
		Algorithm: "ec:secp256r1",
		Default:   false,
	}, k1)

	s.kasKeyCache = nil
	k2, err := s.getPublicKey(context.Background(), "https://localhost:54321", "ec:secp256r1")
	assert.Nil(t, k2)
	require.ErrorContains(t, err, "error making request")
}
