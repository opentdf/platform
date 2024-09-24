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
	"github.com/opentdf/platform/sdk/auth"
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
	if err != nil {
		t.Fatalf("error creating RSA Key: %v", err)
	}

	client, err := newKASClient(dialOption, tokenSource, kasKey, nil)
	if err != nil {
		t.Fatalf("error setting KASClient: %v", err)
	}

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
	if err != nil {
		t.Fatalf("failed to create a rewrap request: %v", err)
	}

	if req.GetSignedRequestToken() == "" {
		t.Fatalf("didn't produce a signed request token")
	}

	pubKey, _ := tokenSource.dpopKey.PublicKey()

	tok, err := jwt.ParseString(req.GetSignedRequestToken(), jwt.WithKey(tokenSource.dpopKey.Algorithm(), pubKey))
	if err != nil {
		t.Fatalf("couldn't parse signed token: %v", err)
	}

	rb, ok := tok.Get("requestBody")
	if !ok {
		t.Fatalf("didn't contain a request body")
	}
	requestBodyJSON, _ := rb.(string)
	var requestBody map[string]interface{}

	err = json.Unmarshal([]byte(requestBodyJSON), &requestBody)
	if err != nil {
		t.Fatalf("error unmarshaling request body: %v", err)
	}

	_, err = ocrypto.NewAsymEncryption(requestBody["clientPublicKey"].(string))
	if err != nil {
		t.Fatalf("NewAsymEncryption failed, incorrect public key include: %v", err)
	}

	if requestBody["policy"] != "a policy" {
		t.Fatalf("incorrect policy")
	}

	requestKeyAccess, _ := requestBody["keyAccess"].(map[string]interface{})
	policyBinding, _ := requestKeyAccess["policyBinding"].(map[string]interface{})

	if requestKeyAccess["url"] != "https://kas.example.org" {
		t.Fatalf("incorrect kasURL")
	}
	if requestKeyAccess["protocol"] != "protocol one" {
		t.Fatalf("incorrect protocol")
	}
	if requestKeyAccess["url"] != "https://kas.example.org" {
		t.Fatalf("incorrect kasURL")
	}
	if requestKeyAccess["wrappedKey"] != "wrapped" {
		t.Fatalf("incorrect wrapped key")
	}
	if policyBinding["alg"] != "HS256" {
		t.Fatalf("incorrect policy binding")
	}
	if policyBinding["hash"] != "somehash" {
		t.Fatalf("incorrect policy binding")
	}
	if requestKeyAccess["encryptedMetadata"] != "encrypted" {
		t.Fatalf("incorrect encrypted metadata")
	}
}
