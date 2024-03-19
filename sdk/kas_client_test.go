package sdk

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/sdk/auth"
	"github.com/opentdf/platform/sdk/internal/crypto"
)

type FakeAccessTokenSource struct {
	dpopKey        jwk.Key
	asymDecryption crypto.AsymDecryption
	accessToken    string
}

func (fake FakeAccessTokenSource) AccessToken() (auth.AccessToken, error) {
	return auth.AccessToken(fake.accessToken), nil
}
func (fake FakeAccessTokenSource) DecryptWithDPoPKey(encrypted []byte) ([]byte, error) {
	return fake.asymDecryption.Decrypt(encrypted)
}
func (fake FakeAccessTokenSource) MakeToken(tokenMaker func(jwk.Key) ([]byte, error)) ([]byte, error) {
	return tokenMaker(fake.dpopKey)
}
func (fake FakeAccessTokenSource) DPoPPublicKeyPEM() string {
	return "this is the PEM"
}
func (fake FakeAccessTokenSource) RefreshAccessToken() error {
	return errors.New("can't refresh this one")
}

func getTokenSource(t *testing.T) FakeAccessTokenSource {
	dpopKey, _ := crypto.NewRSAKeyPair(2048)
	dpopPEM, _ := dpopKey.PrivateKeyInPemFormat()
	decryption, _ := crypto.NewAsymDecryption(dpopPEM)
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
	tokenSource := getTokenSource(t)
	client := KASClient{accessTokenSource: tokenSource}
	keyAccess := KeyAccess{
		KeyType:           "type1",
		KasURL:            "https://kas.example.org",
		Protocol:          "protocol one",
		WrappedKey:        "wrapped",
		PolicyBinding:     "bound",
		EncryptedMetadata: "encrypted",
	}

	req, err := client.getRewrapRequest(keyAccess, "a policy")
	if err != nil {
		t.Fatalf("failed to create a rewrap request: %v", err)
	}

	if req.SignedRequestToken == "" {
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

	if requestBody["clientPublicKey"] != "this is the PEM" {
		t.Fatalf("incorrect public key included")
	}
	if requestBody["policy"] != "a policy" {
		t.Fatalf("incorrect policy")
	}

	requestKeyAccess, _ := requestBody["keyAccess"].(map[string]interface{})

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
	if requestKeyAccess["policyBinding"] != "bound" {
		t.Fatalf("incorrect policy binding")
	}
	if requestKeyAccess["encryptedMetadata"] != "encrypted" {
		t.Fatalf("incorrect encrypted metadata")
	}
}
