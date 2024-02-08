package sdk

import (
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opentdf/opentdf-v2-poc/internal/crypto"
)

func getCredentials() AccessTokenCredentials {
	dpopKey, _ := crypto.NewRSAKeyPair(2048)
	dpopPEM, _ := dpopKey.PrivateKeyInPemFormat()
	decryption, _ := crypto.NewAsymDecryption(dpopPEM)
	dpopJWK, err := jwk.ParseKey([]byte(dpopPEM), jwk.WithPEM(true))
	if err != nil {
		panic(err.Error())
	}
	dpopJWK.Set("alg", jwa.RS256.String())

	return AccessTokenCredentials{
		DPoPKey:        dpopJWK,
		AsymDecryption: decryption,
		AccessToken:    "thisistheaccesstoken",
	}
}

func TestCreatingRequest(t *testing.T) {
	client := KasClient{creds: getCredentials()}
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

}
