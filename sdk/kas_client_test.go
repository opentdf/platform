package sdk

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/opentdf/opentdf-v2-poc/internal/crypto"
)

type FakeUnwrapper struct {
	decrypt      crypto.AsymDecryption
	publicKeyPEM string
}

func NewFakeUnwrapper(kasPrivateKey string) (FakeUnwrapper, error) {
	kasPrivateKey = strings.ReplaceAll(kasPrivateKey, "\n\t", "\n")
	block, _ := pem.Decode([]byte(kasPrivateKey))
	if block == nil {
		return FakeUnwrapper{}, errors.New("failed to parse PEM formatted private key")
	}

	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return FakeUnwrapper{}, fmt.Errorf("could not create fake unwrapper:%v", err)
	}
	publicKey := privKey.(*rsa.PrivateKey).PublicKey
	pkBytes, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return FakeUnwrapper{}, fmt.Errorf("can't marshal public key: %v", err)
	}
	privateBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkBytes,
	}
	publicKeyPEM := new(strings.Builder)
	pem.Encode(publicKeyPEM, &privateBlock)
	asymDecrypt, err := crypto.NewAsymDecryption(kasPrivateKey)
	if err != nil {
		return FakeUnwrapper{}, err
	}

	return FakeUnwrapper{decrypt: asymDecrypt, publicKeyPEM: publicKeyPEM.String()}, nil
}

func (fake FakeUnwrapper) Unwrap(keyAccess KeyAccess, policy string) ([]byte, error) {
	wrappedKey, err := crypto.Base64Decode([]byte(keyAccess.WrappedKey))
	if err != nil {
		return nil, err
	}
	return fake.decrypt.Decrypt(wrappedKey)
}

func (fake FakeUnwrapper) GetKASPublicKey(kasInfo KASInfo) (string, error) {
	return fake.publicKeyPEM, nil
}

// func getCredentials() AccessTokenCredentials {
// 	dpopKey, _ := crypto.NewRSAKeyPair(2048)
// 	dpopPEM, _ := dpopKey.PrivateKeyInPemFormat()
// 	decryption, _ := crypto.NewAsymDecryption(dpopPEM)
// 	dpopJWK, err := jwk.ParseKey([]byte(dpopPEM), jwk.WithPEM(true))
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	dpopJWK.Set("alg", jwa.RS256.String())

// 	return AccessTokenCredentials{
// 		DPoPKey:        dpopJWK,
// 		AsymDecryption: decryption,
// 		AccessToken:    "thisistheaccesstoken",
// 	}
// }

// func TestCreatingRequest(t *testing.T) {
// 	client := KasClient{creds: getCredentials()}
// 	keyAccess := KeyAccess{
// 		KeyType:           "type1",
// 		KasURL:            "https://kas.example.org",
// 		Protocol:          "protocol one",
// 		WrappedKey:        "wrapped",
// 		PolicyBinding:     "bound",
// 		EncryptedMetadata: "encrypted",
// 	}

// 	req, err := client.getRewrapRequest(keyAccess, "a policy")
// 	if err != nil {
// 		t.Fatalf("failed to create a rewrap request: %v", err)
// 	}

// 	if req.SignedRequestToken == "" {
// 		t.Fatalf("didn't produce a signed request token")
// 	}

// }
