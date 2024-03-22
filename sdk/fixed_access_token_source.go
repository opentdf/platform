package sdk

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opentdf/platform/sdk/auth"
	"github.com/opentdf/platform/sdk/internal/crypto"
)

type FixedAccessTokenSource struct {
	token            string
	dpopKey          jwk.Key
	dpopPublicKeyPEM string
	asymDecryption   crypto.AsymDecryption
}

func NewFixedAccessTokenSource(tok string) (FixedAccessTokenSource, error) {
	pem, key, decryption, err := getNewDPoPKey()
	if err != nil {
		return FixedAccessTokenSource{}, fmt.Errorf("can't generate key")
	}

	ts := FixedAccessTokenSource{
		token:            tok,
		dpopKey:          key,
		dpopPublicKeyPEM: pem,
		asymDecryption:   *decryption,
	}

	return ts, nil
}

func (f FixedAccessTokenSource) AccessToken() (auth.AccessToken, error) {
	return auth.AccessToken(f.token), nil
}

// probably better to use `crypto.AsymDecryption` here than roll our own since this should be
// more closely linked to what happens in KAS in terms of crypto params
func (f FixedAccessTokenSource) DecryptWithDPoPKey(data []byte) ([]byte, error) {
	return f.asymDecryption.Decrypt(data)
}

func (f FixedAccessTokenSource) MakeToken(fn func(jwk.Key) ([]byte, error)) ([]byte, error) {
	return fn(f.dpopKey)
}

func (f FixedAccessTokenSource) DPoPPublicKeyPEM() string {
	return f.dpopPublicKeyPEM
}
