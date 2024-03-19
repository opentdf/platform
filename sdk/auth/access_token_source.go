package auth

import "github.com/lestrrat-go/jwx/v2/jwk"

type AccessToken string

type AccessTokenSource interface {
	AccessToken() (AccessToken, error)
	// probably better to use `crypto.AsymDecryption` here than roll our own since this should be
	// more closely linked to what happens in KAS in terms of crypto params
	DecryptWithDPoPKey(data []byte) ([]byte, error)
	MakeToken(func(jwk.Key) ([]byte, error)) ([]byte, error)
	DPoPPublicKeyPEM() string
	RefreshAccessToken() error
}
