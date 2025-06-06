package oidc

import (
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func parseKey(privateKeyPEM []byte) (jwk.Key, error) {
	key, err := jwk.ParseKey(privateKeyPEM)
	if err == nil {
		return key, nil
	}
	return jwk.ParseKey(privateKeyPEM, jwk.WithPEM(true))
}
