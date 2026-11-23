package sdk

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// jwxGetter is implemented by jwx v3 tokens, JWS headers and JWKs.
type jwxGetter interface {
	Get(name string, dst any) error
}

// jwtField returns the named claim or header field as stored by jwx, and
// whether it is present.
func jwtField(g jwxGetter, name string) (any, bool) {
	var v any
	if err := g.Get(name, &v); err != nil {
		return nil, false
	}
	return v, true
}

// exportJWK returns the raw key held by k as a T, such as *ecdsa.PrivateKey.
func exportJWK[T any](k jwk.Key) (T, error) {
	var zero T
	var raw any
	if err := jwk.Export(k, &raw); err != nil {
		return zero, err
	}
	typed, ok := raw.(T)
	if !ok {
		return zero, fmt.Errorf("jwk: raw key is %T, not %T", raw, zero)
	}
	return typed, nil
}
