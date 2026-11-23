// Package jwtclaims reads untyped claims and header fields from jwx v3
// tokens, headers and keys.
package jwtclaims

import "github.com/lestrrat-go/jwx/v3/jwt"

// Getter is implemented by jwx v3 tokens, JWS headers and JWKs.
type Getter interface {
	Get(name string, dst any) error
}

// Field returns the named field as stored by jwx, and whether it is present.
func Field(g Getter, name string) (any, bool) {
	var v any
	if err := g.Get(name, &v); err != nil {
		return nil, false
	}
	return v, true
}

// Map returns every claim in tok, keyed by claim name.
func Map(tok jwt.Token) map[string]any {
	keys := tok.Keys()
	claims := make(map[string]any, len(keys))
	for _, k := range keys {
		if v, ok := Field(tok, k); ok {
			claims[k] = v
		}
	}
	return claims
}
