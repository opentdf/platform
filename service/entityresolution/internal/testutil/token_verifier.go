package testutil

import (
	"context"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

// This helper is shared across multiple test packages, so it cannot live in a
// _test.go file and still be imported by those packages.
type InsecureTokenVerifier struct{}

func NewInsecureTokenVerifier() InsecureTokenVerifier {
	return InsecureTokenVerifier{}
}

func (InsecureTokenVerifier) VerifyAccessToken(_ context.Context, tokenRaw string) (jwt.Token, error) {
	return jwt.ParseString(tokenRaw, jwt.WithVerify(false), jwt.WithValidate(false))
}
