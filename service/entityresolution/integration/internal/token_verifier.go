package internal

import (
	"context"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

type insecureTokenVerifier struct{}

func (insecureTokenVerifier) VerifyAccessToken(_ context.Context, tokenRaw string) (jwt.Token, error) {
	return jwt.ParseString(tokenRaw, jwt.WithVerify(false), jwt.WithValidate(false))
}

func NewInsecureTokenVerifier() insecureTokenVerifier {
	return insecureTokenVerifier{}
}
