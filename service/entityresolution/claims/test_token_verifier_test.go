package claims_test

import (
	"context"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

type insecureTestTokenVerifier struct{}

func (insecureTestTokenVerifier) VerifyAccessToken(_ context.Context, tokenRaw string) (jwt.Token, error) {
	return jwt.ParseString(tokenRaw, jwt.WithVerify(false), jwt.WithValidate(false))
}
