package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type AccessToken string

type TokenType string

const (
	TokenTypeBearer TokenType = "Bearer"
	TokenTypeDPoP   TokenType = "DPoP"
)

// TokenTypeFromOAuthTokenType returns the authentication scheme required for
// an OAuth access token. A DPoP token type requires a DPoP proof; all other
// values use the Bearer scheme.
func TokenTypeFromOAuthTokenType(tokenType string) TokenType {
	if strings.EqualFold(tokenType, string(TokenTypeDPoP)) {
		return TokenTypeDPoP
	}

	return TokenTypeBearer
}

type AccessTokenSource interface {
	AccessToken(ctx context.Context, client *http.Client) (AccessToken, error)
	// MakeToken probably better to use `crypto.AsymDecryption` here than roll our own since this should be
	// more closely linked to what happens in KAS in terms of crypto params
	MakeToken(func(jwk.Key) ([]byte, error)) ([]byte, error)
}

// AccessTokenCredential binds an access token to its authentication scheme.
type AccessTokenCredential struct {
	Token AccessToken
	Type  TokenType
}

// AccessTokenCredentialSource is implemented by token sources that can return
// an access token and its authentication scheme atomically.
//
// Token sources without this optional interface retain the SDK's existing DPoP
// behavior for backwards compatibility.
type AccessTokenCredentialSource interface {
	AccessTokenCredential(ctx context.Context, client *http.Client) (AccessTokenCredential, error)
}
