package auth

import (
	"github.com/lestrrat-go/jwx/v2/jwk"
	"golang.org/x/oauth2"
	"net/http"
)

type AccessToken string

type AccessTokenSource interface {
	TokenSource
	AccessToken(client *http.Client) (AccessToken, error)
	// MakeToken probably better to use `crypto.AsymDecryption` here than roll our own since this should be
	// more closely linked to what happens in KAS in terms of crypto params
	MakeToken(func(jwk.Key) ([]byte, error)) ([]byte, error)
}

// TokenSource matches golang.org/x/oauth2.TokenSource
type TokenSource interface {
	// Token returns a token or an error.
	// Token must be safe for concurrent use by multiple goroutines.
	// The returned Token must not be modified.
	Token() (*oauth2.Token, error)
}
