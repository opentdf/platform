package auth

import (
	"context"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type AccessToken string

type AccessTokenSource interface {
	AccessToken(ctx context.Context, client *http.Client) (AccessToken, error)
	// MakeToken probably better to use `crypto.AsymDecryption` here than roll our own since this should be
	// more closely linked to what happens in KAS in terms of crypto params
	MakeToken(func(jwk.Key) ([]byte, error)) ([]byte, error)
}

// AccessTokenCredential binds an access token to its DPoP status.
type AccessTokenCredential struct {
	Token         AccessToken
	DPoPSupported bool
}

// AccessTokenCredentialSource is implemented by token sources that can return
// an access token and its DPoP status atomically.
//
// Token sources without this optional interface retain the SDK's existing DPoP
// behavior for backwards compatibility.
type AccessTokenCredentialSource interface {
	AccessTokenCredential(ctx context.Context, client *http.Client) (AccessTokenCredential, error)
}
