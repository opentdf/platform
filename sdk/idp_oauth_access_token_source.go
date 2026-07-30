package sdk

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/sdk/auth"
	"golang.org/x/oauth2"
)

// OAuthAccessTokenSource allows connecting to an IDP and obtaining an access token.
type OAuthAccessTokenSource struct {
	source         oauth2.TokenSource
	scopes         []string
	dpopKey        jwk.Key
	asymDecryption ocrypto.AsymDecryption
	dpopPEM        string
}

func NewOAuthAccessTokenSource(
	source oauth2.TokenSource, scopes []string, key *ocrypto.RsaKeyPair,
) (*OAuthAccessTokenSource, error) {
	dpopPublicKeyPEM, dpopKey, asymDecryption, err := getNewDPoPKey(key)
	if err != nil {
		return nil, err
	}

	tokenSource := OAuthAccessTokenSource{
		source:         source,
		scopes:         scopes,
		asymDecryption: *asymDecryption,
		dpopKey:        dpopKey,
		dpopPEM:        dpopPublicKeyPEM,
	}

	return &tokenSource, nil
}

// AccessToken use a pointer receiver so that the token state is shared
func (t *OAuthAccessTokenSource) AccessToken(ctx context.Context, client *http.Client) (auth.AccessToken, error) {
	credential, err := t.AccessTokenCredential(ctx, client)
	return credential.Token, err
}

// AccessTokenCredential returns an access token and its DPoP status from the same token response.
func (t *OAuthAccessTokenSource) AccessTokenCredential(_ context.Context, _ *http.Client) (auth.AccessTokenCredential, error) {
	tok, err := t.source.Token()
	if err != nil {
		return auth.AccessTokenCredential{}, fmt.Errorf("error getting access token: %w", err)
	}

	// Non-nil with AccessToken and not Expired
	if !tok.Valid() {
		return auth.AccessTokenCredential{}, ErrAccessTokenInvalid
		// TODO: refresh tokens if expired?
	}

	return auth.AccessTokenCredential{
		Token:         auth.AccessToken(tok.AccessToken),
		DPoPSupported: strings.EqualFold(tok.Type(), "DPoP"),
	}, nil
}

func (t *OAuthAccessTokenSource) MakeToken(tokenMaker func(jwk.Key) ([]byte, error)) ([]byte, error) {
	return tokenMaker(t.dpopKey)
}
