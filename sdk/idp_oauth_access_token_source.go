package sdk

import (
	"context"
	"fmt"
	"net/http"

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
		source:         cachingTokenSource(source),
		scopes:         scopes,
		asymDecryption: *asymDecryption,
		dpopKey:        dpopKey,
		dpopPEM:        dpopPublicKeyPEM,
	}

	return &tokenSource, nil
}

// cachingTokenSource wraps a token source so that a valid token is reused across
// calls instead of being re-fetched. AccessToken is on the request hot path
// (once per gRPC/Connect call, plus once more to compute the DPoP ath claim), so
// an uncached source would risk an IdP round-trip on every request. Wrapping an
// already-caching source is harmless.
func cachingTokenSource(source oauth2.TokenSource) oauth2.TokenSource {
	return oauth2.ReuseTokenSource(nil, source)
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
		Token: auth.AccessToken(tok.AccessToken),
		Type:  auth.TokenTypeFromOAuthTokenType(tok.Type()),
	}, nil
}

func (t *OAuthAccessTokenSource) MakeToken(tokenMaker func(jwk.Key) ([]byte, error)) ([]byte, error) {
	return tokenMaker(t.dpopKey)
}

// newOAuthAccessTokenSourceFromJWK creates an OAuthAccessTokenSource using a pre-built JWK key.
func newOAuthAccessTokenSourceFromJWK(source oauth2.TokenSource, scopes []string, key jwk.Key) *OAuthAccessTokenSource {
	return &OAuthAccessTokenSource{
		source:  cachingTokenSource(source),
		scopes:  scopes,
		dpopKey: key,
	}
}
