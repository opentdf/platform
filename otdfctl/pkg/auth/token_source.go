package auth

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/opentdf/platform/otdfctl/pkg/profiles"
	"github.com/opentdf/platform/otdfctl/pkg/utils"
	"golang.org/x/oauth2"
)

// profileTokenSource is an oauth2.TokenSource that transparently refreshes
// expired access tokens via the stored refresh token and persists the rotated
// credentials back to the profile. It is safe for concurrent use.
type profileTokenSource struct {
	profile *profiles.OtdfctlProfileStore
	resolve tokenEndpointResolver

	mu           sync.Mutex
	inner        oauth2.TokenSource
	cachedAccess string
}

func newProfileTokenSource(profile *profiles.OtdfctlProfileStore) *profileTokenSource {
	return &profileTokenSource{
		profile: profile,
		resolve: getTokenEndpoint,
	}
}

// Token returns a valid access token, refreshing via the stored refresh token
// when needed and persisting rotated credentials to the profile.
func (p *profileTokenSource) Token() (*oauth2.Token, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	creds := p.profile.GetAuthCredentials()
	if creds.AuthType != profiles.AuthTypeAccessToken {
		return nil, ErrInvalidAuthType
	}

	if p.inner == nil {
		if err := p.rebuild(creds); err != nil {
			return nil, err
		}
	}

	tok, err := p.inner.Token()
	if err != nil {
		if isInvalidGrant(err) {
			_ = p.profile.SetAuthCredentials(profiles.AuthCredentials{})
			p.inner = nil
			return nil, errors.Join(ErrRefreshTokenInvalid, err)
		}
		slog.Warn("token source refresh failed", slog.Any("error", err))
		return nil, err
	}

	if tok.AccessToken != p.cachedAccess {
		p.persist(creds, tok)
		p.cachedAccess = tok.AccessToken
	}
	return tok, nil
}

// Invalidate drops the cached inner source so the next Token() call rebuilds
// from the current profile creds and forces a refresh. Used by callers that
// know the server has rejected the current access token (e.g. a 401 retry).
func (p *profileTokenSource) Invalidate() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.inner = nil
}

// rebuild constructs the inner oauth2.TokenSource from the profile's creds.
// Caller must hold p.mu.
func (p *profileTokenSource) rebuild(creds profiles.AuthCredentials) error {
	endpoint := p.profile.GetEndpoint()
	tlsNoVerify := p.profile.GetTLSNoVerify()

	normalized, err := utils.NormalizeEndpoint(endpoint)
	if err != nil {
		return err
	}
	tokenEndpoint, err := p.resolve(normalized.String(), tlsNoVerify)
	if err != nil {
		return err
	}

	clientID := creds.AccessToken.ClientID
	if clientID == "" {
		clientID = DefaultPublicClientID
	}

	cfg := &oauth2.Config{
		ClientID: clientID,
		Endpoint: oauth2.Endpoint{TokenURL: tokenEndpoint},
	}

	ctx := context.Background()
	if tlsNoVerify {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, utils.NewHTTPClient(tlsNoVerify))
	}

	oldToken := buildToken(&creds)
	p.inner = cfg.TokenSource(ctx, oldToken)
	p.cachedAccess = oldToken.AccessToken
	return nil
}

// persist writes the rotated token back to the profile. Some IdPs omit
// refresh_token on refresh (RFC-compliant no-rotation); keep the old one in
// that case. A write-back failure is logged but not returned — the fresh
// token is still valid for the in-flight call.
func (p *profileTokenSource) persist(oldCreds profiles.AuthCredentials, tok *oauth2.Token) {
	refresh := tok.RefreshToken
	if refresh == "" {
		refresh = oldCreds.AccessToken.RefreshToken
	}
	expiry := tok.Expiry.Unix()
	if tok.Expiry.IsZero() {
		expiry = time.Now().Add(time.Hour).Unix()
		slog.Warn("token response missing expires_in, assuming 1 hour")
	}

	clientID := oldCreds.AccessToken.ClientID
	if clientID == "" {
		clientID = DefaultPublicClientID
	}

	newCreds := profiles.AuthCredentials{
		AuthType: profiles.AuthTypeAccessToken,
		AccessToken: profiles.AuthCredentialsAccessToken{
			ClientID:     clientID,
			AccessToken:  tok.AccessToken,
			RefreshToken: refresh,
			Expiration:   expiry,
		},
	}
	if err := p.profile.SetAuthCredentials(newCreds); err != nil {
		slog.Warn("failed to persist refreshed credentials", slog.Any("error", err))
		return
	}
	slog.Info("access token refreshed", slog.String("profile", p.profile.Name()))
}
