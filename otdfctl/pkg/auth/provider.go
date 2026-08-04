package auth

import (
	"context"

	"github.com/opentdf/platform/otdfctl/pkg/profiles"
	"github.com/opentdf/platform/sdk"
	"golang.org/x/oauth2"
)

// Provider builds SDK authentication for a single auth type (keyed by
// AuthCredentials.AuthType). Extending projects implement it and register it via
// RegisterProvider to add a custom authentication process.
type Provider interface {
	// SDKAuthOption returns the sdk.Option used to authenticate the SDK client.
	SDKAuthOption(profile *profiles.OtdfctlProfileStore) (sdk.Option, error)
	// Validate reports whether the profile's stored credentials are present and usable.
	Validate(ctx context.Context, profile *profiles.OtdfctlProfileStore) error
	// GetToken returns an OAuth2 token for the profile.
	GetToken(ctx context.Context, profile *profiles.OtdfctlProfileStore) (*oauth2.Token, error)
}

// authProviders maps an auth type to its provider. Registration is init-time and
// single-threaded, so no locking is required.
var authProviders = map[string]Provider{}

// RegisterProvider registers (or replaces) the provider for an auth type.
// Extending projects call this from init().
func RegisterProvider(authType string, provider Provider) {
	authProviders[authType] = provider
}

// lookupProvider returns the provider for authType, or ErrInvalidAuthType if none.
func lookupProvider(authType string) (Provider, error) {
	provider, ok := authProviders[authType]
	if !ok {
		return nil, ErrInvalidAuthType
	}
	return provider, nil
}

func init() {
	RegisterProvider(profiles.AuthTypeClientCredentials, clientCredentialsProvider{})
	RegisterProvider(profiles.AuthTypeAccessToken, accessTokenProvider{})
}

// clientCredentialsProvider implements the built-in OAuth2 client-credentials flow.
type clientCredentialsProvider struct{}

func (clientCredentialsProvider) SDKAuthOption(profile *profiles.OtdfctlProfileStore) (sdk.Option, error) {
	c := profile.GetAuthCredentials()
	return sdk.WithClientCredentials(c.ClientID, c.ClientSecret, NormalizeScopes(c.Scopes)), nil
}

func (clientCredentialsProvider) Validate(ctx context.Context, profile *profiles.OtdfctlProfileStore) error {
	c := profile.GetAuthCredentials()
	_, err := GetTokenWithClientCreds(ctx, profile.GetEndpoint(), c.ClientID, c.ClientSecret, profile.GetTLSNoVerify(), c.Scopes)
	return err
}

func (clientCredentialsProvider) GetToken(ctx context.Context, profile *profiles.OtdfctlProfileStore) (*oauth2.Token, error) {
	c := profile.GetAuthCredentials()
	return GetTokenWithClientCreds(ctx, profile.GetEndpoint(), c.ClientID, c.ClientSecret, profile.GetTLSNoVerify(), c.Scopes)
}

// accessTokenProvider implements the built-in static access-token flow.
type accessTokenProvider struct{}

func (accessTokenProvider) SDKAuthOption(profile *profiles.OtdfctlProfileStore) (sdk.Option, error) {
	c := profile.GetAuthCredentials()
	return sdk.WithOAuthAccessTokenSource(oauth2.StaticTokenSource(buildToken(&c))), nil
}

func (accessTokenProvider) Validate(_ context.Context, profile *profiles.OtdfctlProfileStore) error {
	c := profile.GetAuthCredentials()
	if !buildToken(&c).Valid() {
		return ErrAccessTokenExpired
	}
	return nil
}

func (accessTokenProvider) GetToken(_ context.Context, profile *profiles.OtdfctlProfileStore) (*oauth2.Token, error) {
	c := profile.GetAuthCredentials()
	return buildToken(&c), nil
}
