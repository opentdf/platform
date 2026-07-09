package auth

import (
	"context"
	"testing"
	"time"

	"github.com/opentdf/platform/otdfctl/pkg/profiles"
	"github.com/opentdf/platform/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

type fakeProvider struct {
	sdkCalled      bool
	validateCalled bool
	getTokenCalled bool
	token          *oauth2.Token
}

func (f *fakeProvider) SDKAuthOption(_ *profiles.OtdfctlProfileStore) (sdk.Option, error) {
	f.sdkCalled = true
	return sdk.WithInsecurePlaintextConn(), nil
}

func (f *fakeProvider) Validate(_ context.Context, _ *profiles.OtdfctlProfileStore) error {
	f.validateCalled = true
	return nil
}

func (f *fakeProvider) GetToken(_ context.Context, _ *profiles.OtdfctlProfileStore) (*oauth2.Token, error) {
	f.getTokenCalled = true
	return f.token, nil
}

func newProfileWithAuthCreds(t *testing.T, creds profiles.AuthCredentials) *profiles.OtdfctlProfileStore {
	t.Helper()
	store, err := profiles.NewOtdfctlProfileStore(profiles.ProfileDriverMemory, &profiles.ProfileConfig{
		Name:     "test",
		Endpoint: "http://localhost:8080",
	}, true)
	require.NoError(t, err)
	require.NoError(t, store.SetAuthCredentials(creds))
	return store
}

func TestRegisterProvider_Dispatch(t *testing.T) {
	const authType = "custom-dispatch-test"
	fake := &fakeProvider{token: &oauth2.Token{AccessToken: "tok"}}
	RegisterProvider(authType, fake)

	profile := newProfileWithAuthCreds(t, profiles.AuthCredentials{AuthType: authType})

	_, err := GetSDKAuthOptionFromProfile(profile)
	require.NoError(t, err)
	assert.True(t, fake.sdkCalled)

	require.NoError(t, ValidateProfileAuthCredentials(context.Background(), profile))
	assert.True(t, fake.validateCalled)

	tok, err := GetTokenWithProfile(context.Background(), profile)
	require.NoError(t, err)
	assert.True(t, fake.getTokenCalled)
	assert.Equal(t, "tok", tok.AccessToken)
}

func TestUnknownAuthType(t *testing.T) {
	profile := newProfileWithAuthCreds(t, profiles.AuthCredentials{AuthType: "not-registered"})

	_, err := GetSDKAuthOptionFromProfile(profile)
	require.ErrorIs(t, err, ErrInvalidAuthType)

	err = ValidateProfileAuthCredentials(context.Background(), profile)
	require.ErrorIs(t, err, ErrInvalidAuthType)

	_, err = GetTokenWithProfile(context.Background(), profile)
	require.ErrorIs(t, err, ErrInvalidAuthType)
}

func TestEmptyAuthType_Validate(t *testing.T) {
	profile := newProfileWithAuthCreds(t, profiles.AuthCredentials{AuthType: ""})

	err := ValidateProfileAuthCredentials(context.Background(), profile)
	require.ErrorIs(t, err, ErrProfileCredentialsNotFound)
}

func TestBuiltinAccessTokenValidation(t *testing.T) {
	valid := newProfileWithAuthCreds(t, profiles.AuthCredentials{
		AuthType: profiles.AuthTypeAccessToken,
		AccessToken: profiles.AuthCredentialsAccessToken{
			AccessToken: "abc",
			Expiration:  time.Now().Add(time.Hour).Unix(),
		},
	})
	require.NoError(t, ValidateProfileAuthCredentials(context.Background(), valid))

	expired := newProfileWithAuthCreds(t, profiles.AuthCredentials{
		AuthType: profiles.AuthTypeAccessToken,
		AccessToken: profiles.AuthCredentialsAccessToken{
			AccessToken: "abc",
			Expiration:  time.Now().Add(-time.Hour).Unix(),
		},
	})
	require.ErrorIs(t, ValidateProfileAuthCredentials(context.Background(), expired), ErrAccessTokenExpired)
}
