package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/opentdf/platform/otdfctl/pkg/profiles"
	"github.com/opentdf/platform/otdfctl/pkg/utils"
	"golang.org/x/oauth2"
)

const (
	DefaultPublicClientID = "cli-client"
	// expiryBuffer is added to the current time to account for token expiry occurring during
	// subprocess startup and network latency between the expiry check and the actual API call.
	expiryBuffer = 30 * time.Second
)

// Function variable for the token endpoint lookup — swappable in tests.
var getTokenEndpointFunc = getTokenEndpoint

// RefreshAccessToken refreshes the access token using the stored refresh token
// and updates the profile with the new tokens.
func RefreshAccessToken(ctx context.Context, profile *profiles.OtdfctlProfileStore) error {
	if profile == nil {
		return errors.New("profile is required")
	}

	creds := profile.GetAuthCredentials()

	if creds.AuthType != profiles.AuthTypeAccessToken {
		return fmt.Errorf("%w: auth type is %s, not access-token", ErrInvalidAuthType, creds.AuthType)
	}

	if creds.AccessToken.RefreshToken == "" {
		return ErrNoRefreshToken
	}

	endpoint := profile.GetEndpoint()
	tlsNoVerify := profile.GetTLSNoVerify()

	normalized, err := utils.NormalizeEndpoint(endpoint)
	if err != nil {
		return fmt.Errorf("failed to normalize endpoint: %w", err)
	}

	tokenEndpoint, err := getTokenEndpointFunc(normalized.String(), tlsNoVerify)
	if err != nil {
		return fmt.Errorf("failed to get token endpoint: %w", err)
	}

	clientID := creds.AccessToken.ClientID
	if clientID == "" {
		clientID = DefaultPublicClientID
	}

	oauth2Config := &oauth2.Config{
		ClientID: clientID,
		Endpoint: oauth2.Endpoint{
			TokenURL: tokenEndpoint,
		},
	}

	oldToken := &oauth2.Token{
		RefreshToken: creds.AccessToken.RefreshToken,
	}

	if tlsNoVerify {
		httpClient := utils.NewHTTPClient(tlsNoVerify)
		ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	}

	tokenSource := oauth2Config.TokenSource(ctx, oldToken)
	newToken, err := tokenSource.Token()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRefreshFailed, err)
	}

	slog.Debug("successfully refreshed access token")

	expiration := newToken.Expiry.Unix()
	if newToken.Expiry.IsZero() {
		expiration = time.Now().Add(time.Hour).Unix()
		slog.Warn("token response missing expires_in, assuming 1 hour")
	}

	newCreds := profiles.AuthCredentials{
		AuthType: profiles.AuthTypeAccessToken,
		AccessToken: profiles.AuthCredentialsAccessToken{
			ClientID:     clientID,
			AccessToken:  newToken.AccessToken,
			RefreshToken: newToken.RefreshToken,
			Expiration:   expiration,
		},
	}

	if err := profile.SetAuthCredentials(newCreds); err != nil {
		return fmt.Errorf("failed to save refreshed credentials: %w", err)
	}

	slog.Info("access token refreshed and saved")
	return nil
}

// IsTokenExpired checks if the access token in the profile is expired.
// Returns false for non-access-token auth types since refresh only applies there.
func IsTokenExpired(profile *profiles.OtdfctlProfileStore) bool {
	if profile == nil {
		return true
	}
	creds := profile.GetAuthCredentials()
	if creds.AuthType != profiles.AuthTypeAccessToken {
		return false
	}
	expiry := time.Unix(creds.AccessToken.Expiration, 0)
	// We are checking if the current time plus the buffer is after the true token expiry time.
	// If it is, we refresh the token. The purpose of the buffer is to avoid expiry between calls.
	return time.Now().Add(expiryBuffer).After(expiry)
}

// HasRefreshToken checks if the profile has a refresh token.
func HasRefreshToken(profile *profiles.OtdfctlProfileStore) bool {
	if profile == nil {
		return false
	}
	creds := profile.GetAuthCredentials()
	return creds.AuthType == profiles.AuthTypeAccessToken && creds.AccessToken.RefreshToken != ""
}

func getTokenEndpoint(endpoint string, tlsNoVerify bool) (string, error) {
	pc, err := getPlatformConfiguration(endpoint, tlsNoVerify)
	if err != nil {
		return "", fmt.Errorf("failed to get platform configuration: %w", err)
	}
	return pc.tokenEndpoint, nil
}
