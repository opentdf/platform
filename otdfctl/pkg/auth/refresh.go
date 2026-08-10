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

// tokenEndpointResolver looks up the OAuth2 token endpoint for a given
// platform endpoint. Production code uses getTokenEndpoint; tests inject
// a stub to avoid real gRPC calls.
type tokenEndpointResolver func(endpoint string, tlsNoVerify bool) (string, error)

// RefreshAccessToken refreshes the access token using the stored refresh token
// and updates the profile with the new tokens.
func RefreshAccessToken(ctx context.Context, profile *profiles.OtdfctlProfileStore) error {
	return refreshAccessToken(ctx, profile, getTokenEndpoint)
}

func refreshAccessToken(ctx context.Context, profile *profiles.OtdfctlProfileStore, resolveEndpoint tokenEndpointResolver) error {
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

	tokenEndpoint, err := resolveEndpoint(normalized.String(), tlsNoVerify)
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
		if isInvalidGrant(err) {
			// Refresh token is dead server-side; wipe stored creds so the next
			// command hits the login prompt cleanly.
			_ = profile.SetAuthCredentials(profiles.AuthCredentials{})
			return errors.Join(ErrRefreshTokenInvalid, err)
		}
		return fmt.Errorf("%w: %w", ErrRefreshFailed, err)
	}

	slog.Debug("successfully refreshed access token")

	expiration := newToken.Expiry.Unix()
	if newToken.Expiry.IsZero() {
		expiration = time.Now().Add(time.Hour).Unix()
		slog.Warn("token response missing expires_in, assuming 1 hour")
	}

	// Some IdPs omit refresh_token on refresh (no-rotation); keep the old one.
	refreshToken := newToken.RefreshToken
	if refreshToken == "" {
		refreshToken = creds.AccessToken.RefreshToken
	}

	newCreds := profiles.AuthCredentials{
		AuthType: profiles.AuthTypeAccessToken,
		AccessToken: profiles.AuthCredentialsAccessToken{
			ClientID:     clientID,
			AccessToken:  newToken.AccessToken,
			RefreshToken: refreshToken,
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

// isInvalidGrant reports whether err is an oauth2 token-endpoint error carrying
// RFC 6749 §5.2 code "invalid_grant" — i.e. the refresh token is expired or revoked.
func isInvalidGrant(err error) bool {
	var re *oauth2.RetrieveError
	return errors.As(err, &re) && re.ErrorCode == "invalid_grant"
}
