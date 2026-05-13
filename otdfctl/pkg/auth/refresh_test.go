package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/opentdf/platform/otdfctl/pkg/profiles"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestProfile(t *testing.T, authType string, accessToken, refreshToken string, expiration int64) *profiles.OtdfctlProfileStore {
	t.Helper()
	cfg := &profiles.ProfileConfig{
		Name:        "test",
		Endpoint:    "https://example.com",
		TLSNoVerify: false,
	}
	store, err := profiles.NewOtdfctlProfileStore(profiles.ProfileDriverMemory, cfg, false)
	require.NoError(t, err)
	err = store.SetAuthCredentials(profiles.AuthCredentials{
		AuthType: authType,
		AccessToken: profiles.AuthCredentialsAccessToken{
			ClientID:     "cli-client",
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			Expiration:   expiration,
		},
	})
	require.NoError(t, err)
	return store
}

func TestIsTokenExpired(t *testing.T) {
	tests := []struct {
		name     string
		authType string
		exp      int64
		want     bool
	}{
		{
			name:     "expired token",
			authType: profiles.AuthTypeAccessToken,
			exp:      time.Now().Add(-time.Hour).Unix(),
			want:     true,
		},
		{
			name:     "valid token",
			authType: profiles.AuthTypeAccessToken,
			exp:      time.Now().Add(time.Hour).Unix(),
			want:     false,
		},
		{
			name:     "non-access-token auth type",
			authType: profiles.AuthTypeClientCredentials,
			exp:      time.Now().Add(-time.Hour).Unix(),
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := newTestProfile(t, tt.authType, "tok", "refresh", tt.exp)
			got := IsTokenExpired(profile)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestHasRefreshToken(t *testing.T) {
	tests := []struct {
		name         string
		authType     string
		refreshToken string
		want         bool
	}{
		{
			name:         "has refresh token",
			authType:     profiles.AuthTypeAccessToken,
			refreshToken: "refresh-tok",
			want:         true,
		},
		{
			name:         "no refresh token",
			authType:     profiles.AuthTypeAccessToken,
			refreshToken: "",
			want:         false,
		},
		{
			name:         "wrong auth type",
			authType:     profiles.AuthTypeClientCredentials,
			refreshToken: "refresh-tok",
			want:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := newTestProfile(t, tt.authType, "tok", tt.refreshToken, time.Now().Add(time.Hour).Unix())
			got := HasRefreshToken(profile)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRefreshAccessTokenWrongAuthType(t *testing.T) {
	profile := newTestProfile(t, profiles.AuthTypeClientCredentials, "tok", "refresh", time.Now().Add(time.Hour).Unix())
	err := RefreshAccessToken(context.Background(), profile)
	require.ErrorIs(t, err, ErrInvalidAuthType)
}

func TestRefreshAccessTokenNoRefreshToken(t *testing.T) {
	profile := newTestProfile(t, profiles.AuthTypeAccessToken, "tok", "", time.Now().Add(-time.Hour).Unix())
	err := RefreshAccessToken(context.Background(), profile)
	require.ErrorIs(t, err, ErrNoRefreshToken)
}

func TestRefreshAccessTokenSuccess(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "new-access-token",
			"refresh_token": "new-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
		assert.NoError(t, err)
	}))
	defer tokenServer.Close()

	origFunc := getTokenEndpointFunc
	getTokenEndpointFunc = func(string, bool) (string, error) {
		return tokenServer.URL, nil
	}
	defer func() { getTokenEndpointFunc = origFunc }()

	profile := newTestProfile(t, profiles.AuthTypeAccessToken, "old-token", "old-refresh", time.Now().Add(-time.Hour).Unix())

	err := RefreshAccessToken(context.Background(), profile)
	require.NoError(t, err)

	creds := profile.GetAuthCredentials()
	assert.Equal(t, "new-access-token", creds.AccessToken.AccessToken)
	assert.Equal(t, "new-refresh-token", creds.AccessToken.RefreshToken)
	assert.Greater(t, creds.AccessToken.Expiration, time.Now().Unix(),
		"expiration should be updated to a future timestamp")
}

func TestRefreshAccessTokenEndpointError(t *testing.T) {
	origFunc := getTokenEndpointFunc
	getTokenEndpointFunc = func(string, bool) (string, error) {
		return "", errors.New("gRPC connection failed")
	}
	defer func() { getTokenEndpointFunc = origFunc }()

	profile := newTestProfile(t, profiles.AuthTypeAccessToken, "tok", "refresh", time.Now().Add(-time.Hour).Unix())
	err := RefreshAccessToken(context.Background(), profile)
	require.ErrorContains(t, err, "failed to get token endpoint")
}

func TestRefreshAccessTokenRefreshFails(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		err := json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		assert.NoError(t, err)
	}))
	defer tokenServer.Close()

	origFunc := getTokenEndpointFunc
	getTokenEndpointFunc = func(string, bool) (string, error) {
		return tokenServer.URL, nil
	}
	defer func() { getTokenEndpointFunc = origFunc }()

	profile := newTestProfile(t, profiles.AuthTypeAccessToken, "tok", "refresh", time.Now().Add(-time.Hour).Unix())
	err := RefreshAccessToken(context.Background(), profile)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrRefreshFailed)
}

func TestRefreshAccessTokenEmptyClientID(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "new-token",
			"refresh_token": "new-refresh",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
		assert.NoError(t, err)
	}))
	defer tokenServer.Close()

	origFunc := getTokenEndpointFunc
	getTokenEndpointFunc = func(string, bool) (string, error) {
		return tokenServer.URL, nil
	}
	defer func() { getTokenEndpointFunc = origFunc }()

	cfg := &profiles.ProfileConfig{
		Name:     "test",
		Endpoint: "https://example.com",
	}
	profile, err := profiles.NewOtdfctlProfileStore(profiles.ProfileDriverMemory, cfg, false)
	require.NoError(t, err)
	err = profile.SetAuthCredentials(profiles.AuthCredentials{
		AuthType: profiles.AuthTypeAccessToken,
		AccessToken: profiles.AuthCredentialsAccessToken{
			ClientID:     "",
			AccessToken:  "old-token",
			RefreshToken: "old-refresh",
			Expiration:   time.Now().Add(-time.Hour).Unix(),
		},
	})
	require.NoError(t, err)

	err = RefreshAccessToken(context.Background(), profile)
	require.NoError(t, err)

	creds := profile.GetAuthCredentials()
	assert.Equal(t, DefaultPublicClientID, creds.AccessToken.ClientID)
}

func TestRefreshAccessTokenTLSNoVerify(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "tls-token",
			"refresh_token": "tls-refresh",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
		assert.NoError(t, err)
	}))
	defer tokenServer.Close()

	origFunc := getTokenEndpointFunc
	getTokenEndpointFunc = func(string, bool) (string, error) {
		return tokenServer.URL, nil
	}
	defer func() { getTokenEndpointFunc = origFunc }()

	cfg := &profiles.ProfileConfig{
		Name:        "test",
		Endpoint:    "https://example.com",
		TLSNoVerify: true,
	}
	profile, err := profiles.NewOtdfctlProfileStore(profiles.ProfileDriverMemory, cfg, false)
	require.NoError(t, err)
	err = profile.SetAuthCredentials(profiles.AuthCredentials{
		AuthType: profiles.AuthTypeAccessToken,
		AccessToken: profiles.AuthCredentialsAccessToken{
			ClientID:     "cli-client",
			AccessToken:  "old-token",
			RefreshToken: "old-refresh",
			Expiration:   time.Now().Add(-time.Hour).Unix(),
		},
	})
	require.NoError(t, err)

	err = RefreshAccessToken(context.Background(), profile)
	require.NoError(t, err)

	creds := profile.GetAuthCredentials()
	assert.Equal(t, "tls-token", creds.AccessToken.AccessToken)
}

func TestGetTokenEndpointFuncSwappable(t *testing.T) {
	origFunc := getTokenEndpointFunc
	defer func() { getTokenEndpointFunc = origFunc }()

	called := false
	getTokenEndpointFunc = func(endpoint string, tlsNoVerify bool) (string, error) {
		called = true
		assert.Equal(t, "https://example.com:443", endpoint)
		assert.False(t, tlsNoVerify)
		return "https://idp.example.com/token", nil
	}

	profile := newTestProfile(t, profiles.AuthTypeAccessToken, "tok", "refresh", time.Now().Add(-time.Hour).Unix())
	_ = RefreshAccessToken(context.Background(), profile)
	assert.True(t, called, "getTokenEndpointFunc should have been called")
}

func TestGetTokenEndpointBadEndpoint(t *testing.T) {
	_, err := getTokenEndpoint("https://localhost:1", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get platform configuration")
}

func TestGetTokenEndpointEmptyEndpoint(t *testing.T) {
	_, err := getTokenEndpoint("", false)
	require.Error(t, err)
}

func TestRefreshAccessTokenNilProfile(t *testing.T) {
	err := RefreshAccessToken(context.Background(), nil)
	require.Error(t, err)
}

func TestIsTokenExpiredNilProfile(t *testing.T) {
	assert.True(t, IsTokenExpired(nil))
}

func TestHasRefreshTokenNilProfile(t *testing.T) {
	assert.False(t, HasRefreshToken(nil))
}
