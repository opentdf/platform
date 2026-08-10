package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/opentdf/platform/otdfctl/pkg/profiles"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTokenSourceForTest builds a profileTokenSource with the resolver pointed
// at the given httptest server URL.
func newTokenSourceForTest(profile *profiles.OtdfctlProfileStore, tokenURL string) *profileTokenSource {
	ts := newProfileTokenSource(profile)
	ts.resolve = func(string, bool) (string, error) { return tokenURL, nil }
	return ts
}

func TestProfileTokenSource_ValidTokenNoRefresh(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	profile := newTestProfile(t, profiles.AuthTypeAccessToken, "current-access", "refresh", time.Now().Add(time.Hour).Unix())
	ts := newTokenSourceForTest(profile, server.URL)

	tok, err := ts.Token()
	require.NoError(t, err)
	assert.Equal(t, "current-access", tok.AccessToken)
	assert.Equal(t, int32(0), hits.Load(), "no network call expected for a valid token")
}

func TestProfileTokenSource_ExpiredRefreshesAndPersists(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "fresh-access",
			"refresh_token": "rotated-refresh",
			"token_type":    "Bearer",
			"expires_in":    3600,
		}))
	}))
	defer server.Close()

	profile := newTestProfile(t, profiles.AuthTypeAccessToken, "stale", "old-refresh", time.Now().Add(-time.Hour).Unix())
	ts := newTokenSourceForTest(profile, server.URL)

	tok, err := ts.Token()
	require.NoError(t, err)
	assert.Equal(t, "fresh-access", tok.AccessToken)

	creds := profile.GetAuthCredentials()
	assert.Equal(t, "fresh-access", creds.AccessToken.AccessToken)
	assert.Equal(t, "rotated-refresh", creds.AccessToken.RefreshToken)
	assert.Greater(t, creds.AccessToken.Expiration, time.Now().Unix())
}

func TestProfileTokenSource_NoRotationKeepsOldRefresh(t *testing.T) {
	// RFC-compliant IdP that does not rotate refresh tokens omits the field.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fresh-access",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}))
	}))
	defer server.Close()

	profile := newTestProfile(t, profiles.AuthTypeAccessToken, "stale", "keep-me", time.Now().Add(-time.Hour).Unix())
	ts := newTokenSourceForTest(profile, server.URL)

	_, err := ts.Token()
	require.NoError(t, err)

	creds := profile.GetAuthCredentials()
	assert.Equal(t, "keep-me", creds.AccessToken.RefreshToken)
}

func TestProfileTokenSource_ConcurrentRefreshSingleFlights(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "shared-fresh",
			"refresh_token": "shared-refresh",
			"token_type":    "Bearer",
			"expires_in":    3600,
		}))
	}))
	defer server.Close()

	profile := newTestProfile(t, profiles.AuthTypeAccessToken, "stale", "refresh", time.Now().Add(-time.Hour).Unix())
	ts := newTokenSourceForTest(profile, server.URL)

	const workers = 20
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			tok, err := ts.Token()
			assert.NoError(t, err)
			assert.Equal(t, "shared-fresh", tok.AccessToken)
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(1), hits.Load(), "concurrent Token() calls must single-flight the refresh")
}

func TestProfileTokenSource_InvalidGrantClearsCreds(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"}))
	}))
	defer server.Close()

	profile := newTestProfile(t, profiles.AuthTypeAccessToken, "stale", "refresh", time.Now().Add(-time.Hour).Unix())
	ts := newTokenSourceForTest(profile, server.URL)

	_, err := ts.Token()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrRefreshTokenInvalid)

	creds := profile.GetAuthCredentials()
	assert.Empty(t, creds.AuthType)
	assert.Empty(t, creds.AccessToken.RefreshToken)
}

func TestProfileTokenSource_InvalidateForcesRefresh(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "post-invalidate",
			"refresh_token": "post-invalidate-refresh",
			"token_type":    "Bearer",
			"expires_in":    3600,
		}))
	}))
	defer server.Close()

	// Start with a valid, non-expired token so the first Token() does not refresh.
	profile := newTestProfile(t, profiles.AuthTypeAccessToken, "current", "refresh", time.Now().Add(time.Hour).Unix())
	ts := newTokenSourceForTest(profile, server.URL)

	tok, err := ts.Token()
	require.NoError(t, err)
	assert.Equal(t, "current", tok.AccessToken)
	require.Equal(t, int32(0), hits.Load())

	// Server has revoked the token; Invalidate() forces the next call to refresh
	// even though the stored token hasn't expired yet.
	ts.Invalidate()

	tok, err = ts.Token()
	require.NoError(t, err)
	assert.Equal(t, "post-invalidate", tok.AccessToken)
	assert.Equal(t, int32(1), hits.Load())
}

func TestProfileTokenSource_ZeroExpiryFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "fresh",
			"refresh_token": "fresh-refresh",
			"token_type":    "Bearer",
		}))
	}))
	defer server.Close()

	profile := newTestProfile(t, profiles.AuthTypeAccessToken, "stale", "refresh", time.Now().Add(-time.Hour).Unix())
	ts := newTokenSourceForTest(profile, server.URL)

	_, err := ts.Token()
	require.NoError(t, err)

	creds := profile.GetAuthCredentials()
	assert.Greater(t, creds.AccessToken.Expiration, time.Now().Unix(),
		"zero expiry in response should fall back to ~1 hour")
}

func TestProfileTokenSource_WrongAuthType(t *testing.T) {
	profile := newTestProfile(t, profiles.AuthTypeClientCredentials, "tok", "refresh", time.Now().Add(time.Hour).Unix())
	ts := newTokenSourceForTest(profile, "http://ignored")

	_, err := ts.Token()
	require.ErrorIs(t, err, ErrInvalidAuthType)
}
