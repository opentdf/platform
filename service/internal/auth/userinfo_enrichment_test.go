package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Define an interface for the UserInfoCache with just the methods we need
type UserInfoCacheInterface interface {
	GetFromCache(ctx context.Context, issuer, subject string) (*oidc.UserInfo, []byte, error)
	Get(ctx context.Context, issuer, subject, token string) (*oidc.UserInfo, []byte, error)
	Invalidate(ctx context.Context) error
}

// This is a test-specific Authentication struct that works with our mock
type TestAuthentication struct {
	logger            *logger.Logger
	userInfoCache     UserInfoCacheInterface
	oidcConfiguration TestAuthNConfig
}

// A simplified AuthNConfig for testing
type TestAuthNConfig struct {
	EnrichUserInfo bool
}

// Implementation of GetUserInfoWithExchange that matches the real method
func (a *TestAuthentication) GetUserInfoWithExchange(ctx context.Context, tokenIssuer, tokenSubject, tokenRaw string) ([]byte, error) {
	// If userinfo enrichment is disabled, return empty userinfo
	if !a.oidcConfiguration.EnrichUserInfo {
		return []byte{}, nil
	}

	// Try to get userinfo from cache with the original token
	_, userInfoRaw, err := a.userInfoCache.GetFromCache(ctx, tokenIssuer, tokenSubject)
	if err == nil {
		return userInfoRaw, nil
	}

	// Fetch userinfo with the token (simplifying the exchange for tests)
	_, userInfoRaw, err = a.userInfoCache.Get(ctx, tokenIssuer, tokenSubject, tokenRaw)
	if err != nil {
		return nil, errors.New("unauthenticated")
	}
	return userInfoRaw, nil
}

// This is a mock implementation for testing
type mockUserInfoCache struct {
	getCacheCount     int
	getCount          int
	cacheHit          bool
	cachedInfo        []byte
	getCacheCallCount int
	getCacheFunc      func(ctx context.Context, issuer, subject string) (*oidc.UserInfo, []byte, error)
}

func (m *mockUserInfoCache) GetFromCache(ctx context.Context, issuer, subject string) (*oidc.UserInfo, []byte, error) {
	m.getCacheCount++
	m.getCacheCallCount++ // Increment for both methods of tracking

	// Use custom function if provided
	if m.getCacheFunc != nil {
		return m.getCacheFunc(ctx, issuer, subject)
	}

	// Otherwise use the default behavior
	if m.cacheHit {
		return &oidc.UserInfo{}, m.cachedInfo, nil
	}
	return nil, nil, errors.New("cache miss")
}

func (m *mockUserInfoCache) Get(_ context.Context, _ string, _ string, _ string) (*oidc.UserInfo, []byte, error) {
	m.getCount++
	return &oidc.UserInfo{}, m.cachedInfo, nil
}

func (m *mockUserInfoCache) Invalidate(_ context.Context) error {
	return nil
}

func TestGetUserInfoWithExchange(t *testing.T) {
	testLogger, err := logger.NewLogger(logger.Config{
		Output: "stdout",
		Level:  "debug",
		Type:   "json",
	})
	require.NoError(t, err, "Failed to create logger")

	t.Run("when enrichUserInfo is disabled", func(t *testing.T) {
		cache := &mockUserInfoCache{
			cacheHit:   false,
			cachedInfo: nil,
		}

		auth := &TestAuthentication{
			logger:        testLogger,
			userInfoCache: cache,
			oidcConfiguration: TestAuthNConfig{
				EnrichUserInfo: false,
			},
		}

		userInfo, err := auth.GetUserInfoWithExchange(t.Context(), "issuer", "subject", "token")

		require.NoError(t, err)
		assert.Equal(t, []byte{}, userInfo, "Should return empty userinfo when enrichUserInfo is disabled")

		// Verify that the cache was not called
		assert.Equal(t, 0, cache.getCacheCount, "Cache should not be called when enrichUserInfo is disabled")
	})

	t.Run("when enrichUserInfo is enabled and cache hit", func(t *testing.T) {
		cachedUserInfo := []byte(`{"sub":"subject","name":"Test User"}`)
		cache := &mockUserInfoCache{
			cacheHit:   true,
			cachedInfo: cachedUserInfo,
		}

		auth := &TestAuthentication{
			logger:        testLogger,
			userInfoCache: cache,
			oidcConfiguration: TestAuthNConfig{
				EnrichUserInfo: true,
			},
		}

		userInfo, err := auth.GetUserInfoWithExchange(t.Context(), "issuer", "subject", "token")

		require.NoError(t, err)
		assert.Equal(t, cachedUserInfo, userInfo, "Should return cached userinfo")

		// Verify that the cache was called
		assert.Equal(t, 1, cache.getCacheCount, "Cache should be called when enrichUserInfo is enabled")
	})

	t.Run("when enrichUserInfo is enabled and cache hit using custom function", func(t *testing.T) {
		cachedUserInfo := []byte(`{"sub":"subject","name":"Test User"}`)
		hitCache := &mockUserInfoCache{
			getCacheFunc: func(_ context.Context, _ string, _ string) (*oidc.UserInfo, []byte, error) {
				return &oidc.UserInfo{}, cachedUserInfo, nil
			},
		}

		auth := &TestAuthentication{
			logger:        testLogger,
			userInfoCache: hitCache,
			oidcConfiguration: TestAuthNConfig{
				EnrichUserInfo: true,
			},
		}

		userInfo, err := auth.GetUserInfoWithExchange(t.Context(), "issuer", "subject", "token")

		require.NoError(t, err)
		assert.Equal(t, cachedUserInfo, userInfo, "Should return cached userinfo")

		// Verify that the cache was called
		assert.Equal(t, 1, hitCache.getCacheCallCount, "Cache should be called when enrichUserInfo is enabled")
	})
}
