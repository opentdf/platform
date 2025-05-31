package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/cache"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

const (
	UserInfoCacheService = "userinfo"
	// DefaultUserInfoTimeout is the default timeout for userinfo HTTP requests
	DefaultUserInfoTimeout = 30 * time.Second
)

var ErrUserInfoCacheMiss = errors.New("user info cache miss")

type UserInfo = oidc.UserInfo

// UserInfoCache provides caching for OIDC UserInfo responses using the centralized cache library.
type UserInfoCache struct {
	oidcConfig *oidc.DiscoveryConfiguration
	cache      *cache.Cache
	logger     *logger.Logger
}

// NewUserInfoCache creates a new OIDC UserInfo cache with the given TTL (in seconds).
func NewUserInfoCache(oidcConfig *oidc.DiscoveryConfiguration, cache *cache.Cache, logger *logger.Logger) (*UserInfoCache, error) {
	return &UserInfoCache{oidcConfig: oidcConfig, cache: cache, logger: logger}, nil
}

// Get tries to get userinfo from cache otherwise fetches it from the UserInfo endpoint.
func (u *UserInfoCache) Get(ctx context.Context, issuer, subject string, tokenRaw string) (*oidc.UserInfo, []byte, error) {
	l := u.logger.With("issuer", issuer).With("subject", subject)
	key := userInfoCacheKey(issuer, subject)
	userInfo, userInfoRaw, err := u.GetFromCache(ctx, issuer, subject)
	if err == nil {
		// If cache hit, return the cached userinfo
		l.Debug("userinfo found in cache")
		return userInfo, userInfoRaw, nil
	} else if !errors.Is(err, ErrUserInfoCacheMiss) {
		// If error and not a cache miss
		l.Error("failed to get userinfo from cache", "error", err)
		return nil, nil, err
	}

	// Fetch the userinfo
	l.Debug("fetching userinfo from UserInfo endpoint")
	userInfo, userInfoRaw, err = FetchUserInfo(ctx, u.oidcConfig.UserinfoEndpoint, tokenRaw)
	if err != nil {
		l.Error("failed to fetch userinfo from UserInfo endpoint", "error", err)
		return nil, nil, err
	}
	l.Debug("fetched userinfo from UserInfo endpoint")

	// Store it in cache and return
	return userInfo, userInfoRaw, u.cache.Set(ctx, key, userInfoRaw, nil)
}

func (u *UserInfoCache) GetFromCache(ctx context.Context, issuer, subject string) (*oidc.UserInfo, []byte, error) {
	l := u.logger.With("issuer", issuer).With("subject", subject)
	key := userInfoCacheKey(issuer, subject)
	val, err := u.cache.Get(ctx, key)
	if err != nil {
		return nil, nil, ErrUserInfoCacheMiss
	}
	userInfoRaw, ok := val.([]byte)
	if !ok {
		l.Error("failed to cast cached userinfo to []byte", "error", err)
		return nil, nil, fmt.Errorf("failed to cast cached userinfo to []byte: %w", err)
	}
	userInfo := new(oidc.UserInfo)
	if err := json.Unmarshal(userInfoRaw, userInfo); err != nil {
		l.Error("failed to decode userinfo from cache", "error", err)
		return nil, nil, fmt.Errorf("failed to decode userinfo from cache: %w", err)
	}
	return userInfo, userInfoRaw, nil
}

// Invalidate all userinfo cache entries
func (u *UserInfoCache) Invalidate(ctx context.Context) error {
	return u.cache.Invalidate(ctx)
}

// userInfoCacheKey generates a cache key by hashing the issuer URL and combining with subject.
func userInfoCacheKey(issuer, subject string) string {
	// Use base64 encoding for speed instead of sha256
	issuerBytes := []byte(issuer)
	issuerEncoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(issuerBytes)))
	base64.RawURLEncoding.Encode(issuerEncoded, issuerBytes)
	subjectBytes := []byte(subject)
	subjectEncoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(subjectBytes)))
	base64.RawURLEncoding.Encode(subjectEncoded, subjectBytes)
	return fmt.Sprintf("iss:%s|sub:%s", string(issuerEncoded), string(subjectEncoded))
}

// fetchUserInfo performs a GET request to the UserInfo endpoint to fetch user information.
func FetchUserInfo(ctx context.Context, userInfoEndpoint string, tokenRaw string) (*oidc.UserInfo, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoEndpoint, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+tokenRaw)

	// Use our debug transport for the user info request
	client := &http.Client{
		Timeout: DefaultUserInfoTimeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to execute userinfo request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Try to read the error response body
		errorBody, _ := io.ReadAll(resp.Body)
		return nil, nil, fmt.Errorf("failed to fetch userinfo: status %d, details: %s", resp.StatusCode, string(errorBody))
	}

	userInfoRaw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read userinfo response body: %w", err)
	}

	userinfo := new(oidc.UserInfo)
	if err := json.Unmarshal(userInfoRaw, userinfo); err != nil {
		return nil, nil, fmt.Errorf("failed to decode userinfo response: %w", err)
	}

	return userinfo, userInfoRaw, nil
}
