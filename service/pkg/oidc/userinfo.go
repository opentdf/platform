package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/cache"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

const (
	UserInfoCacheService = "userinfo"
)

var (
	ErrUserInfoCacheMiss = errors.New("user info cache miss")
	ErrUserInfoCacheCast = errors.New("failed to cast cached userinfo to []byte")
)

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
	key := userInfoCacheKey(issuer, subject)
	userInfo, userInfoRaw, err := u.GetFromCache(ctx, issuer, subject)
	if err == nil {
		// If cache hit, return the cached userinfo
		u.logger.Debug("Userinfo found in cache", "issuer", issuer, "subject", subject)
		return userInfo, userInfoRaw, nil
	} else if err != ErrUserInfoCacheMiss {
		// If error and not a cache miss
		u.logger.Error("Failed to get userinfo from cache", "issuer", issuer, "subject", subject, "error", err)
		return nil, nil, err
	}

	// Fetch the userinfo
	u.logger.Debug("Fetching userinfo from UserInfo endpoint", "issuer", issuer, "subject", subject)
	userInfo, userInfoRaw, err = FetchUserInfo(ctx, u.oidcConfig.UserinfoEndpoint, tokenRaw)
	if err != nil {
		u.logger.Error("Failed to fetch userinfo from UserInfo endpoint", "issuer", issuer, "subject", subject, "error", err)
		return nil, nil, err
	}
	u.logger.Debug("Fetched userinfo from UserInfo endpoint", "issuer", issuer, "subject", subject)

	// Store it in cache and return
	return userInfo, userInfoRaw, u.cache.Set(ctx, key, userInfoRaw, nil)
}

func (u *UserInfoCache) GetFromCache(ctx context.Context, issuer, subject string) (*oidc.UserInfo, []byte, error) {
	key := userInfoCacheKey(issuer, subject)
	val, err := u.cache.Get(ctx, key)
	if err != nil {
		return nil, nil, ErrUserInfoCacheMiss
	}
	userInfoRaw, ok := val.([]byte)
	if !ok {
		return nil, nil, fmt.Errorf("failed to cast cached userinfo to []byte: %w", err)
	}
	userInfo := new(oidc.UserInfo)
	if err := json.Unmarshal(userInfoRaw, userInfo); err != nil {
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
	// Create a logger for debugging
	debugLogger := log.New(os.Stderr, "[USERINFO] ", log.LstdFlags)
	debugLogger.Printf("Fetching UserInfo from endpoint: %s", userInfoEndpoint)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoEndpoint, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}

	// Only log a small portion of the token for security
	tokenPreview := ""
	if len(tokenRaw) > 10 {
		tokenPreview = tokenRaw[:10] + "..."
	}
	debugLogger.Printf("Using bearer token: %s", tokenPreview)

	req.Header.Set("Authorization", "Bearer "+tokenRaw)

	// Use our debug transport for the user info request
	client := &http.Client{
		Transport: NewDebugTransport(http.DefaultTransport),
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to execute userinfo request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Try to read the error response body
		errorBody, _ := io.ReadAll(resp.Body)
		debugLogger.Printf("Failed to fetch userinfo: status %d, response body: %s", resp.StatusCode, string(errorBody))
		return nil, nil, fmt.Errorf("failed to fetch userinfo: status %d, details: %s", resp.StatusCode, string(errorBody))
	}

	userInfoRaw, err := io.ReadAll(resp.Body)
	if err != nil {
		debugLogger.Printf("Failed to read userinfo response body: %v", err)
		return nil, nil, fmt.Errorf("failed to read userinfo response body: %w", err)
	}

	userinfo := new(oidc.UserInfo)
	if err := json.Unmarshal(userInfoRaw, userinfo); err != nil {
		debugLogger.Printf("Failed to decode userinfo response: %v", err)
		return nil, nil, fmt.Errorf("failed to decode userinfo response: %w", err)
	}

	debugLogger.Printf("Successfully fetched UserInfo for subject: %s", userinfo.Subject)
	return userinfo, userInfoRaw, nil
}
