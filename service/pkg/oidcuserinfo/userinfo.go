// Package oidcuserinfo provides caching and retrieval for OIDC UserInfo responses.
package oidcuserinfo

import (
	"context"
	"time"

	"github.com/opentdf/platform/service/pkg/cache"
)

// CacheConfig holds configuration for the OIDC UserInfo cache.
type CacheConfig struct {
	TTL time.Duration
}

// UserInfo provides caching for OIDC UserInfo responses using the centralized cache library.
type UserInfo struct {
	cache    *cache.Cache
	service  string
	cacheTTL time.Duration
}

// NewUserInfo creates a new OIDC UserInfo cache with the given TTL (in seconds).
func NewUserInfo(service string, ttlSeconds int64, cacheManager *cache.CacheManager) (*UserInfo, error) {
	// Set up cache options as needed for your use case
	opts := cache.CacheOptions{
		// Example: MaxEntries: 10000, MaxSize: 1 << 20, Shards: 64
	}
	c := cacheManager.NewCache(service, opts)
	return &UserInfo{cache: c, service: service, cacheTTL: time.Duration(ttlSeconds) * time.Second}, nil
}

// NewCacheWithConfig creates a new OIDC UserInfo cache using a CacheConfig.
func NewCacheWithConfig(service string, cfg CacheConfig, cacheManager *cache.CacheManager) (*UserInfo, error) {
	return NewUserInfo(service, int64(cfg.TTL.Seconds()), cacheManager)
}

// Key returns a unique cache key for a user based on issuer and sub.
func Key(issuer, sub string) string {
	return issuer + ":" + sub
}

// Get tries to get userinfo from cache.
func (u *UserInfo) Get(ctx context.Context, issuer, sub string) (map[string]interface{}, bool) {
	key := Key(issuer, sub)
	val, err := u.cache.Get(ctx, key)
	if err == nil {
		if userinfo, ok := val.(map[string]interface{}); ok {
			return userinfo, true
		}
	}
	return nil, false
}

// Set stores userinfo in cache.
func (u *UserInfo) Set(ctx context.Context, issuer, sub string, userinfo map[string]interface{}) {
	key := Key(issuer, sub)
	_ = u.cache.Set(ctx, key, userinfo, nil) // Pass nil or []string{} for tags if not used
}
