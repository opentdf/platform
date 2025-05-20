package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/pkg/cache"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type UserInfo = oidc.UserInfo

// UserInfoCache provides caching for OIDC UserInfo responses using the centralized cache library.
type UserInfoCache struct {
	oidcConfig *oidc.DiscoveryConfiguration
	cache      *cache.Cache
}

// NewUserInfoCache creates a new OIDC UserInfo cache with the given TTL (in seconds).
func NewUserInfoCache(oidcConfig *oidc.DiscoveryConfiguration, cache *cache.Cache) (*UserInfoCache, error) {
	return &UserInfoCache{oidcConfig: oidcConfig, cache: cache}, nil
}

// Get tries to get userinfo from cache otherwise fetches it from the UserInfo endpoint.
func (u *UserInfoCache) Get(ctx context.Context, token jwt.Token, tokenRaw string) (*oidc.UserInfo, []byte, error) {
	key := fmt.Sprintf("%s:%s", token.Issuer(), token.Subject())
	if val, err := u.cache.Get(ctx, key); err == nil {
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

	// Fetch the userinfo
	userInfo, userInfoRaw, err := FetchUserInfo(ctx, u.oidcConfig.UserinfoEndpoint, tokenRaw)
	if err != nil {
		return nil, nil, err
	}

	// Store it in cache and return
	return userInfo, userInfoRaw, u.cache.Set(ctx, key, userInfoRaw, nil)
}

// Invalidate all userinfo cache entries
func (u *UserInfoCache) Invalidate(ctx context.Context) error {
	return u.cache.Invalidate(ctx)
}

// fetchUserInfo performs a GET request to the UserInfo endpoint to fetch user information.
func FetchUserInfo(ctx context.Context, userInfoEndpoint string, tokenRaw string) (*oidc.UserInfo, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoEndpoint, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenRaw)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to execute userinfo request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("failed to fetch userinfo: status %d", resp.StatusCode)
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
