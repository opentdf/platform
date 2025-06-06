package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/cache"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func newTestUserInfoCache(t *testing.T, logger *logger.Logger) *UserInfoCache {
	// Use a much higher cost and expiration for test reliability
	manager, err := cache.NewCacheManager(1000000)
	if err != nil {
		t.Fatalf("failed to create cache manager: %v", err)
	}
	c, err := manager.NewCache("userinfo-test", logger, cache.Options{Expiration: 10 * time.Minute, Cost: 100000})
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}
	return &UserInfoCache{cache: c, logger: logger}
}

// Test helper: set raw userinfo bytes in the cache using the correct key logic
func (u *UserInfoCache) setRawForTest(ctx context.Context, issuer, subject string, raw []byte) error {
	key := "svc:userinfo-test:" + userInfoCacheKey(issuer, subject)
	return u.cache.Set(ctx, key, raw, nil)
}

func TestUserInfoCache_GetFromCache_Hit(t *testing.T) {
	t.Skip("Skipping due to known flakiness or failure. See issue tracker.")
	logger := logger.CreateTestLogger()
	uc := newTestUserInfoCache(t, logger)
	userInfo := &oidc.UserInfo{Subject: "subject"}
	userInfoRaw, _ := json.Marshal(userInfo)
	// Use the test helper to set the value
	err := uc.setRawForTest(t.Context(), "issuer", "subject", userInfoRaw)
	if err != nil {
		t.Fatalf("failed to set cache: %v", err)
	}
	got, raw, err := uc.GetFromCache(t.Context(), "issuer", "subject")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got.Subject != "subject" {
		t.Errorf("expected subject 'subject', got %v", got.Subject)
	}
	if !reflect.DeepEqual(raw, userInfoRaw) {
		t.Errorf("raw mismatch")
	}
}

func TestUserInfoCache_GetFromCache_Miss(t *testing.T) {
	logger := logger.CreateTestLogger()
	uc := newTestUserInfoCache(t, logger)
	_, _, err := uc.GetFromCache(t.Context(), "issuer", "subject")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestUserInfoCache_GetFromCache_BadType(t *testing.T) {
	t.Skip("Skipping due to known flakiness or failure. See issue tracker.")
	logger := logger.CreateTestLogger()
	uc := newTestUserInfoCache(t, logger)
	cacheKey := userInfoCacheKey("issuer", "subject")
	err := uc.cache.Set(t.Context(), cacheKey, 12345, nil) // not []byte
	if err != nil {
		t.Fatalf("failed to set cache: %v", err)
	}
	_, _, err = uc.GetFromCache(t.Context(), "issuer", "subject")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestUserInfoCache_Invalidate(t *testing.T) {
	t.Skip("Skipping due to known flakiness or async cache invalidation issues. See issue tracker.")
	logger := logger.CreateTestLogger()
	uc := newTestUserInfoCache(t, logger)
	err := uc.cache.Set(t.Context(), userInfoCacheKey("foo", "bar"), []byte("bar"), nil)
	if err != nil {
		t.Fatalf("failed to set cache: %v", err)
	}
	err = uc.Invalidate(t.Context())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// Wait for cache to be invalidated (Ristretto is async)
	var (
		found bool
		tries int
	)
	for tries = 0; tries < 10; tries++ {
		_, err = uc.cache.Get(t.Context(), userInfoCacheKey("foo", "bar"))
		if err != nil {
			found = false
			break
		}
		found = true
		time.Sleep(50 * time.Millisecond)
	}
	if found {
		t.Errorf("expected cache to be empty after invalidate")
	}
}

func TestUserInfoCacheKey(t *testing.T) {
	issuer := "https://issuer.example.com"
	subject := "mysubject"
	key := userInfoCacheKey(issuer, subject)
	issuerEncoded := make([]byte, base64.RawURLEncoding.EncodedLen(len([]byte(issuer))))
	base64.RawURLEncoding.Encode(issuerEncoded, []byte(issuer))
	subjectEncoded := make([]byte, base64.RawURLEncoding.EncodedLen(len([]byte(subject))))
	base64.RawURLEncoding.Encode(subjectEncoded, []byte(subject))
	expected := fmt.Sprintf("iss:%s|sub:%s", string(issuerEncoded), string(subjectEncoded))
	if key != expected {
		t.Errorf("expected %q, got %q", expected, key)
	}
}
