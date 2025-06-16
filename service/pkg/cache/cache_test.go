package cache

import (
	"testing"
	"time"

	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/require"
)

func TestNewCacheManager_ValidMaxCost(t *testing.T) {
	maxCost := int64(1024 * 1024) // 1MB
	manager, err := NewCacheManager(maxCost)
	require.NoError(t, err)
	require.NotNil(t, manager)
	require.NotNil(t, manager.cache)
}

func TestNewCacheManager_InvalidMaxCost(t *testing.T) {
	// Ristretto requires MaxCost > 0, so use 0 or negative
	_, err := NewCacheManager(0)
	require.Error(t, err)

	_, err = NewCacheManager(-100)
	require.Error(t, err)
}

func TestNewCacheManager_NewCacheIntegration(t *testing.T) {
	maxCost := int64(1024 * 1024)
	manager, err := NewCacheManager(maxCost)
	require.NoError(t, err)
	require.NotNil(t, manager)

	// Use a simple logger stub
	log, _ := newTestLogger()

	options := Options{
		Expiration: 1 * time.Minute,
		Cost:       1,
	}
	cache, err := manager.NewCache("testService", log, options)
	require.NoError(t, err)
	require.NotNil(t, cache)
	require.Equal(t, "testService", cache.serviceName)
	require.Equal(t, options, cache.cacheOptions)
}

// newTestLogger returns a logger.Logger stub for testing.
func newTestLogger() (*logger.Logger, func()) {
	// If logger.Logger has a constructor that doesn't require external setup, use it.
	// Otherwise, return a dummy or nil logger if allowed.
	l, _ := logger.NewLogger(logger.Config{Output: "stdout", Level: "error", Type: "json"})
	return l, func() {}
}
