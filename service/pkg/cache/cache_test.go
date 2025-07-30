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
	log := logger.CreateTestLogger()

	options := Options{
		Expiration: 1 * time.Minute,
	}
	cache, err := manager.NewCache("testService", log, options)
	require.NoError(t, err)
	require.NotNil(t, cache)
	require.Equal(t, "testService", cache.serviceName)
	require.Equal(t, options, cache.cacheOptions)
}

func TestCacheManagerClose(t *testing.T) {
	// Create a cache manager
	manager, err := NewCacheManager(1024 * 1024) // 1 MB max cost
	require.NoError(t, err)
	require.NotNil(t, manager)

	// Ensure Close does not panic
	require.NotPanics(t, func() {
		manager.Close()
	})

	// Calling Close twice should also be safe (defensive test)
	require.NotPanics(t, func() {
		manager.Close()
	})
}
