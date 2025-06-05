package cache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/store"
	ristretto_store "github.com/eko/gocache/store/ristretto/v4"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	configV2 "github.com/opentdf/platform/service/entityresolution/config/v2"
	"github.com/opentdf/platform/service/logger"
)

const (
	numCounters = 1000      // Number of counters for the ristretto cache
	maxCost     = 100000000 // Maximum cost for the ristretto cache (100MB)
	bufferItems = 64        // Buffer items for the ristretto cache
)

// ResponseCache caches attributes and subject mappings with periodic refresh
type ResponseCache struct {
	logger        *logger.Logger
	responseCache *cache.Cache[*entityresolutionV2.ResolveEntitiesResponse]
	configuredTTL time.Duration
}

func NewResponseCache(
	l *logger.Logger,
	cfg *configV2.ERSConfig,
) (*ResponseCache, error) {
	if cfg.CacheResponseLifetimeSeconds == 0 {
		return nil, errors.New("IdP Response Cache is disabled (refresh interval is 0 seconds)")
	}

	l = l.With("component", "ERSResponseCache")

	l.Debug("Initializing shared IdP Response Cache")
	instance := &ResponseCache{
		logger:        l,
		configuredTTL: time.Duration(cfg.CacheResponseLifetimeSeconds) * time.Second,
	}

	ristrettoCache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: numCounters,
		MaxCost:     maxCost,
		BufferItems: bufferItems,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create ristretto cache: %w", err)
	}
	ristrettoStore := ristretto_store.NewRistretto(ristrettoCache)

	responseCache := cache.New[*entityresolutionV2.ResolveEntitiesResponse](ristrettoStore)
	instance.responseCache = responseCache

	l.Debug("Shared IdP Response Cache initialized")
	return instance, nil
}

func (c *ResponseCache) IsEnabled() bool {
	return c != nil
}

func (c *ResponseCache) Get(ctx context.Context, key string) (*entityresolutionV2.ResolveEntitiesResponse, error) {
	if c == nil || c.responseCache == nil {
		return nil, errors.New("IdP Response Cache is not initialized")
	}
	c.logger.DebugContext(ctx, "Retrieving response from cache", "key", key)

	resp, err := c.responseCache.Get(ctx, key)
	if err != nil {
		c.logger.DebugContext(ctx, "Cache miss", "key", key, "error", err)
		return nil, fmt.Errorf("failed to get response from cache: %w", err)
	}
	c.logger.DebugContext(ctx, "cache hit")
	return resp, nil
}

func (c *ResponseCache) Set(ctx context.Context, key string, value *entityresolutionV2.ResolveEntitiesResponse) error {
	if c == nil || c.responseCache == nil {
		return errors.New("IdP Response Cache is not initialized")
	}
	c.logger.DebugContext(ctx, "Setting response in cache", "key", key)

	if err := c.responseCache.Set(ctx, key, value, store.WithExpiration(c.configuredTTL)); err != nil {
		return fmt.Errorf("failed to set response in cache: %w", err)
	}
	c.logger.DebugContext(ctx, "Response cached successfully")
	return nil
}
