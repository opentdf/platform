package config

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/eko/gocache/lib/v4/cache"
	ristretto_store "github.com/eko/gocache/store/ristretto/v4"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/logger"
	policydb "github.com/opentdf/platform/service/policy/db"
)

// Shared service-level instance of EntitlementPolicyCache (attributes and subject mappings)
var (
	entitlementPolicyCacheInstance *EntitlementPolicyCache
	entitlementPolicyCacheOnce     sync.Once
)

const (
	attributesCacheKey      = "attributes"
	subjectMappingsCacheKey = "subject_mappings"
)

// EntitlementPolicyCache caches attributes and subject mappings with periodic refresh
type EntitlementPolicyCache struct {
	dbClient                  policydb.PolicyDBClient
	logger                    *logger.Logger
	attributesCache           *cache.Cache[[]*policy.Attribute]
	subjectMappingCache       *cache.Cache[[]*policy.SubjectMapping]
	configuredRefreshInterval time.Duration
	stopRefresh               chan struct{}
	refreshCompleted          chan struct{}
}

func (c *EntitlementPolicyCache) IsEnabled() bool {
	return c != nil
}

// Start initiates the cache and begins periodic refresh
func (c *EntitlementPolicyCache) Start(ctx context.Context) error {
	// Reset channels in case Start is called multiple times
	// Only reset if stopRefresh is closed or nil
	select {
	case <-c.stopRefresh:
		// Channel was closed, recreate it
		c.stopRefresh = make(chan struct{})
		c.refreshCompleted = make(chan struct{})
	default:
		// Channel is still open, do nothing
	}

	// Initial refresh
	if err := c.Refresh(ctx); err != nil {
		return fmt.Errorf("failed initial cache refresh: %w", err)
	}

	// Begin periodic refresh if an interval is set
	if c.configuredRefreshInterval > 0 {
		c.logger.DebugContext(ctx, "Starting periodic cache refresh",
			"interval_seconds", c.configuredRefreshInterval.Seconds())
		go c.periodicRefresh(ctx)
	} else {
		c.logger.DebugContext(ctx, "Periodic cache refresh is disabled (interval <= 0)")
	}

	return nil
}

// Timeout for the stop operation
var stopTimeout = 5 * time.Second

// Stop stops the periodic refresh goroutine if it's running
func (c *EntitlementPolicyCache) Stop() {
	// Only attempt to stop the refresh goroutine if an interval was set
	if c.configuredRefreshInterval > 0 {
		// Signal the goroutine to stop
		close(c.stopRefresh)
		// Wait with a timeout for the refresh goroutine to complete
		select {
		case <-c.refreshCompleted:
			// Goroutine completed successfully
		case <-time.After(stopTimeout):
			// Timeout as a safety mechanism in case the goroutine is stuck
			c.logger.WarnContext(context.Background(), "Timed out waiting for refresh goroutine to complete")
		}
	}
}

// Refresh manually refreshes the cache
func (c *EntitlementPolicyCache) Refresh(ctx context.Context) error {
	attributes, err := c.dbClient.ListAllAttributes(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch attributes: %w", err)
	}
	err = c.attributesCache.Set(ctx, attributesCacheKey, attributes)
	if err != nil {
		return fmt.Errorf("failed to cache attributes: %w", err)
	}

	subjectMappings, err := c.dbClient.ListAllSubjectMappings(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch subject mappings: %w", err)
	}
	err = c.subjectMappingCache.Set(ctx, subjectMappingsCacheKey, subjectMappings)
	if err != nil {
		return fmt.Errorf("failed to cache subject mappings: %w", err)
	}

	c.logger.DebugContext(ctx,
		"EntitlementPolicyCache refreshed",
		"attributes_count", len(attributes),
		"subject_mappings_count", len(subjectMappings),
	)

	return nil
}

// ListCachedAttributes returns the cached attributes and overall total, where
// a limit of 0 and offset 0 returns all attributes
func (c *EntitlementPolicyCache) ListCachedAttributes(ctx context.Context, limit, offset int32) ([]*policy.Attribute, int32, error) {
	attributes, err := c.attributesCache.Get(ctx, attributesCacheKey)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to retrieve attributes from cache: %w", err)
	}

	total := int32(len(attributes))
	// TODO: we may want to copy this so callers cannot modify the cached data
	// If offset is beyond the length, return empty slice
	if offset >= total {
		return nil, 0, nil
	}
	// If limit is 0, return any attributes beyond the offset
	if limit == 0 {
		return attributes[offset:], total, nil
	}
	// Ensure we don't exceed the slice bounds
	limited := min(offset+limit, total)

	return attributes[offset:limited], total, nil
}

// ListCachedSubjectMappings returns the cached subject mappings and overall total, where
// a limit of 0 returns all subject mappings
func (c *EntitlementPolicyCache) ListCachedSubjectMappings(ctx context.Context, limit, offset int32) ([]*policy.SubjectMapping, int32, error) {
	subjectMappings, err := c.subjectMappingCache.Get(ctx, subjectMappingsCacheKey)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to retrieve subject mappings from cache: %w", err)
	}
	total := int32(len(subjectMappings))
	// TODO: we may want to copy this so callers cannot modify the cached data
	// If offset is beyond the length, return empty slice
	if offset >= total {
		return nil, 0, nil
	}
	// If limit is 0, return any subject mappings beyond the offset
	if limit == 0 {
		return subjectMappings[offset:], total, nil
	}
	// Ensure we don't exceed the slice bounds
	limited := min(offset+limit, total)

	return subjectMappings[offset:limited], total, nil
}

// periodicRefresh refreshes the cache at the specified interval
func (c *EntitlementPolicyCache) periodicRefresh(ctx context.Context) {
	//nolint:mnd // Half the refresh interval for the context timeout
	waitTimeout := c.configuredRefreshInterval / 2

	ticker := time.NewTicker(c.configuredRefreshInterval)
	defer func() {
		ticker.Stop()
		// Always signal completion, regardless of how we exit
		close(c.refreshCompleted)
	}()

	for {
		select {
		case <-ticker.C:
			// Create a child context that can be canceled if refresh takes too long
			refreshCtx, cancel := context.WithTimeout(ctx, waitTimeout)
			err := c.Refresh(refreshCtx)
			cancel() // Always cancel the context to prevent leaks
			if err != nil {
				c.logger.ErrorContext(ctx, "Failed to refresh cache", "error", err)
			}
		case <-c.stopRefresh:
			return
		case <-ctx.Done():
			c.logger.DebugContext(ctx, "Context canceled, stopping periodic refresh")
			return
		}
	}
}

func GetSharedEntitlementPolicyCache(
	ctx context.Context,
	dbClient policydb.PolicyDBClient,
	l *logger.Logger,
	cfg *Config,
) *EntitlementPolicyCache {
	if cfg.CacheRefreshIntervalSeconds == 0 {
		l.DebugContext(ctx, "Entitlement policy cache is disabled, returning nil")
		return nil
	}

	var initErr error
	entitlementPolicyCacheOnce.Do(func() {
		l.DebugContext(ctx, "Initializing shared entitlement policy cache")
		instance := &EntitlementPolicyCache{
			logger:                    l,
			dbClient:                  dbClient,
			configuredRefreshInterval: time.Duration(cfg.CacheRefreshIntervalSeconds) * time.Second,
			stopRefresh:               make(chan struct{}),
			refreshCompleted:          make(chan struct{}),
		}

		ristrettoCache, err := ristretto.NewCache(&ristretto.Config{
			NumCounters: 1000,
			MaxCost:     100000000, // 100MB
			BufferItems: 64,
		})
		if err != nil {
			panic(err)
		}
		ristrettoStore := ristretto_store.NewRistretto(ristrettoCache)

		attributesCache := cache.New[[]*policy.Attribute](ristrettoStore)
		instance.attributesCache = attributesCache

		subjectMappingCache := cache.New[[]*policy.SubjectMapping](ristrettoStore)
		instance.subjectMappingCache = subjectMappingCache

		// Try to start the cache
		if err := instance.Start(ctx); err != nil {
			l.ErrorContext(ctx, "Failed to start entitlement policy cache", "error", err)
			initErr = err
			return
		}

		// Only set the instance if Start() succeeds
		entitlementPolicyCacheInstance = instance
		l.DebugContext(ctx, "Shared entitlement policy cache initialized")
	})

	// Log if we're returning nil due to an initialization error
	if initErr != nil && entitlementPolicyCacheInstance == nil {
		l.WarnContext(ctx, "Returning nil entitlement policy cache due to previous initialization error")
	}

	return entitlementPolicyCacheInstance
}
