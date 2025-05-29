package config

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/logger"
	policydb "github.com/opentdf/platform/service/policy/db"
)

// Shared service-level instance of EntitlementPolicyCache (attributes and subject mappings)
var entitlementPolicyCacheInstance *EntitlementPolicyCache
var entitlementPolicyCacheOnce sync.Once

// debounceInterval is the minimum time between refresh operations
const debounceInterval = 1 * time.Second

// EntitlementPolicyCache caches attributes and subject mappings with periodic refresh
type EntitlementPolicyCache struct {
	mutex                     sync.RWMutex
	dbClient                  policydb.PolicyDBClient
	logger                    *logger.Logger
	attributes                []*policy.Attribute
	subjectMappings           []*policy.SubjectMapping
	configuredRefreshInterval time.Duration
	stopRefresh               chan struct{}
	refreshCompleted          chan struct{}
	lastRefreshTime           time.Time
	lastRefreshMutex          sync.Mutex // Protects lastRefreshTime
}

func (c *EntitlementPolicyCache) IsEnabled() bool {
	return c != nil
}

// Start initiates the cache and begins periodic refresh
func (c *EntitlementPolicyCache) Start(ctx context.Context) error {
	// Initial refresh
	if err := c.Refresh(ctx); err != nil {
		return fmt.Errorf("failed initial cache refresh: %w", err)
	}

	// Begin periodic refresh if an interval is set
	if c.configuredRefreshInterval > 0 {
		go c.periodicRefresh(ctx)
	}

	return nil
}

// Stop stops the periodic refresh goroutine
func (c *EntitlementPolicyCache) Stop() {
	close(c.stopRefresh)
	<-c.refreshCompleted // Wait for the refresh goroutine to complete
}

// Refresh manually refreshes the cache
func (c *EntitlementPolicyCache) Refresh(ctx context.Context) error {
	// Time-based debounce: if it's been less than debounceInterval since the last refresh, skip this one
	c.lastRefreshMutex.Lock()
	sinceLastRefresh := time.Since(c.lastRefreshTime)
	if sinceLastRefresh < debounceInterval {
		c.logger.TraceContext(ctx, "EntitlementPolicyCache refresh debounced, skipping",
			"since_last_refresh", sinceLastRefresh.String(),
			"debounce_interval", debounceInterval.String())
		c.lastRefreshMutex.Unlock()
		return nil
	}

	// We're going ahead with the refresh, update the last refresh time
	c.lastRefreshTime = time.Now()
	c.lastRefreshMutex.Unlock()

	attributes, err := c.dbClient.ListAllAttributes(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch attributes: %w", err)
	}

	subjectMappings, err := c.dbClient.ListAllSubjectMappings(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch subject mappings: %w", err)
	}

	c.mutex.Lock()
	c.attributes = attributes
	c.subjectMappings = subjectMappings
	c.mutex.Unlock()

	c.logger.DebugContext(ctx,
		"EntitlementPolicyCache refreshed",
		"attributes_count", len(attributes),
		"subject_mappings_count", len(subjectMappings),
	)

	return nil
}

// ListCachedAttributes returns the cached attributes, where a limit of 0 and offset 0 returns all attributes
func (c *EntitlementPolicyCache) ListCachedAttributes(limit, offset int32) []*policy.Attribute {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	attributes := c.attributes
	// TODO: we may want to copy this so callers cannot modify the cached data
	// If offset is beyond the length, return empty slice
	if offset >= int32(len(attributes)) {
		return nil
	}
	// If limit is 0, return any attributes beyond the offset
	if limit == 0 {
		return attributes[offset:]
	}
	// Ensure we don't exceed the slice bounds
	limited := offset + limit
	if limited > int32(len(attributes)) {
		limited = int32(len(attributes)) - offset
	}
	return attributes[offset:limited]
}

// ListCachedSubjectMappings returns the cached subject mappings, where a limit of 0 returns all subject mappings
func (c *EntitlementPolicyCache) ListCachedSubjectMappings(limit, offset int32) []*policy.SubjectMapping {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	subjectMappings := c.subjectMappings
	// TODO: we may want to copy this so callers cannot modify the cached data
	// If offset is beyond the length, return empty slice
	if offset >= int32(len(subjectMappings)) {
		return nil
	}
	// If limit and offset are 0, return any subject mappings beyond the offset
	if limit == 0 {
		return subjectMappings[offset:]
	}
	// Ensure we don't exceed the slice bounds
	limited := offset + limit
	if limited > int32(len(subjectMappings)) {
		limited = int32(len(subjectMappings)) - offset
	}
	return subjectMappings[offset:limited]
}

// periodicRefresh refreshes the cache at the specified interval
func (c *EntitlementPolicyCache) periodicRefresh(ctx context.Context) {
	ticker := time.NewTicker(c.configuredRefreshInterval)
	defer func() {
		ticker.Stop()
		close(c.refreshCompleted)
	}()

	for {
		select {
		case <-ticker.C:
			err := c.Refresh(ctx)
			if err != nil {
				c.logger.ErrorContext(ctx, "Failed to refresh cache", "error", err)
			}
		case <-c.stopRefresh:
			return
		case <-ctx.Done():
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
	entitlementPolicyCacheOnce.Do(func() {
		l.DebugContext(ctx, "Initializing shared entitlement policy cache")
		entitlementPolicyCacheInstance = &EntitlementPolicyCache{
			logger:                    l,
			dbClient:                  dbClient,
			configuredRefreshInterval: time.Duration(cfg.CacheRefreshIntervalSeconds) * time.Second,
			attributes:                make([]*policy.Attribute, 0),
			subjectMappings:           make([]*policy.SubjectMapping, 0),
			stopRefresh:               make(chan struct{}),
			refreshCompleted:          make(chan struct{}),
			lastRefreshTime:           time.Time{}, // Initialize with zero time to allow first refresh
		}
		if err := entitlementPolicyCacheInstance.Start(ctx); err != nil {
			l.ErrorContext(ctx, "Failed to start entitlement policy cache", "error", err)
			return
		}
		l.DebugContext(ctx, "Shared entitlement policy cache initialized")
	})
	return entitlementPolicyCacheInstance
}
