package authorization

import (
	"context"
	"fmt"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/eko/gocache/lib/v4/cache"
	ristretto_store "github.com/eko/gocache/store/ristretto/v4"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	otdfSDK "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/logger"
)

const (
	attributesCacheKey      = "attributes"
	subjectMappingsCacheKey = "subject_mappings"

	numCounters = 1000      // Number of counters for the ristretto cache
	maxCost     = 100000000 // Maximum cost for the ristretto cache (100MB)
	bufferItems = 64        // Buffer items for the ristretto cache
)

// EntitlementPolicyCache caches attributes and subject mappings with periodic refresh
type EntitlementPolicyCache struct {
	sdk                       *otdfSDK.SDK
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
		// Check if stopRefresh is already closed
		select {
		case <-c.stopRefresh:
			// Channel is already closed, nothing to do
			c.logger.DebugContext(context.Background(), "Stop called on already stopped cache")
			return
		default:
			// Channel is still open, proceed with closing
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
}

// Refresh manually refreshes the cache
func (c *EntitlementPolicyCache) Refresh(ctx context.Context) error {
	attributes, err := c.fetchAllDefinitions(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch attributes: %w", err)
	}
	err = c.attributesCache.Set(ctx, attributesCacheKey, attributes)
	if err != nil {
		return fmt.Errorf("failed to cache attributes: %w", err)
	}

	subjectMappings, err := c.fetchAllSubjectMappings(ctx)
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

// ListCachedAttributes returns the cached attributes
func (c *EntitlementPolicyCache) ListCachedAttributes(ctx context.Context) ([]*policy.Attribute, error) {
	return c.attributesCache.Get(ctx, attributesCacheKey)
}

// ListCachedSubjectMappings returns the cached subject mappings
func (c *EntitlementPolicyCache) ListCachedSubjectMappings(ctx context.Context) ([]*policy.SubjectMapping, error) {
	return c.subjectMappingCache.Get(ctx, subjectMappingsCacheKey)
}

// fetchAllDefinitions retrieves all attribute definitions within policy
func (c *EntitlementPolicyCache) fetchAllDefinitions(ctx context.Context) ([]*policy.Attribute, error) {
	// If quantity of attributes exceeds maximum list pagination, all are needed to determine entitlements
	var nextOffset int32
	attrsList := make([]*policy.Attribute, 0)

	for {
		listed, err := c.sdk.Attributes.ListAttributes(ctx, &attrs.ListAttributesRequest{
			State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE,
			// defer to service default for limit pagination
			Pagination: &policy.PageRequest{
				Offset: nextOffset,
			},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list attributes: %w", err)
		}

		nextOffset = listed.GetPagination().GetNextOffset()
		attrsList = append(attrsList, listed.GetAttributes()...)

		if nextOffset <= 0 {
			break
		}
	}
	return attrsList, nil
}

// fetchAllSubjectMappings retrieves all attribute values' subject mappings within policy
func (c *EntitlementPolicyCache) fetchAllSubjectMappings(ctx context.Context) ([]*policy.SubjectMapping, error) {
	// If quantity of subject mappings exceeds maximum list pagination, all are needed to determine entitlements
	var nextOffset int32
	smList := make([]*policy.SubjectMapping, 0)

	for {
		listed, err := c.sdk.SubjectMapping.ListSubjectMappings(ctx, &subjectmapping.ListSubjectMappingsRequest{
			// defer to service default for limit pagination
			Pagination: &policy.PageRequest{
				Offset: nextOffset,
			},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list subject mappings: %w", err)
		}

		nextOffset = listed.GetPagination().GetNextOffset()
		smList = append(smList, listed.GetSubjectMappings()...)

		if nextOffset <= 0 {
			break
		}
	}
	return smList, nil
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

func NewEntitlementPolicyCache(
	ctx context.Context,
	sdk *otdfSDK.SDK,
	l *logger.Logger,
	cfg *Config,
) (*EntitlementPolicyCache, error) {
	if cfg.CacheRefreshIntervalSeconds == 0 {
		l.DebugContext(ctx, "Entitlement policy cache is disabled, returning nil")
		return nil, nil
	}

	l.DebugContext(ctx, "Initializing shared entitlement policy cache")
	instance := &EntitlementPolicyCache{
		logger:                    l,
		sdk:                       sdk,
		configuredRefreshInterval: time.Duration(cfg.CacheRefreshIntervalSeconds) * time.Second,
		stopRefresh:               make(chan struct{}),
		refreshCompleted:          make(chan struct{}),
	}

	ristrettoCache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: numCounters,
		MaxCost:     maxCost,
		BufferItems: bufferItems,
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
		return nil, fmt.Errorf("failed to start entitlement policy cache: %w", err)
	}

	// Only set the instance if Start() succeeds
	l.DebugContext(ctx, "Shared entitlement policy cache initialized")
	return instance, nil

}
