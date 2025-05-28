package cache

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	otdfSDK "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/policy/config"
)

// EntitlementPolicyCache caches attributes and subject mappings with periodic refresh
type EntitlementPolicyCache struct {
	mutex                     sync.RWMutex
	sdk                       *otdfSDK.SDK
	logger                    *logger.Logger
	attributes                []*policy.Attribute
	subjectMappings           []*policy.SubjectMapping
	configuredRefreshInterval time.Duration
	stopRefresh               chan struct{}
	refreshCompleted          chan struct{}
}

// NewEntitlementPolicyCache creates a new cache with the specified refresh interval
// and functions for fetching attributes and subject mappings
func NewEntitlementPolicyCache(
	sdk *otdfSDK.SDK,
	logger *logger.Logger,
) (*EntitlementPolicyCache, error) {
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	if sdk == nil {
		return nil, fmt.Errorf("authenticated SDK is required")
	}

	cache := &EntitlementPolicyCache{
		logger:                    logger,
		sdk:                       sdk,
		configuredRefreshInterval: config.GetPolicyEntitlementCacheRefreshInterval(),
		attributes:                make([]*policy.Attribute, 0),
		subjectMappings:           make([]*policy.SubjectMapping, 0),
		stopRefresh:               make(chan struct{}),
		refreshCompleted:          make(chan struct{}),
	}

	return cache, nil
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

// Refresh manually refreshes the cache
func (c *EntitlementPolicyCache) Refresh(ctx context.Context) error {
	attributes, err := c.fetchAllDefinitions(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch attributes: %w", err)
	}

	subjectMappings, err := c.fetchAllSubjectMappings(ctx)
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

// GetAttributes returns the cached attributes
func (c *EntitlementPolicyCache) GetAttributes(ctx context.Context) []*policy.Attribute {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	// TODO: we may want to copy this so callers cannot modify the cached data
	return c.attributes
}

// GetSubjectMappings returns the cached subject mappings
func (c *EntitlementPolicyCache) GetSubjectMappings(ctx context.Context) []*policy.SubjectMapping {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	// TODO: we may want to copy this so callers cannot modify the cached data
	return c.subjectMappings
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
	// If quantity of attributes exceeds maximum list pagination, all are needed to determine entitlements
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
