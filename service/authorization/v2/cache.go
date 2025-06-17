package authorization

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/opentdf/platform/protocol/go/policy"
	otdfSDK "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/internal/access/v2"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/cache"
)

const (
	entitlementPolicyCacheKey = "entitlement_policy"
)

var (
	// Cache tags for authorization-related data set in the cache
	authzCacheTags = []string{"authorization", "policy", "entitlements"}

	// stopTimeout is the maximum time to wait for the periodic refresh goroutine to stop
	stopTimeout = 5 * time.Second

	ErrFailedToStartCache   = errors.New("failed to start EntitlementPolicyCache")
	ErrFailedToRefreshCache = errors.New("failed to refresh EntitlementPolicyCache")
	ErrFailedToSet          = errors.New("failed to set cache with fresh EntitlementPolicy")
	ErrFailedToGet          = errors.New("failed to get cached EntitlementPolicy")
	ErrCacheDisabled        = errors.New("EntitlementPolicyCache is disabled (refresh interval is 0 seconds)")
)

// EntitlementPolicyCache caches attributes and subject mappings with periodic refresh
type EntitlementPolicyCache struct {
	sdk         *otdfSDK.SDK
	logger      *logger.Logger
	cacheClient *cache.Cache[EntitlementPolicy]
	// SDK-connected retriever to fetch fresh data from policy services
	retriever                 *access.EntitlementPolicyRetriever
	configuredRefreshInterval time.Duration
	stopRefresh               chan struct{}
	refreshCompleted          chan struct{}
}

// The EntitlementPolicy struct holds all the cached entitlement policy, as generics allow one
// data type per service cache instance.
type EntitlementPolicy struct {
	Attributes          []*policy.Attribute
	SubjectMappings     []*policy.SubjectMapping
	RegisteredResources []*policy.RegisteredResource
}

// NewEntitlementPolicyCache holds a platform-provided cache client and manages a periodic refresh of
// cached entitlement policy data, fetching fresh data from the policy services at configured interval.
func NewEntitlementPolicyCache(
	ctx context.Context,
	l *logger.Logger,
	sdk *otdfSDK.SDK,
	cacheClient *cache.Cache[EntitlementPolicy],
	cacheRefreshIntervalSeconds int,
) (*EntitlementPolicyCache, error) {
	if cacheRefreshIntervalSeconds == 0 {
		return nil, ErrCacheDisabled
	}
	l = l.With("component", "EntitlementPolicyCache")

	l.DebugContext(ctx, "Initializing cache...", slog.Int("refresh_interval_seconds", cacheRefreshIntervalSeconds))

	instance := &EntitlementPolicyCache{
		logger:                    l,
		cacheClient:               cacheClient,
		retriever:                 access.NewEntitlementPolicyRetriever(sdk),
		configuredRefreshInterval: time.Duration(cacheRefreshIntervalSeconds) * time.Second,
		stopRefresh:               make(chan struct{}),
		refreshCompleted:          make(chan struct{}),
	}

	// Try to start the cache
	if err := instance.Start(ctx); err != nil {
		return nil, errors.Join(ErrFailedToStartCache, err)
	}

	// Only set the instance if Start() succeeds
	l.DebugContext(ctx, "Shared EntitlementPolicyCache initialized")
	return instance, nil
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
		return errors.Join(ErrFailedToRefreshCache, err)
	}

	// Begin periodic refresh if an interval is set
	if c.configuredRefreshInterval > 0 {
		c.logger.DebugContext(ctx, "Starting periodic cache refresh",
			"seconds", c.configuredRefreshInterval.Seconds())
		go c.periodicRefresh(ctx)
	} else {
		c.logger.DebugContext(ctx, "Periodic cache refresh is disabled (interval <= 0)")
	}

	return nil
}

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

// Refresh manually refreshes the cache by reaching out to policy services
func (c *EntitlementPolicyCache) Refresh(ctx context.Context) error {
	attributes, err := c.retriever.ListAllAttributes(ctx)
	if err != nil {
		return err
	}

	subjectMappings, err := c.retriever.ListAllSubjectMappings(ctx)
	if err != nil {
		return err
	}

	registeredResources, err := c.ListAllRegisteredResources(ctx)
	if err != nil {
		return err
	}

	policy := EntitlementPolicy{
		Attributes:          attributes,
		SubjectMappings:     subjectMappings,
		RegisteredResources: registeredResources,
	}

	err = c.cacheClient.Set(ctx, entitlementPolicyCacheKey, policy, authzCacheTags)
	if err != nil {
		return errors.Join(ErrFailedToSet, err)
	}

	c.logger.DebugContext(ctx,
		"EntitlementPolicyCache refreshed",
		"attributes_count", len(attributes),
		"subject_mappings_count", len(subjectMappings),
	)

	return nil
}

// ListAllAttributes returns the cached attributes
func (c *EntitlementPolicyCache) ListAllAttributes(ctx context.Context) ([]*policy.Attribute, error) {
	cached, err := c.cacheClient.Get(ctx, entitlementPolicyCacheKey)
	if err != nil {
		return nil, fmt.Errorf("%w, attributes: %w", ErrFailedToGet, err)
	}
	return cached.Attributes, nil
}

// ListAllSubjectMappings returns the cached subject mappings
func (c *EntitlementPolicyCache) ListAllSubjectMappings(ctx context.Context) ([]*policy.SubjectMapping, error) {
	cached, err := c.cacheClient.Get(ctx, entitlementPolicyCacheKey)
	if err != nil {
		return nil, fmt.Errorf(", subject mappings: %w", ErrFailedToGet, err)
	}
	return cached.SubjectMappings, nil
}

// ListAllRegisteredResources returns the cached registered resources
func (c *EntitlementPolicyCache) ListAllRegisteredResources(ctx context.Context) ([]*policy.RegisteredResource, error) {
	cached, err := c.cacheClient.Get(ctx, entitlementPolicyCacheKey)
	if err != nil {
		return nil, fmt.Errorf("%w, registered resources: %w", ErrFailedToGet, err)
	}
	return cached.RegisteredResources, nil
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
