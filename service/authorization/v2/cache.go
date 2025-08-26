package authorization

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/internal/access/v2"
	"github.com/opentdf/platform/service/logger"
)

const (
	attributesCacheKey          = "attributes_cache_key"
	subjectMappingsCacheKey     = "subject_mappings_cache_key"
	registeredResourcesCacheKey = "registered_resources_cache_key"
)

var (
	// Cache tags for authorization-related data set in the cache
	authzCacheTags = []string{"authorization", "policy", "entitlements"}

	// stopTimeout is the maximum time to wait for the periodic refresh goroutine to stop
	stopTimeout = 5 * time.Second

	// valid minimum refresh interval for the cache (too frequently may overload policy services)
	minRefreshInterval = 15 * time.Second
	maxRefreshInterval = 1 * time.Hour

	ErrInvalidCacheConfig    = errors.New("invalid cache configuration")
	ErrFailedToStartCache    = errors.New("failed to start EntitlementPolicyCache")
	ErrFailedToRefreshCache  = errors.New("failed to refresh EntitlementPolicyCache")
	ErrFailedToSet           = errors.New("failed to set cache with fresh entitlement policy")
	ErrFailedToGet           = errors.New("failed to get cached entitlement policy")
	ErrCacheDisabled         = errors.New("EntitlementPolicyCache is disabled (refresh interval is 0 seconds)")
	ErrCachedTypeNotExpected = errors.New("cached data is not of expected type")
)

// EntitlementPolicyCache caches attributes and subject mappings with periodic refresh
type EntitlementPolicyCache struct {
	logger *logger.Logger
	policy access.EntitlementPolicy
	mu     sync.RWMutex

	// SDK-connected retriever to fetch fresh data from policy services
	retriever *access.EntitlementPolicyRetriever

	// Refresh state
	configuredRefreshInterval time.Duration
	stopRefresh               chan struct{}
	refreshCompleted          chan struct{}

	// isCacheFilled indicates if the cache has been filled
	isCacheFilled bool
}



// NewEntitlementPolicyCache holds a platform-provided cache client and manages a periodic refresh of
// cached entitlement policy data, fetching fresh data from the policy services at configured interval.
func NewEntitlementPolicyCache(
	ctx context.Context,
	l *logger.Logger,
	retriever *access.EntitlementPolicyRetriever,
	cacheRefreshInterval time.Duration,
) (*EntitlementPolicyCache, error) {
	if cacheRefreshInterval == 0 {
		return nil, ErrCacheDisabled
	}
	l = l.With("component", "EntitlementPolicyCache")

	l.DebugContext(ctx, "initializing cache")

	instance := &EntitlementPolicyCache{
		logger:                    l,
		retriever:                 retriever,
		configuredRefreshInterval: cacheRefreshInterval,
		stopRefresh:               make(chan struct{}),
		refreshCompleted:          make(chan struct{}),
	}

	// Try to start the cache
	if err := instance.Start(ctx); err != nil {
		return nil, errors.Join(ErrFailedToStartCache, err)
	}

	// Only set the instance if Start() succeeds
	l.DebugContext(ctx, "initialized EntitlementPolicyCache and started periodic refresh")
	return instance, nil
}

func (c *EntitlementPolicyCache) IsEnabled() bool {
	return c != nil
}

func (c *EntitlementPolicyCache) IsReady(ctx context.Context) bool {
	if !c.IsEnabled() || c.retriever == nil {
		return false
	}
	if !c.isCacheFilled {
		if err := c.Refresh(ctx); err != nil {
			c.logger.ErrorContext(ctx, "cache is not ready", slog.Any("error", err))
			return false
		}
	}
	return true
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

	c.logger.DebugContext(ctx,
		"starting periodic cache refresh",
		slog.Float64("seconds", c.configuredRefreshInterval.Seconds()),
	)
	go c.periodicRefresh(ctx)

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
			c.logger.DebugContext(context.Background(), "stop called on already stopped cache")
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
				c.logger.WarnContext(context.Background(), "timed out waiting for refresh goroutine to complete")
			}
		}
	}
}

// Refresh manually refreshes the cache by reaching out to policy services. In the event of an error,
// the cache is marked as not filled, and the error is returned.
func (c *EntitlementPolicyCache) Refresh(ctx context.Context) error {
	// Retrieve fresh data from the policy services
	attributes, err := c.retriever.ListAllAttributes(ctx)
	if err != nil {
		return err
	}
	subjectMappings, err := c.retriever.ListAllSubjectMappings(ctx)
	if err != nil {
		return err
	}
	registeredResources, err := c.retriever.ListAllRegisteredResources(ctx)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.policy = access.EntitlementPolicy{
		Attributes:          attributes,
		RegisteredResources: registeredResources,
		SubjectMappings:     subjectMappings,
	}

	c.logger.DebugContext(ctx,
		"refreshed EntitlementPolicyCache",
		slog.Int("attributes_count", len(attributes)),
		slog.Int("subject_mappings_count", len(subjectMappings)),
		slog.Int("registered_resources_count", len(registeredResources)),
	)

	// Mark the cache as filled after a successful refresh
	c.isCacheFilled = true

	return nil
}

// ListAllAttributes returns the cached attributes
func (c *EntitlementPolicyCache) ListAllAttributes(ctx context.Context) ([]*policy.Attribute, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var attributes []*policy.Attribute
	attributes = c.policy.Attributes
	return attributes, nil
}

// ListAllSubjectMappings returns the cached subject mappings
func (c *EntitlementPolicyCache) ListAllSubjectMappings(ctx context.Context) ([]*policy.SubjectMapping, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var subjectMappings []*policy.SubjectMapping
	subjectMappings = c.policy.SubjectMappings
	return subjectMappings, nil
}

// ListAllRegisteredResources returns the cached registered resources, or none in the event of a cache miss
func (c *EntitlementPolicyCache) ListAllRegisteredResources(ctx context.Context) ([]*policy.RegisteredResource, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var registeredResources []*policy.RegisteredResource
	registeredResources = c.policy.RegisteredResources
	return registeredResources, nil
}

func (c *EntitlementPolicyCache) GetEntitlementPolicy(ctx context.Context) (access.EntitlementPolicy, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.policy, nil
}

// periodicRefresh refreshes the cache at the specified interval
func (c *EntitlementPolicyCache) periodicRefresh(ctx context.Context) {
	waitTimeout := c.configuredRefreshInterval

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
				c.logger.ErrorContext(ctx, "failed to refresh cache", slog.Any("error", err))
			}
		case <-c.stopRefresh:
			return
		case <-ctx.Done():
			c.logger.DebugContext(ctx, "context canceled, stopping periodic refresh")
			return
		}
	}
}
