package authorization

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/internal/access/v2"
	"github.com/opentdf/platform/service/logger"
)

var (
	stopTimeout             = 5 * time.Second
	minRefreshInterval      = 15 * time.Second
	maxRefreshInterval      = 1 * time.Hour
	ErrInvalidCacheConfig   = errors.New("invalid cache configuration")
	ErrCacheDisabled        = errors.New("EntitlementPolicyCache is disabled (refresh interval is 0 seconds)")
	ErrFailedToRefreshCache = errors.New("failed to refresh EntitlementPolicyCache")
)

// EntitlementPolicyCache publishes one complete immutable snapshot per refresh.
// Readers keep their snapshot while a replacement is fetched and compiled.
type EntitlementPolicyCache struct {
	logger                    *logger.Logger
	retriever                 access.EntitlementPolicyStore
	options                   access.PolicyOptions
	snapshot                  atomic.Pointer[EntitlementPolicy]
	refreshMu                 sync.Mutex
	configuredRefreshInterval time.Duration
	stopRefresh               chan struct{}
	refreshCompleted          chan struct{}
	stopOnce                  sync.Once
}

// EntitlementPolicy holds the raw policy and its compiled evaluation indexes.
type EntitlementPolicy struct {
	Attributes           []*policy.Attribute
	SubjectMappings      []*policy.SubjectMapping
	DynamicValueMappings []*policy.DynamicValueMapping
	RegisteredResources  []*policy.RegisteredResource
	Obligations          []*policy.Obligation
	prepared             *access.PreparedPolicy
}

func NewEntitlementPolicyCache(ctx context.Context, l *logger.Logger, retriever access.EntitlementPolicyStore, interval time.Duration, options access.PolicyOptions) (*EntitlementPolicyCache, error) {
	if interval <= 0 {
		return nil, ErrCacheDisabled
	}
	c := &EntitlementPolicyCache{
		logger: l.With("component", "EntitlementPolicyCache"), retriever: retriever, options: options,
		configuredRefreshInterval: interval, stopRefresh: make(chan struct{}), refreshCompleted: make(chan struct{}),
	}
	go c.periodicRefresh(ctx)
	return c, nil
}

func (c *EntitlementPolicyCache) IsEnabled() bool { return c != nil }

func (c *EntitlementPolicyCache) IsReady(ctx context.Context) bool {
	if c == nil || c.retriever == nil {
		return false
	}
	if c.snapshot.Load() != nil {
		return true
	}
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	// A concurrent request may have completed the first refresh while we waited.
	if c.snapshot.Load() != nil {
		return true
	}
	if err := c.refresh(ctx); err != nil {
		c.logger.ErrorContext(ctx, "cache is not ready", slog.Any("error", err))
		return false
	}
	return true
}

func (c *EntitlementPolicyCache) PreparedPolicy(_ context.Context) (*access.PreparedPolicy, error) {
	if snapshot := c.snapshot.Load(); snapshot != nil {
		return snapshot.prepared, nil
	}
	return nil, ErrFailedToRefreshCache
}

// Refresh retains the last successful snapshot if retrieval or compilation fails.
// Policy visibility still follows the configured refresh interval; caching remains opt-in.
func (c *EntitlementPolicyCache) Refresh(ctx context.Context) error {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	return c.refresh(ctx)
}

func (c *EntitlementPolicyCache) Stop() {
	c.stopOnce.Do(func() { close(c.stopRefresh) })
	select {
	case <-c.refreshCompleted:
	case <-time.After(stopTimeout):
		c.logger.Warn("timed out waiting for refresh goroutine to complete")
	}
}

func (p *EntitlementPolicy) IsEnabled() bool              { return p != nil }
func (p *EntitlementPolicy) IsReady(context.Context) bool { return p != nil }
func (p *EntitlementPolicy) ListAllAttributes(context.Context) ([]*policy.Attribute, error) {
	return p.Attributes, nil
}

func (p *EntitlementPolicy) ListAllSubjectMappings(context.Context) ([]*policy.SubjectMapping, error) {
	return p.SubjectMappings, nil
}

func (p *EntitlementPolicy) ListAllDynamicValueMappings(context.Context) ([]*policy.DynamicValueMapping, error) {
	return p.DynamicValueMappings, nil
}

func (p *EntitlementPolicy) ListAllRegisteredResources(context.Context) ([]*policy.RegisteredResource, error) {
	return p.RegisteredResources, nil
}

func (p *EntitlementPolicy) ListAllObligations(context.Context) ([]*policy.Obligation, error) {
	return p.Obligations, nil
}

func (c *EntitlementPolicyCache) ListAllAttributes(ctx context.Context) ([]*policy.Attribute, error) {
	return c.current().ListAllAttributes(ctx)
}

func (c *EntitlementPolicyCache) ListAllSubjectMappings(ctx context.Context) ([]*policy.SubjectMapping, error) {
	return c.current().ListAllSubjectMappings(ctx)
}

func (c *EntitlementPolicyCache) ListAllDynamicValueMappings(ctx context.Context) ([]*policy.DynamicValueMapping, error) {
	return c.current().ListAllDynamicValueMappings(ctx)
}

func (c *EntitlementPolicyCache) ListAllRegisteredResources(ctx context.Context) ([]*policy.RegisteredResource, error) {
	return c.current().ListAllRegisteredResources(ctx)
}

func (c *EntitlementPolicyCache) ListAllObligations(ctx context.Context) ([]*policy.Obligation, error) {
	return c.current().ListAllObligations(ctx)
}

func (c *EntitlementPolicyCache) refresh(ctx context.Context) error {
	if c.retriever == nil {
		return ErrFailedToRefreshCache
	}
	next := &EntitlementPolicy{}
	var err error
	if c.options.AllowDirectEntitlements || c.options.AllowDynamicValueMappings {
		next.Attributes, err = c.retriever.ListAllAttributes(ctx)
		if err != nil {
			return err
		}
		next.SubjectMappings, err = c.retriever.ListAllSubjectMappings(ctx)
		if err != nil {
			return err
		}
	}
	if c.options.AllowDynamicValueMappings {
		next.DynamicValueMappings, err = c.retriever.ListAllDynamicValueMappings(ctx)
		if err != nil {
			return err
		}
	}
	next.RegisteredResources, err = c.retriever.ListAllRegisteredResources(ctx)
	if err != nil {
		return err
	}
	next.Obligations, err = c.retriever.ListAllObligations(ctx)
	if err != nil {
		return err
	}
	next.prepared, err = access.NewPreparedPolicy(ctx, c.logger, next, c.options)
	if err != nil {
		return fmt.Errorf("compile entitlement policy: %w", err)
	}
	c.snapshot.Store(next)
	return nil
}

func (c *EntitlementPolicyCache) periodicRefresh(ctx context.Context) {
	ticker := time.NewTicker(c.configuredRefreshInterval)
	defer ticker.Stop()
	defer close(c.refreshCompleted)
	for {
		select {
		case <-ticker.C:
			refreshCtx, cancel := context.WithTimeout(ctx, c.configuredRefreshInterval)
			err := c.Refresh(refreshCtx)
			cancel()
			if err != nil {
				c.logger.ErrorContext(ctx, "failed to refresh cache", slog.Any("error", err))
			}
		case <-c.stopRefresh:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (c *EntitlementPolicyCache) current() *EntitlementPolicy {
	if p := c.snapshot.Load(); p != nil {
		return p
	}
	return &EntitlementPolicy{}
}
