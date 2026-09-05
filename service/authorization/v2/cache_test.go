package authorization

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/internal/access/v2"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/require"
)

type snapshotRetriever struct {
	EntitlementPolicy
	attributes atomic.Int32
	mappings   atomic.Int32
	resources  atomic.Int32
	dynamic    atomic.Int32
	fail       atomic.Bool
}

func (s *snapshotRetriever) ListAllAttributes(ctx context.Context) ([]*policy.Attribute, error) {
	s.attributes.Add(1)
	return s.EntitlementPolicy.ListAllAttributes(ctx)
}

func (s *snapshotRetriever) ListAllSubjectMappings(ctx context.Context) ([]*policy.SubjectMapping, error) {
	s.mappings.Add(1)
	return s.EntitlementPolicy.ListAllSubjectMappings(ctx)
}

func (s *snapshotRetriever) ListAllDynamicValueMappings(ctx context.Context) ([]*policy.DynamicValueMapping, error) {
	s.dynamic.Add(1)
	return s.EntitlementPolicy.ListAllDynamicValueMappings(ctx)
}

func (s *snapshotRetriever) ListAllRegisteredResources(ctx context.Context) ([]*policy.RegisteredResource, error) {
	s.resources.Add(1)
	if s.fail.Load() {
		return nil, errors.New("policy unavailable")
	}
	return s.EntitlementPolicy.ListAllRegisteredResources(ctx)
}

func testSnapshotCache(t *testing.T, retriever access.EntitlementPolicyStore, options access.PolicyOptions) *EntitlementPolicyCache {
	t.Helper()
	c, err := NewEntitlementPolicyCache(t.Context(), logger.CreateTestLogger(), retriever, time.Hour, options)
	require.NoError(t, err)
	t.Cleanup(c.Stop)
	return c
}

func TestPolicyCacheColdRequestsShareOneSnapshot(t *testing.T) {
	source := &snapshotRetriever{}
	c := testSnapshotCache(t, source, access.PolicyOptions{})
	const concurrency = 32
	ready := make(chan bool, concurrency)
	var workers sync.WaitGroup
	for range concurrency {
		workers.Go(func() { ready <- c.IsReady(t.Context()) })
	}
	workers.Wait()
	close(ready)
	for ok := range ready {
		require.True(t, ok)
	}
	require.EqualValues(t, 1, source.resources.Load())
	require.Zero(t, source.attributes.Load())
	require.Zero(t, source.mappings.Load())
	require.Zero(t, source.dynamic.Load())
	first, err := c.PreparedPolicy(t.Context())
	require.NoError(t, err)
	second, err := c.PreparedPolicy(t.Context())
	require.NoError(t, err)
	require.Same(t, first, second)
}

func TestPolicyCacheFailedRefreshRetainsCompleteSnapshot(t *testing.T) {
	source := &snapshotRetriever{EntitlementPolicy: EntitlementPolicy{
		RegisteredResources: []*policy.RegisteredResource{{Name: "first", Values: []*policy.RegisteredResourceValue{{Value: "value"}}}},
	}}
	c := testSnapshotCache(t, source, access.PolicyOptions{})
	require.True(t, c.IsReady(t.Context()))
	first, err := c.PreparedPolicy(t.Context())
	require.NoError(t, err)
	source.RegisteredResources = []*policy.RegisteredResource{{Name: "second", Values: []*policy.RegisteredResourceValue{{Value: "value"}}}}
	source.fail.Store(true)
	require.Error(t, c.Refresh(t.Context()))
	retained, err := c.PreparedPolicy(t.Context())
	require.NoError(t, err)
	require.Same(t, first, retained)
	resources, err := c.ListAllRegisteredResources(t.Context())
	require.NoError(t, err)
	require.Equal(t, "first", resources[0].GetName())
	source.fail.Store(false)
	require.NoError(t, c.Refresh(t.Context()))
	replacement, err := c.PreparedPolicy(t.Context())
	require.NoError(t, err)
	require.NotSame(t, first, replacement)
	resources, err = c.ListAllRegisteredResources(t.Context())
	require.NoError(t, err)
	require.Equal(t, "second", resources[0].GetName())
}

func TestPolicyCacheFeatureSpecificLoads(t *testing.T) {
	for _, options := range []access.PolicyOptions{
		{AllowDirectEntitlements: true}, {AllowDynamicValueMappings: true},
	} {
		t.Run(fmtPolicyOptions(options), func(t *testing.T) {
			source := &snapshotRetriever{EntitlementPolicy: EntitlementPolicy{Attributes: []*policy.Attribute{}, SubjectMappings: []*policy.SubjectMapping{}}}
			c := testSnapshotCache(t, source, options)
			require.True(t, c.IsReady(t.Context()))
			require.EqualValues(t, 1, source.attributes.Load())
			require.EqualValues(t, 1, source.mappings.Load())
			if options.AllowDynamicValueMappings {
				require.EqualValues(t, 1, source.dynamic.Load())
			} else {
				require.Zero(t, source.dynamic.Load())
			}
		})
	}
}

func fmtPolicyOptions(options access.PolicyOptions) string {
	if options.AllowDirectEntitlements {
		return "direct"
	}
	return "dynamic"
}

func TestPolicyCacheDisabledAndUnavailable(t *testing.T) {
	var absent *EntitlementPolicyCache
	require.False(t, absent.IsEnabled())
	require.False(t, absent.IsReady(t.Context()))
	c := testSnapshotCache(t, nil, access.PolicyOptions{})
	require.True(t, c.IsEnabled())
	require.False(t, c.IsReady(t.Context()))
	require.Error(t, c.Refresh(t.Context()))
	_, err := c.PreparedPolicy(t.Context())
	require.ErrorIs(t, err, ErrFailedToRefreshCache)
	_, err = NewEntitlementPolicyCache(t.Context(), nil, nil, 0, access.PolicyOptions{})
	require.ErrorIs(t, err, ErrCacheDisabled)
}
