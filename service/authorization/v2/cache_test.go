package authorization

import (
	"testing"
	"time"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	mockCacheExpiry = 5 * time.Minute
	l               = logger.CreateTestLogger()
)

func Test_NewEntitlementPolicyCache(t *testing.T) {
	ctx := t.Context()
	refreshInterval := 10 * time.Second
	mockCache, _ := cache.TestCacheClient(mockCacheExpiry)

	c, err := NewEntitlementPolicyCache(ctx, l, nil, mockCache, refreshInterval)
	require.NoError(t, err)
	assert.NotNil(t, c)
	assert.Equal(t, refreshInterval, c.configuredRefreshInterval)
	assert.False(t, c.isCacheFilled)
}

func Test_EntitlementPolicyCache_RefreshInterval(t *testing.T) {
	var refreshInterval time.Duration
	ctx := t.Context()
	mockCache, _ := cache.TestCacheClient(mockCacheExpiry)

	_, err := NewEntitlementPolicyCache(ctx, l, nil, mockCache, refreshInterval)
	require.ErrorIs(t, err, ErrCacheDisabled)

	refreshInterval = 10 * time.Second
	c, err := NewEntitlementPolicyCache(ctx, l, nil, mockCache, refreshInterval)
	require.NoError(t, err)
	assert.NotNil(t, c)
}

func Test_EntitlementPolicyCache_Enabled(t *testing.T) {
	var (
		c               *EntitlementPolicyCache
		err             error
		ctx             = t.Context()
		refreshInterval = 10 * time.Second
		mockCache, _    = cache.TestCacheClient(mockCacheExpiry)
	)
	assert.False(t, c.IsEnabled())
	assert.False(t, c.IsReady(ctx))

	c, err = NewEntitlementPolicyCache(ctx, l, nil, mockCache, refreshInterval)
	require.NoError(t, err)
	assert.NotNil(t, c)
	assert.True(t, c.IsEnabled())
	// Retriever is nil, so cache is not ready
	assert.False(t, c.IsReady(ctx))
}

func Test_EntitlementPolicyCache_CacheMiss(t *testing.T) {
	ctx := t.Context()
	mockCache, _ := cache.TestCacheClient(mockCacheExpiry)

	c, err := NewEntitlementPolicyCache(ctx, l, nil, mockCache, 1*time.Hour)
	require.NoError(t, err)

	// No errors, but empty lists on cache misses
	attrs, err := c.ListAllAttributes(ctx)
	require.NoError(t, err)
	assert.Empty(t, attrs)

	subjectMappings, err := c.ListAllSubjectMappings(ctx)
	require.NoError(t, err)
	assert.Empty(t, subjectMappings)

	registeredResources, err := c.ListAllRegisteredResources(ctx)
	require.NoError(t, err)
	assert.Empty(t, registeredResources)
}

func Test_EntitlementPolicyCache_CacheHits(t *testing.T) {
	ctx := t.Context()
	mockCache, _ := cache.TestCacheClient(mockCacheExpiry)

	attrsList := []*policy.Attribute{{Name: "attr1"}}
	subjMappingsList := []*policy.SubjectMapping{{Id: "id-123"}}
	resourcesList := []*policy.RegisteredResource{{Name: "res1"}}
	_ = mockCache.Set(ctx, attributesCacheKey, attrsList, nil)
	_ = mockCache.Set(ctx, subjectMappingsCacheKey, subjMappingsList, nil)
	_ = mockCache.Set(ctx, registeredResourcesCacheKey, resourcesList, nil)

	c, err := NewEntitlementPolicyCache(ctx, l, nil, mockCache, 1*time.Hour)
	require.NoError(t, err)

	// Allow for some concurrency overhead in cache library to prevent flakiness in tests
	time.Sleep(10 * time.Millisecond)

	attrs, err := c.ListAllAttributes(ctx)
	require.NoError(t, err)
	assert.Len(t, attrs, 1)
	assert.Equal(t, "attr1", attrs[0].GetName())

	subjectMappings, err := c.ListAllSubjectMappings(ctx)
	require.NoError(t, err)
	assert.Len(t, subjectMappings, 1)
	assert.Equal(t, "id-123", subjectMappings[0].GetId())

	registeredResources, err := c.ListAllRegisteredResources(ctx)
	require.NoError(t, err)
	assert.Len(t, registeredResources, 1)
	assert.Equal(t, "res1", registeredResources[0].GetName())
}
