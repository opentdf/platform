package authorization

import (
	"testing"
	"time"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/cache"
	"github.com/stretchr/testify/assert"
)

var (
	mockCacheExpiry = 5 * time.Minute
	mockCache, _    = cache.TestCacheClient(mockCacheExpiry)
)

func TestEntitlementPolicyCache_RefreshInterval(t *testing.T) {
	var refreshInterval time.Duration
	ctx := t.Context()
	l := logger.CreateTestLogger()
	_, err := NewEntitlementPolicyCache(ctx, l, nil, mockCache, refreshInterval)
	assert.ErrorIs(t, err, ErrCacheDisabled)

	refreshInterval = 10 * time.Second
	c, err := NewEntitlementPolicyCache(ctx, l, nil, mockCache, refreshInterval)
	assert.NoError(t, err)
	assert.NotNil(t, c)
}

func TestEntitlementPolicyCache_Enabled(t *testing.T) {
	var (
		c               *EntitlementPolicyCache
		err             error
		ctx             = t.Context()
		l               = logger.CreateTestLogger()
		refreshInterval = 10 * time.Second
	)
	assert.False(t, c.IsEnabled())
	assert.False(t, c.IsReady(ctx))

	c, err = NewEntitlementPolicyCache(ctx, l, nil, mockCache, refreshInterval)
	assert.NoError(t, err)
	assert.NotNil(t, c)
	assert.True(t, c.IsEnabled())
	// Retriever is nil, so cache is not ready
	assert.False(t, c.IsReady(ctx))
}

func TestEntitlementPolicyCache_CacheMiss(t *testing.T) {
	ctx := t.Context()
	l := logger.CreateTestLogger()

	c, err := NewEntitlementPolicyCache(ctx, l, nil, mockCache, 1*time.Hour)
	assert.NoError(t, err)

	// No errors, but empty lists on cache misses
	attrs, err := c.ListAllAttributes(ctx)
	assert.NoError(t, err)
	assert.Len(t, attrs, 0)

	subjectMappings, err := c.ListAllSubjectMappings(ctx)
	assert.NoError(t, err)
	assert.Len(t, subjectMappings, 0)

	registeredResources, err := c.ListAllRegisteredResources(ctx)
	assert.NoError(t, err)
	assert.Len(t, registeredResources, 0)
}

func TestEntitlementPolicyCache_CacheHits(t *testing.T) {
	ctx := t.Context()
	l := logger.CreateTestLogger()

	c, err := NewEntitlementPolicyCache(ctx, l, nil, mockCache, 1*time.Hour)
	assert.NoError(t, err)

	attrsList := []*policy.Attribute{{Name: "attr1"}}
	subjMappingsList := []*policy.SubjectMapping{{Id: "id-123"}}
	resourcesList := []*policy.RegisteredResource{{Name: "res1"}}
	mockCache.Set(ctx, attributesCacheKey, attrsList, nil)
	mockCache.Set(ctx, subjectMappingsCacheKey, subjMappingsList, nil)
	mockCache.Set(ctx, registeredResourcesCacheKey, resourcesList, nil)

	attrs, err := c.ListAllAttributes(ctx)
	assert.NoError(t, err)
	assert.Len(t, attrs, 1)
	assert.Equal(t, "attr1", attrs[0].Name)

	subjectMappings, err := c.ListAllSubjectMappings(ctx)
	assert.NoError(t, err)
	assert.Len(t, subjectMappings, 1)
	assert.Equal(t, "id-123", subjectMappings[0].Id)

	registeredResources, err := c.ListAllRegisteredResources(ctx)
	assert.NoError(t, err)
	assert.Len(t, registeredResources, 1)
	assert.Equal(t, "res1", registeredResources[0].Name)
}
