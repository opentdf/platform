package authorization

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/internal/access/v2"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/cache"
	"github.com/stretchr/testify/assert"
)

var mockCache = cache.TestCacheClient()

// mockRetriever implements the EntitlementPolicyRetriever interface

// type mockRetriever struct {
// 	attributes          []*policy.Attribute
// 	subjectMappings     []*policy.SubjectMapping
// 	registeredResources []*policy.RegisteredResource
// 	attrErr             error
// 	subjErr             error
// 	resErr              error

// 	calledAttributes          bool
// 	calledSubjectMappings     bool
// 	calledRegisteredResources bool
// 	isReady                   bool
// 	isEnabled                 bool
// }

// func (m *mockRetriever) ListAllAttributes(ctx context.Context) ([]*policy.Attribute, error) {
// 	m.calledAttributes = true
// 	return m.attributes, m.attrErr
// }
// func (m *mockRetriever) ListAllSubjectMappings(ctx context.Context) ([]*policy.SubjectMapping, error) {
// 	m.calledSubjectMappings = true
// 	return m.subjectMappings, m.subjErr
// }
// func (m *mockRetriever) ListAllRegisteredResources(ctx context.Context) ([]*policy.RegisteredResource, error) {
// 	m.calledRegisteredResources = true
// 	return m.registeredResources, m.resErr
// }
// func (m *mockRetriever) IsReady() bool {
// 	return m.isReady
// }
// func (m *mockRetriever) IsEnabled() bool {
// 	return m.isEnabled
// }

func TestEntitlementPolicyCache_BasicLifecycle(t *testing.T) {
	ctx := t.Context()
	l := logger.CreateTestLogger()
	mockCache := &mockCache{store: make(map[string]interface{})}
	mr := &mockRetriever{
		attributes:          []*policy.Attribute{{Name: "attr1"}},
		subjectMappings:     []*policy.SubjectMapping{{Id: "user1"}},
		registeredResources: []*policy.RegisteredResource{{Name: "res1"}},
	}

	cacheRefreshInterval := 1 * time.Hour
	c, err := NewEntitlementPolicyCache(ctx, l, nil, mockCache, cacheRefreshInterval)
	if err != nil {
		t.Fatalf("Failed to initialize cache: %v", err)
	}

	assert.True(t, c.IsEnabled())
	assert.True(t, c.IsReady(ctx))

	attrs, err := c.ListAllAttributes(ctx)
	assert.NoError(t, err)
	assert.Len(t, attrs, 1)
	assert.Equal(t, "attr1", attrs[0].Name)

	subjs, err := c.ListAllSubjectMappings(ctx)
	assert.NoError(t, err)
	assert.Len(t, subjs, 1)
	assert.Equal(t, "user1", subjs[0].Id)

	ress, err := c.ListAllRegisteredResources(ctx)
	assert.NoError(t, err)
	assert.Len(t, ress, 1)
	assert.Equal(t, "res1", ress[0].Name)

	c.Stop()
}

func TestEntitlementPolicyCache_RefreshErrors(t *testing.T) {
	ctx := t.Context()
	l := logger.CreateTestLogger()
	mockCache := &mockCache{store: make(map[string]interface{})}
	mr := &mockRetriever{
		attrErr: errors.New("attr error"),
	}
	oldNew := access.NewEntitlementPolicyRetriever
	access.NewEntitlementPolicyRetriever = func(_ *sdk.SDK) *access.EntitlementPolicyRetriever {
		return &access.EntitlementPolicyRetriever{
			ListAllAttributes:          mr.ListAllAttributes,
			ListAllSubjectMappings:     mr.ListAllSubjectMappings,
			ListAllRegisteredResources: mr.ListAllRegisteredResources,
		}
	}
	defer func() { access.NewEntitlementPolicyRetriever = oldNew }()

	_, err := NewEntitlementPolicyCache(ctx, l, nil, mockCache, 1*time.Hour)
	assert.Error(t, err)
}

func TestEntitlementPolicyCache_Disabled(t *testing.T) {
	ctx := t.Context()
	l := logger.CreateTestLogger()
	mockCache := &mockCache{store: make(map[string]interface{})}
	_, err := NewEntitlementPolicyCache(ctx, l, nil, mockCache, 0)
	assert.ErrorIs(t, err, ErrCacheDisabled)
}

func TestEntitlementPolicyCache_CacheMiss(t *testing.T) {
	ctx := t.Context()
	l := logger.CreateTestLogger()
	mockCache := &mockCache{store: make(map[string]interface{})}
	mr := &mockRetriever{}
	oldNew := access.NewEntitlementPolicyRetriever
	access.NewEntitlementPolicyRetriever = func(_ *sdk.SDK) *access.EntitlementPolicyRetriever {
		return &access.EntitlementPolicyRetriever{
			ListAllAttributes:          mr.ListAllAttributes,
			ListAllSubjectMappings:     mr.ListAllSubjectMappings,
			ListAllRegisteredResources: mr.ListAllRegisteredResources,
		}
	}
	defer func() { access.NewEntitlementPolicyRetriever = oldNew }()

	c, err := NewEntitlementPolicyCache(ctx, l, nil, mockCache, 1*time.Hour)
	assert.NoError(t, err)

	// Remove from cache to simulate miss
	delete(mockCache.store, attributesCacheKey)
	attrs, err := c.ListAllAttributes(ctx)
	assert.NoError(t, err)
	assert.Len(t, attrs, 0)
}

func TestEntitlementPolicyCache_RefreshCallsRetriever(t *testing.T) {
	ctx := t.Context()
	l := logger.CreateTestLogger()
	mockCache := &mockCache{store: make(map[string]interface{})}
	mr := &mockRetriever{
		attributes:          []*policy.Attribute{{Name: "attr1"}},
		subjectMappings:     []*policy.SubjectMapping{{Id: "user1"}},
		registeredResources: []*policy.RegisteredResource{{Name: "res1"}},
	}

	cacheRefreshInterval := 1 * time.Hour
	c := &EntitlementPolicyCache{
		logger:                    l,
		cacheClient:               mockCache,
		retriever:                 mr,
		configuredRefreshInterval: cacheRefreshInterval,
	}

	// Call Refresh
	err := c.Refresh(ctx)
	assert.NoError(t, err)

	// Verify retriever methods were called
	assert.True(t, mr.calledAttributes)
	assert.True(t, mr.calledSubjectMappings)
	assert.True(t, mr.calledRegisteredResources)
}
