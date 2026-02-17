package sdk

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/sdk/sdkconnect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockDiscoveryAttributesClient is a test double for AttributesServiceClient.
type mockDiscoveryAttributesClient struct {
	sdkconnect.AttributesServiceClient

	listAttributesFunc           func(ctx context.Context, req *attributes.ListAttributesRequest) (*attributes.ListAttributesResponse, error)
	getAttributeValuesByFqnsFunc func(ctx context.Context, req *attributes.GetAttributeValuesByFqnsRequest) (*attributes.GetAttributeValuesByFqnsResponse, error)
}

func (m *mockDiscoveryAttributesClient) ListAttributes(ctx context.Context, req *attributes.ListAttributesRequest) (*attributes.ListAttributesResponse, error) {
	return m.listAttributesFunc(ctx, req)
}

func (m *mockDiscoveryAttributesClient) GetAttributeValuesByFqns(ctx context.Context, req *attributes.GetAttributeValuesByFqnsRequest) (*attributes.GetAttributeValuesByFqnsResponse, error) {
	return m.getAttributeValuesByFqnsFunc(ctx, req)
}

// mockDiscoveryAuthzClient is a test double for AuthorizationServiceClient.
type mockDiscoveryAuthzClient struct {
	sdkconnect.AuthorizationServiceClient

	getEntitlementsFunc func(ctx context.Context, req *authorization.GetEntitlementsRequest) (*authorization.GetEntitlementsResponse, error)
}

func (m *mockDiscoveryAuthzClient) GetEntitlements(ctx context.Context, req *authorization.GetEntitlementsRequest) (*authorization.GetEntitlementsResponse, error) {
	return m.getEntitlementsFunc(ctx, req)
}

// newDiscoverySDK creates a minimal SDK with mock service clients for discovery tests.
func newDiscoverySDK(attrClient sdkconnect.AttributesServiceClient, authzClient sdkconnect.AuthorizationServiceClient) SDK {
	s := SDK{}
	s.Attributes = attrClient
	s.Authorization = authzClient
	return s
}

// makeAttr is a test helper to build a policy.Attribute.
func makeAttr(fqn string) *policy.Attribute {
	return &policy.Attribute{Fqn: fqn}
}

// fqnMap is a test helper to build a GetAttributeValuesByFqns response map.
func fqnMap(fqns ...string) map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue {
	m := make(map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue, len(fqns))
	for _, f := range fqns {
		m[f] = &attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{}
	}
	return m
}

// --- ListAttributes tests ---

func TestListAttributes_Empty(t *testing.T) {
	attrClient := &mockDiscoveryAttributesClient{
		listAttributesFunc: func(_ context.Context, _ *attributes.ListAttributesRequest) (*attributes.ListAttributesResponse, error) {
			return &attributes.ListAttributesResponse{}, nil
		},
	}
	s := newDiscoverySDK(attrClient, nil)

	result, err := s.ListAttributes(context.Background())
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestListAttributes_SinglePage(t *testing.T) {
	expected := []*policy.Attribute{
		makeAttr("https://example.com/attr/level/value/high"),
		makeAttr("https://example.com/attr/level/value/low"),
	}
	attrClient := &mockDiscoveryAttributesClient{
		listAttributesFunc: func(_ context.Context, _ *attributes.ListAttributesRequest) (*attributes.ListAttributesResponse, error) {
			return &attributes.ListAttributesResponse{Attributes: expected}, nil
		},
	}
	s := newDiscoverySDK(attrClient, nil)

	result, err := s.ListAttributes(context.Background())
	require.NoError(t, err)
	assert.Equal(t, expected, result)
}

func TestListAttributes_MultiPage(t *testing.T) {
	page1 := []*policy.Attribute{makeAttr("https://example.com/attr/a/value/1")}
	page2 := []*policy.Attribute{makeAttr("https://example.com/attr/b/value/2")}

	calls := 0
	attrClient := &mockDiscoveryAttributesClient{
		listAttributesFunc: func(_ context.Context, req *attributes.ListAttributesRequest) (*attributes.ListAttributesResponse, error) {
			calls++
			if req.GetPagination().GetOffset() == 0 {
				return &attributes.ListAttributesResponse{
					Attributes: page1,
					Pagination: &policy.PageResponse{NextOffset: 1},
				}, nil
			}
			return &attributes.ListAttributesResponse{
				Attributes: page2,
				Pagination: &policy.PageResponse{NextOffset: 0},
			}, nil
		},
	}
	s := newDiscoverySDK(attrClient, nil)

	result, err := s.ListAttributes(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, calls, "should have paginated twice")
	assert.Equal(t, append(page1, page2...), result)
}

func TestListAttributes_NamespaceFilter(t *testing.T) {
	var capturedReq *attributes.ListAttributesRequest
	attrClient := &mockDiscoveryAttributesClient{
		listAttributesFunc: func(_ context.Context, req *attributes.ListAttributesRequest) (*attributes.ListAttributesResponse, error) {
			capturedReq = req
			return &attributes.ListAttributesResponse{}, nil
		},
	}
	s := newDiscoverySDK(attrClient, nil)

	_, err := s.ListAttributes(context.Background(), "my-namespace")
	require.NoError(t, err)
	assert.Equal(t, "my-namespace", capturedReq.GetNamespace())
}

func TestListAttributes_PageLimitExceeded(t *testing.T) {
	attrClient := &mockDiscoveryAttributesClient{
		listAttributesFunc: func(_ context.Context, _ *attributes.ListAttributesRequest) (*attributes.ListAttributesResponse, error) {
			// Always return a non-zero next_offset to simulate a runaway server.
			return &attributes.ListAttributesResponse{
				Attributes: []*policy.Attribute{makeAttr("https://example.com/attr/a/value/1")},
				Pagination: &policy.PageResponse{NextOffset: 1},
			}, nil
		},
	}
	s := newDiscoverySDK(attrClient, nil)

	_, err := s.ListAttributes(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeded maximum page limit")
}

func TestListAttributes_ServiceError(t *testing.T) {
	attrClient := &mockDiscoveryAttributesClient{
		listAttributesFunc: func(_ context.Context, _ *attributes.ListAttributesRequest) (*attributes.ListAttributesResponse, error) {
			return nil, errors.New("service unavailable")
		},
	}
	s := newDiscoverySDK(attrClient, nil)

	_, err := s.ListAttributes(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listing attributes")
	assert.Contains(t, err.Error(), "service unavailable")
}

// --- ValidateAttributes tests ---

func TestValidateAttributes_Empty(t *testing.T) {
	s := newDiscoverySDK(nil, nil)
	err := s.ValidateAttributes(context.Background(), nil)
	require.NoError(t, err)

	err = s.ValidateAttributes(context.Background(), []string{})
	require.NoError(t, err)
}

func TestValidateAttributes_AllFound(t *testing.T) {
	fqns := []string{
		"https://example.com/attr/level/value/high",
		"https://example.com/attr/type/value/secret",
	}
	attrClient := &mockDiscoveryAttributesClient{
		getAttributeValuesByFqnsFunc: func(_ context.Context, _ *attributes.GetAttributeValuesByFqnsRequest) (*attributes.GetAttributeValuesByFqnsResponse, error) {
			return &attributes.GetAttributeValuesByFqnsResponse{FqnAttributeValues: fqnMap(fqns...)}, nil
		},
	}
	s := newDiscoverySDK(attrClient, nil)

	err := s.ValidateAttributes(context.Background(), fqns)
	require.NoError(t, err)
}

func TestValidateAttributes_SomeMissing(t *testing.T) {
	fqns := []string{
		"https://example.com/attr/level/value/high",
		"https://example.com/attr/type/value/missing",
	}
	attrClient := &mockDiscoveryAttributesClient{
		getAttributeValuesByFqnsFunc: func(_ context.Context, _ *attributes.GetAttributeValuesByFqnsRequest) (*attributes.GetAttributeValuesByFqnsResponse, error) {
			// Only return the first FQN as found
			return &attributes.GetAttributeValuesByFqnsResponse{
				FqnAttributeValues: fqnMap(fqns[0]),
			}, nil
		},
	}
	s := newDiscoverySDK(attrClient, nil)

	err := s.ValidateAttributes(context.Background(), fqns)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrAttributeNotFound)
	assert.Contains(t, err.Error(), "https://example.com/attr/type/value/missing")
}

func TestValidateAttributes_AllMissing(t *testing.T) {
	fqns := []string{
		"https://example.com/attr/a/value/x",
		"https://example.com/attr/b/value/y",
	}
	attrClient := &mockDiscoveryAttributesClient{
		getAttributeValuesByFqnsFunc: func(_ context.Context, _ *attributes.GetAttributeValuesByFqnsRequest) (*attributes.GetAttributeValuesByFqnsResponse, error) {
			return &attributes.GetAttributeValuesByFqnsResponse{FqnAttributeValues: fqnMap()}, nil
		},
	}
	s := newDiscoverySDK(attrClient, nil)

	err := s.ValidateAttributes(context.Background(), fqns)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrAttributeNotFound)
}

func TestValidateAttributes_TooManyFQNs(t *testing.T) {
	fqns := make([]string, maxValidateFQNs+1)
	for i := range fqns {
		fqns[i] = fmt.Sprintf("https://example.com/attr/level/value/v%d", i)
	}
	s := newDiscoverySDK(nil, nil)

	err := s.ValidateAttributes(context.Background(), fqns)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too many attribute FQNs")
}

func TestValidateAttributes_InvalidFQNFormat(t *testing.T) {
	s := newDiscoverySDK(nil, nil)

	err := s.ValidateAttributes(context.Background(), []string{"not-a-valid-fqn"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid attribute value FQN")
	assert.Contains(t, err.Error(), "not-a-valid-fqn")
}

func TestValidateAttributes_ServiceError(t *testing.T) {
	fqns := []string{"https://example.com/attr/level/value/high"}
	attrClient := &mockDiscoveryAttributesClient{
		getAttributeValuesByFqnsFunc: func(_ context.Context, _ *attributes.GetAttributeValuesByFqnsRequest) (*attributes.GetAttributeValuesByFqnsResponse, error) {
			return nil, errors.New("network error")
		},
	}
	s := newDiscoverySDK(attrClient, nil)

	err := s.ValidateAttributes(context.Background(), fqns)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validating attributes")
	assert.Contains(t, err.Error(), "network error")
}

// --- GetEntityAttributes tests ---

func TestGetEntityAttributes_NilEntity(t *testing.T) {
	s := newDiscoverySDK(nil, nil)
	_, err := s.GetEntityAttributes(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "entity must not be nil")
}

func TestGetEntityAttributes_Found(t *testing.T) {
	expectedFQNs := []string{
		"https://example.com/attr/clearance/value/secret",
		"https://example.com/attr/country/value/us",
	}
	authzClient := &mockDiscoveryAuthzClient{
		getEntitlementsFunc: func(_ context.Context, req *authorization.GetEntitlementsRequest) (*authorization.GetEntitlementsResponse, error) {
			assert.Len(t, req.GetEntities(), 1)
			return &authorization.GetEntitlementsResponse{
				Entitlements: []*authorization.EntityEntitlements{
					{EntityId: "e1", AttributeValueFqns: expectedFQNs},
				},
			}, nil
		},
	}
	s := newDiscoverySDK(nil, authzClient)

	entity := &authorization.Entity{
		Id:         "e1",
		EntityType: &authorization.Entity_EmailAddress{EmailAddress: "alice@example.com"},
	}
	result, err := s.GetEntityAttributes(context.Background(), entity)
	require.NoError(t, err)
	assert.Equal(t, expectedFQNs, result)
}

func TestGetEntityAttributes_NoEntitlements(t *testing.T) {
	authzClient := &mockDiscoveryAuthzClient{
		getEntitlementsFunc: func(_ context.Context, _ *authorization.GetEntitlementsRequest) (*authorization.GetEntitlementsResponse, error) {
			return &authorization.GetEntitlementsResponse{}, nil
		},
	}
	s := newDiscoverySDK(nil, authzClient)

	entity := &authorization.Entity{
		Id:         "e1",
		EntityType: &authorization.Entity_ClientId{ClientId: "my-service"},
	}
	result, err := s.GetEntityAttributes(context.Background(), entity)
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestGetEntityAttributes_IDMismatch(t *testing.T) {
	authzClient := &mockDiscoveryAuthzClient{
		getEntitlementsFunc: func(_ context.Context, _ *authorization.GetEntitlementsRequest) (*authorization.GetEntitlementsResponse, error) {
			// Server returns entitlements for a different entity ID than requested.
			return &authorization.GetEntitlementsResponse{
				Entitlements: []*authorization.EntityEntitlements{
					{EntityId: "other-entity", AttributeValueFqns: []string{"https://example.com/attr/a/value/x"}},
				},
			}, nil
		},
	}
	s := newDiscoverySDK(nil, authzClient)

	entity := &authorization.Entity{
		Id:         "e1",
		EntityType: &authorization.Entity_EmailAddress{EmailAddress: "alice@example.com"},
	}
	result, err := s.GetEntityAttributes(context.Background(), entity)
	require.NoError(t, err)
	assert.Empty(t, result, "should return empty when no entitlement matches the requested entity ID")
}

func TestGetEntityAttributes_ServiceError(t *testing.T) {
	authzClient := &mockDiscoveryAuthzClient{
		getEntitlementsFunc: func(_ context.Context, _ *authorization.GetEntitlementsRequest) (*authorization.GetEntitlementsResponse, error) {
			return nil, errors.New("auth service unavailable")
		},
	}
	s := newDiscoverySDK(nil, authzClient)

	entity := &authorization.Entity{
		Id:         "e1",
		EntityType: &authorization.Entity_Uuid{Uuid: "550e8400-e29b-41d4-a716-446655440000"},
	}
	_, err := s.GetEntityAttributes(context.Background(), entity)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "getting entity attributes")
	assert.Contains(t, err.Error(), "auth service unavailable")
}

// --- ValidateAttributeValue tests ---

func TestValidateAttributeValue_ValidAndExists(t *testing.T) {
	fqn := "https://example.com/attr/level/value/high"
	attrClient := &mockDiscoveryAttributesClient{
		getAttributeValuesByFqnsFunc: func(_ context.Context, _ *attributes.GetAttributeValuesByFqnsRequest) (*attributes.GetAttributeValuesByFqnsResponse, error) {
			return &attributes.GetAttributeValuesByFqnsResponse{FqnAttributeValues: fqnMap(fqn)}, nil
		},
	}
	s := newDiscoverySDK(attrClient, nil)

	err := s.ValidateAttributeValue(context.Background(), fqn)
	require.NoError(t, err)
}

func TestValidateAttributeValue_ValidButMissing(t *testing.T) {
	fqn := "https://example.com/attr/level/value/nonexistent"
	attrClient := &mockDiscoveryAttributesClient{
		getAttributeValuesByFqnsFunc: func(_ context.Context, _ *attributes.GetAttributeValuesByFqnsRequest) (*attributes.GetAttributeValuesByFqnsResponse, error) {
			return &attributes.GetAttributeValuesByFqnsResponse{FqnAttributeValues: fqnMap()}, nil
		},
	}
	s := newDiscoverySDK(attrClient, nil)

	err := s.ValidateAttributeValue(context.Background(), fqn)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrAttributeNotFound)
}

func TestValidateAttributeValue_InvalidFormat(t *testing.T) {
	s := newDiscoverySDK(nil, nil)

	err := s.ValidateAttributeValue(context.Background(), "bad-fqn-format")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid attribute value FQN")
}
