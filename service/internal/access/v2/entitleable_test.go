package access

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/sdk/sdkconnect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	otdfSDK "github.com/opentdf/platform/sdk"
)

// fakeAttributesClient embeds the interface (nil) so it satisfies AttributesServiceClient while only
// overriding GetEntitleableAttributesByFqns. Any other method call would panic, which is fine for
// tests that never invoke them.
type fakeAttributesClient struct {
	sdkconnect.AttributesServiceClient
	respFunc func(req *attrs.GetEntitleableAttributesByFqnsRequest) (*attrs.GetEntitleableAttributesByFqnsResponse, error)
	requests []*attrs.GetEntitleableAttributesByFqnsRequest
}

func (f *fakeAttributesClient) GetEntitleableAttributesByFqns(_ context.Context, req *attrs.GetEntitleableAttributesByFqnsRequest) (*attrs.GetEntitleableAttributesByFqnsResponse, error) {
	f.requests = append(f.requests, req)
	return f.respFunc(req)
}

func newSDKWithAttributes(f *fakeAttributesClient) *otdfSDK.SDK {
	return &otdfSDK.SDK{Attributes: f}
}

func TestFetchEntitleableAttributes_MapsAndDedupes(t *testing.T) {
	definitionFQN := "https://example.com/attr/classification"
	valueFQN := definitionFQN + "/value/confidential"
	sm := &policy.SubjectMapping{Id: "sm-1", AttributeValue: &policy.Value{Fqn: valueFQN}}

	fake := &fakeAttributesClient{
		respFunc: func(_ *attrs.GetEntitleableAttributesByFqnsRequest) (*attrs.GetEntitleableAttributesByFqnsResponse, error) {
			return &attrs.GetEntitleableAttributesByFqnsResponse{
				Definitions: map[string]*attrs.GetEntitleableAttributesByFqnsResponse_EntitleableDefinition{
					definitionFQN: {
						Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
						Namespace: &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"},
					},
				},
				FqnEntitleableAttributes: map[string]*attrs.GetEntitleableAttributesByFqnsResponse_EntitleableAttribute{
					valueFQN: {
						DefinitionFqn: definitionFQN,
						Value: &attrs.GetEntitleableAttributesByFqnsResponse_EntitleableValue{
							Fqn: valueFQN, ValueId: "confidential-id", SubjectMappings: []*policy.SubjectMapping{sm},
						},
					},
				},
			}, nil
		},
	}

	// Uppercase + duplicate inputs should be normalized and deduped to a single requested FQN.
	defs, sms, err := fetchEntitleableAttributes(context.Background(), newSDKWithAttributes(fake), []string{strings.ToUpper(valueFQN), valueFQN})
	require.NoError(t, err)
	require.Len(t, fake.requests, 1)
	assert.Equal(t, []string{valueFQN}, fake.requests[0].GetFqns())

	require.Len(t, defs, 1)
	assert.Equal(t, definitionFQN, defs[0].GetFqn())
	assert.Equal(t, policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, defs[0].GetRule())
	assert.Equal(t, "ns-1", defs[0].GetNamespace().GetId())
	require.Len(t, defs[0].GetValues(), 1)
	assert.Equal(t, valueFQN, defs[0].GetValues()[0].GetFqn())
	assert.Equal(t, "confidential-id", defs[0].GetValues()[0].GetId())
	// SMs are carried only in the returned slice, never on the definition's values (no double-count).
	assert.Empty(t, defs[0].GetValues()[0].GetSubjectMappings())
	require.Len(t, sms, 1)
	assert.Equal(t, "sm-1", sms[0].GetId())
}

func TestFetchEntitleableAttributes_Batches(t *testing.T) {
	definitionFQN := "https://example.com/attr/classification"
	fake := &fakeAttributesClient{
		respFunc: func(req *attrs.GetEntitleableAttributesByFqnsRequest) (*attrs.GetEntitleableAttributesByFqnsResponse, error) {
			resp := &attrs.GetEntitleableAttributesByFqnsResponse{
				Definitions: map[string]*attrs.GetEntitleableAttributesByFqnsResponse_EntitleableDefinition{
					definitionFQN: {Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF},
				},
				FqnEntitleableAttributes: make(map[string]*attrs.GetEntitleableAttributesByFqnsResponse_EntitleableAttribute),
			}
			for _, fqn := range req.GetFqns() {
				resp.FqnEntitleableAttributes[fqn] = &attrs.GetEntitleableAttributesByFqnsResponse_EntitleableAttribute{
					DefinitionFqn: definitionFQN,
					Value:         &attrs.GetEntitleableAttributesByFqnsResponse_EntitleableValue{Fqn: fqn, ValueId: fqn + "-id"},
				}
			}
			return resp, nil
		},
	}

	fqns := make([]string, maxEntitleableFQNsPerRequest+1)
	for i := range fqns {
		fqns[i] = fmt.Sprintf("%s/value/value-%03d", definitionFQN, i)
	}

	defs, _, err := fetchEntitleableAttributes(context.Background(), newSDKWithAttributes(fake), fqns)
	require.NoError(t, err)
	require.Len(t, fake.requests, 2)
	assert.Len(t, fake.requests[0].GetFqns(), maxEntitleableFQNsPerRequest)
	assert.Len(t, fake.requests[1].GetFqns(), 1)
	// All values map to the one definition.
	require.Len(t, defs, 1)
	assert.Len(t, defs[0].GetValues(), len(fqns))
}

func TestFetchEntitleableAttributes_Hierarchy(t *testing.T) {
	definitionFQN := "https://example.com/attr/clearance"
	high := definitionFQN + "/value/high"
	mid := definitionFQN + "/value/mid"
	low := definitionFQN + "/value/low"
	smHigh := &policy.SubjectMapping{Id: "sm-high", AttributeValue: &policy.Value{Fqn: high}}

	fake := &fakeAttributesClient{
		respFunc: func(_ *attrs.GetEntitleableAttributesByFqnsRequest) (*attrs.GetEntitleableAttributesByFqnsResponse, error) {
			return &attrs.GetEntitleableAttributesByFqnsResponse{
				Definitions: map[string]*attrs.GetEntitleableAttributesByFqnsResponse_EntitleableDefinition{
					definitionFQN: {
						Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
						Values: []*attrs.GetEntitleableAttributesByFqnsResponse_EntitleableValue{
							{Fqn: high, ValueId: "high-id", SubjectMappings: []*policy.SubjectMapping{smHigh}},
							{Fqn: mid, ValueId: "mid-id"},
							{Fqn: low, ValueId: "low-id"},
						},
					},
				},
				FqnEntitleableAttributes: map[string]*attrs.GetEntitleableAttributesByFqnsResponse_EntitleableAttribute{
					high: {
						DefinitionFqn: definitionFQN,
						Value:         &attrs.GetEntitleableAttributesByFqnsResponse_EntitleableValue{Fqn: high, ValueId: "high-id", SubjectMappings: []*policy.SubjectMapping{smHigh}},
					},
				},
			}, nil
		},
	}

	defs, sms, err := fetchEntitleableAttributes(context.Background(), newSDKWithAttributes(fake), []string{high})
	require.NoError(t, err)
	require.Len(t, defs, 1)
	// Ordered sibling values are populated for hierarchy definitions.
	valueFQNs := make([]string, 0, len(defs[0].GetValues()))
	for _, v := range defs[0].GetValues() {
		valueFQNs = append(valueFQNs, v.GetFqn())
	}
	assert.Equal(t, []string{high, mid, low}, valueFQNs)
	// The requested value's subject mapping is counted exactly once (from the sibling expansion).
	require.Len(t, sms, 1)
	assert.Equal(t, "sm-high", sms[0].GetId())
}

func TestFetchEntitleableAttributes_MissingFqnOmitted(t *testing.T) {
	fake := &fakeAttributesClient{
		respFunc: func(_ *attrs.GetEntitleableAttributesByFqnsRequest) (*attrs.GetEntitleableAttributesByFqnsResponse, error) {
			return &attrs.GetEntitleableAttributesByFqnsResponse{
				FqnEntitleableAttributes: map[string]*attrs.GetEntitleableAttributesByFqnsResponse_EntitleableAttribute{},
			}, nil
		},
	}

	defs, sms, err := fetchEntitleableAttributes(context.Background(), newSDKWithAttributes(fake), []string{"https://example.com/attr/classification/value/missing"})
	require.NoError(t, err)
	assert.NotNil(t, defs)
	assert.NotNil(t, sms)
	assert.Empty(t, defs)
	assert.Empty(t, sms)
}

func TestFetchEntitleableAttributes_MissingDefinitionErrors(t *testing.T) {
	valueFQN := "https://example.com/attr/classification/value/confidential"
	fake := &fakeAttributesClient{
		respFunc: func(_ *attrs.GetEntitleableAttributesByFqnsRequest) (*attrs.GetEntitleableAttributesByFqnsResponse, error) {
			return &attrs.GetEntitleableAttributesByFqnsResponse{
				FqnEntitleableAttributes: map[string]*attrs.GetEntitleableAttributesByFqnsResponse_EntitleableAttribute{
					valueFQN: {
						DefinitionFqn: "https://example.com/attr/classification",
						Value:         &attrs.GetEntitleableAttributesByFqnsResponse_EntitleableValue{Fqn: valueFQN, ValueId: "id"},
					},
				},
			}, nil
		},
	}

	defs, sms, err := fetchEntitleableAttributes(context.Background(), newSDKWithAttributes(fake), []string{valueFQN})
	require.Error(t, err)
	assert.Nil(t, defs)
	assert.Nil(t, sms)
	assert.Contains(t, err.Error(), "references missing definition")
}

func TestFetchEntitleableAttributes_AllowTraversalEmptyValueRegistersDefinition(t *testing.T) {
	definitionFQN := "https://example.com/attr/classification"
	valueFQN := definitionFQN + "/value/adhoc"
	fake := &fakeAttributesClient{
		respFunc: func(_ *attrs.GetEntitleableAttributesByFqnsRequest) (*attrs.GetEntitleableAttributesByFqnsResponse, error) {
			return &attrs.GetEntitleableAttributesByFqnsResponse{
				Definitions: map[string]*attrs.GetEntitleableAttributesByFqnsResponse_EntitleableDefinition{
					definitionFQN: {Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF},
				},
				FqnEntitleableAttributes: map[string]*attrs.GetEntitleableAttributesByFqnsResponse_EntitleableAttribute{
					// allow_traversal miss: value returned with empty identity.
					valueFQN: {DefinitionFqn: definitionFQN, Value: &attrs.GetEntitleableAttributesByFqnsResponse_EntitleableValue{}},
				},
			}, nil
		},
	}

	defs, sms, err := fetchEntitleableAttributes(context.Background(), newSDKWithAttributes(fake), []string{valueFQN})
	require.NoError(t, err)
	// Definition is registered (for direct-entitlement synthesis) but carries no concrete value.
	require.Len(t, defs, 1)
	assert.Equal(t, definitionFQN, defs[0].GetFqn())
	assert.Empty(t, defs[0].GetValues())
	assert.Empty(t, sms)
}
