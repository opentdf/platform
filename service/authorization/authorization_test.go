package authorization

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/policy"
	attr "github.com/opentdf/platform/protocol/go/policy/attributes"
	otdf "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/internal/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	entitlementsResponse             authorization.GetEntitlementsResponse
	getAttributesByValueFqnsResponse attr.GetAttributeValuesByFqnsResponse
	mockNamespace                    = "www.example.org"
	mockAttrName                     = "foo"
	mockAttrValue1                   = "value1"
	mockAttrValue2                   = "value2"
	mockFqn1                         = fmt.Sprintf("https://%s/attr/%s/value/%s", mockNamespace, mockAttrName, mockAttrValue1)
	mockFqn2                         = fmt.Sprintf("https://%s/attr/%s/value/%s", mockNamespace, mockAttrName, mockAttrValue2)
)

func mockRetrieveAttributeDefinitions(ctx context.Context, _ *authorization.ResourceAttribute, _ *otdf.SDK) (map[string]*attr.GetAttributeValuesByFqnsResponse_AttributeAndValue, error) {
	slog.DebugContext(ctx, "Using mocked GetAttributeValuesByFqns: "+getAttributesByValueFqnsResponse.String())
	return getAttributesByValueFqnsResponse.GetFqnAttributeValues(), nil
}

func mockRetrieveEntitlements(ctx context.Context, _ *authorization.GetEntitlementsRequest, _ *AuthorizationService) (*authorization.GetEntitlementsResponse, error) {
	slog.DebugContext(ctx, "Using mocked GetEntitlements: "+entitlementsResponse.String())
	return &entitlementsResponse, nil
}

func TestGetComprehensiveHierarchy(t *testing.T) {

	as := &AuthorizationService{
		logger: logger.CreateTestLogger(),
	}

	avf := attr.GetAttributeValuesByFqnsResponse{
		FqnAttributeValues: nil,
	}

	tests := []struct {
		name            string
		attributesMap   map[string]*policy.Attribute
		entitlement     string
		currentEntitles []string
		expectedResult  []string
	}{
		{
			name:            "NoAttributes",
			attributesMap:   map[string]*policy.Attribute{},
			entitlement:     "ent1",
			currentEntitles: []string{},
			expectedResult:  []string{},
		},
		{
			name: "OneAttribute",
			attributesMap: map[string]*policy.Attribute{
				"ent1": {
					Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
					Values: []*policy.Value{
						{Fqn: "ent1"},
						{Fqn: "ent2"},
					},
				},
				"ent0": {
					Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
					Values: []*policy.Value{
						{Fqn: "ent0v0"},
					},
				},
			},
			entitlement:     "ent1",
			currentEntitles: []string{"ent0", "ent1"},
			expectedResult:  []string{"ent0", "ent1", "ent2"},
		},
		{
			name: "MultipleAttributes",
			attributesMap: map[string]*policy.Attribute{
				"ent2": {
					Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
					Values: []*policy.Value{
						{Fqn: "ent1"},
						{Fqn: "ent2"},
						{Fqn: "ent3"},
					},
				},
				"ent0": {
					Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
					Values: []*policy.Value{
						{Fqn: "ent0v0"},
					},
				},
			},
			entitlement:     "ent2",
			currentEntitles: []string{"ent0", "ent2"},
			expectedResult:  []string{"ent0", "ent2", "ent3"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keys := []string{}

			for k := range tc.attributesMap {
				keys = append(keys, k)
			}
			result := getComprehensiveHierarchy(
				tc.attributesMap,
				&avf,
				tc.entitlement,
				as,
				tc.currentEntitles,
			)

			assert.Equal(t, tc.expectedResult, result)
		})
	}
}

func Test_GetDecisionsAllOf_Pass(t *testing.T) {
	logger := logger.CreateTestLogger()

	retrieveAttributeDefinitions = mockRetrieveAttributeDefinitions
	retrieveEntitlements = mockRetrieveEntitlements

	// set entitlementsResponse and getAttributesByValueFqnsResponse
	entitlementsResponse = authorization.GetEntitlementsResponse{Entitlements: []*authorization.EntityEntitlements{
		{
			EntityId:           "e1",
			AttributeValueFqns: []string{mockFqn1},
		},
	}}
	attrDef := policy.Attribute{
		Name: mockAttrName,
		Namespace: &policy.Namespace{
			Name: mockNamespace,
		},
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
		Values: []*policy.Value{
			{
				Value: mockAttrValue1,
			},
		},
	}
	getAttributesByValueFqnsResponse = attr.GetAttributeValuesByFqnsResponse{FqnAttributeValues: map[string]*attr.GetAttributeValuesByFqnsResponse_AttributeAndValue{
		"https://www.example.org/attr/foo/value/value1": {
			Attribute: &attrDef,
			Value: &policy.Value{
				Fqn: mockFqn1,
			},
		},
	}}

	// set the request
	req := authorization.GetDecisionsRequest{DecisionRequests: []*authorization.DecisionRequest{
		{
			Actions: []*policy.Action{},
			EntityChains: []*authorization.EntityChain{
				{
					Id: "ec1",
					Entities: []*authorization.Entity{
						{Id: "e1", EntityType: &authorization.Entity_UserName{UserName: "bob.smith"}},
					},
				},
			},
			ResourceAttributes: []*authorization.ResourceAttribute{
				{AttributeValueFqns: []string{mockFqn1}},
			},
		},
	}}

	as := AuthorizationService{logger: logger}
	retrieveEntitlements = mockRetrieveEntitlements
	ctxb := context.Background()

	resp, err := as.GetDecisions(ctxb, &req)

	require.NoError(t, err)
	assert.NotNil(t, resp)

	// one entitlement, one attribute value throughout
	slog.Debug(resp.String())
	assert.Len(t, resp.GetDecisionResponses(), 1)
	assert.Equal(t, authorization.DecisionResponse_DECISION_PERMIT, resp.GetDecisionResponses()[0].GetDecision())

	// run again with two attribute values throughout
	entitlementsResponse = authorization.GetEntitlementsResponse{Entitlements: []*authorization.EntityEntitlements{
		{
			EntityId:           "e1",
			AttributeValueFqns: []string{mockFqn1},
		},
		{
			EntityId:           "e999",
			AttributeValueFqns: []string{mockFqn1},
		},
	}}
	// set the request
	req = authorization.GetDecisionsRequest{DecisionRequests: []*authorization.DecisionRequest{
		{
			Actions: []*policy.Action{},
			EntityChains: []*authorization.EntityChain{
				{
					Id: "ec1",
					Entities: []*authorization.Entity{
						{Id: "e1", EntityType: &authorization.Entity_UserName{UserName: "bob.smith"}},
					},
				},
			},
			ResourceAttributes: []*authorization.ResourceAttribute{
				{AttributeValueFqns: []string{mockFqn1}},
			},
		},
		{
			Actions: []*policy.Action{},
			EntityChains: []*authorization.EntityChain{
				{
					Id: "ec1",
					Entities: []*authorization.Entity{
						{Id: "e1", EntityType: &authorization.Entity_UserName{UserName: "bob.smith"}},
					},
				},
			},
			ResourceAttributes: []*authorization.ResourceAttribute{
				{AttributeValueFqns: []string{mockFqn1}},
			},
		},
	}}
	attrDef.Values = append(attrDef.Values, &policy.Value{
		Value: mockAttrValue2,
	})
	getAttributesByValueFqnsResponse.FqnAttributeValues["https://www.example.org/attr/foo/value/value2"] = &attr.GetAttributeValuesByFqnsResponse_AttributeAndValue{
		Attribute: &attrDef,
		Value: &policy.Value{
			Fqn: mockFqn2,
		},
	}
	entitlementsResponse.Entitlements[0].AttributeValueFqns = []string{mockFqn1, mockFqn2}

	resp, err = as.GetDecisions(ctxb, &req)
	require.NoError(t, err)
	assert.Len(t, resp.GetDecisionResponses(), 2)
	assert.Equal(t, authorization.DecisionResponse_DECISION_DENY, resp.GetDecisionResponses()[0].GetDecision())
	assert.Equal(t, authorization.DecisionResponse_DECISION_DENY, resp.GetDecisionResponses()[1].GetDecision())
}

func Test_GetDecisions_AllOf_Fail(t *testing.T) {
	logger := logger.CreateTestLogger()

	retrieveAttributeDefinitions = mockRetrieveAttributeDefinitions
	retrieveEntitlements = mockRetrieveEntitlements

	// set entitlementsResponse and getAttributesByValueFqnsResponse
	entitlementsResponse = authorization.GetEntitlementsResponse{Entitlements: []*authorization.EntityEntitlements{
		{
			EntityId:           "e1",
			AttributeValueFqns: []string{mockFqn1},
		},
		{
			EntityId:           "e999",
			AttributeValueFqns: []string{mockFqn1},
		},
	}}
	attrDef := policy.Attribute{
		Name: mockAttrName,
		Namespace: &policy.Namespace{
			Name: mockNamespace,
		},
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
		Values: []*policy.Value{
			{
				Value: mockAttrValue1,
			},
			{
				Value: mockAttrValue2,
			},
		},
	}
	getAttributesByValueFqnsResponse = attr.GetAttributeValuesByFqnsResponse{FqnAttributeValues: map[string]*attr.GetAttributeValuesByFqnsResponse_AttributeAndValue{
		"https://www.example.org/attr/foo/value/value1": {
			Attribute: &attrDef,
			Value: &policy.Value{
				Fqn: mockFqn1,
			},
		},
		"https://www.example.org/attr/foo/value/value2": {
			Attribute: &attrDef,
			Value: &policy.Value{
				Fqn: mockFqn2,
			},
		},
	}}

	// set the request
	req := authorization.GetDecisionsRequest{DecisionRequests: []*authorization.DecisionRequest{
		{
			Actions: []*policy.Action{},
			EntityChains: []*authorization.EntityChain{
				{
					Id: "ec1",
					Entities: []*authorization.Entity{
						{Id: "e1", EntityType: &authorization.Entity_UserName{UserName: "bob.smith"}},
					},
				},
			},
			ResourceAttributes: []*authorization.ResourceAttribute{
				{AttributeValueFqns: []string{mockFqn1, mockFqn2}},
			},
		},
	}}

	as := AuthorizationService{logger: logger}
	ctxb := context.Background()

	resp, err := as.GetDecisions(ctxb, &req)

	require.NoError(t, err)
	assert.NotNil(t, resp)

	// NOTE: there should be two decision responses, one for each data attribute value, but authorization service
	// only responds with one permit/deny at the moment
	// entitlements only contain the first FQN, so we have a deny decision
	slog.Debug(resp.String())
	assert.Len(t, resp.GetDecisionResponses(), 1)
	assert.Equal(t, authorization.DecisionResponse_DECISION_DENY, resp.GetDecisionResponses()[0].GetDecision())
}
