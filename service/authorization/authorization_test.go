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

const tdfEntityResolutionClientCredentialsJwt = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI0OXRmSjByRUo4c0YzUjJ3Yi05eENHVXhYUEQ4RTZldmNsRG1hZ05EM3lBIn0.eyJleHAiOjE3MTUwOTE2MDQsImlhdCI6MTcxNTA5MTMwNCwianRpIjoiMTE3MTYzMjYtNWQyNS00MjlmLWFjMDItNmU0MjE2OWFjMGJhIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4ODg4L2F1dGgvcmVhbG1zL29wZW50ZGYiLCJhdWQiOlsiaHR0cDovL2xvY2FsaG9zdDo4ODg4IiwicmVhbG0tbWFuYWdlbWVudCIsImFjY291bnQiXSwic3ViIjoiOTljOWVlZDItOTM1Ni00ZjE2LWIwODQtZTgyZDczZjViN2QyIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoidGRmLWVudGl0eS1yZXNvbHV0aW9uIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW9wZW50ZGYiLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsicmVhbG0tbWFuYWdlbWVudCI6eyJyb2xlcyI6WyJ2aWV3LXVzZXJzIiwidmlldy1jbGllbnRzIiwicXVlcnktY2xpZW50cyIsInF1ZXJ5LWdyb3VwcyIsInF1ZXJ5LXVzZXJzIl19LCJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6InByb2ZpbGUgZW1haWwiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImNsaWVudEhvc3QiOiIxOTIuMTY4LjI0MC4xIiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LXRkZi1lbnRpdHktcmVzb2x1dGlvbiIsImNsaWVudEFkZHJlc3MiOiIxOTIuMTY4LjI0MC4xIiwiY2xpZW50X2lkIjoidGRmLWVudGl0eS1yZXNvbHV0aW9uIn0.h29QLo-QvIc67KKqU_e1-x6G_o5YQccOyW9AthMdB7xhn9C1dBrcScytaWq1RfETPmnM8MXGezqN4OpXrYr-zbkHhq9ha0Ib-M1VJXNgA5sbgKW9JxGQyudmYPgn4fimDCJtAsXo7C-e3mYNm6DJS0zhGQ3msmjLTcHmIPzWlj7VjtPgKhYV75b7yr_yZNBdHjf3EZqfynU2sL8bKa1w7DYDNQve7ThtD4MeKLiuOQHa3_23dECs_ptvPVks7pLGgRKfgGHBC-KQuopjtxIhwkz2vOWRzugDl0aBJMHfwBajYhgZ2YRlV9dqSxmy8BOj4OEXuHbiyfIpY0rCRpSrGg"

func mockRetrieveAttributeDefinitions(ctx context.Context, _ *authorization.ResourceAttribute, _ *otdf.SDK) (map[string]*attr.GetAttributeValuesByFqnsResponse_AttributeAndValue, error) {
	slog.DebugContext(ctx, "Using mocked GetAttributeValuesByFqns: "+getAttributesByValueFqnsResponse.String())
	return getAttributesByValueFqnsResponse.GetFqnAttributeValues(), nil
}

func mockRetrieveEntitlements(ctx context.Context, _ *authorization.GetEntitlementsRequest, _ *AuthorizationService) (*authorization.GetEntitlementsResponse, error) {
	slog.DebugContext(ctx, "Using mocked GetEntitlements: "+entitlementsResponse.String())
	return &entitlementsResponse, nil
}

func createTestLogger() (*logger.Logger, error) {
	logger, err := logger.NewLogger(logger.Config{Level: "debug", Output: "stdout", Type: "json"})
	if err != nil {
		return nil, err
	}
	return logger, nil
}

func Test_GetDecisionsAllOf_Pass(t *testing.T) {
	logger, err := createTestLogger()
	require.NoError(t, err)

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
	logger, err := createTestLogger()
	require.NoError(t, err)

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
