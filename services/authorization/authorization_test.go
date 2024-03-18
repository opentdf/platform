package authorization_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	attr "github.com/opentdf/platform/protocol/go/policy/attributes"
	authorizationSvc "github.com/opentdf/platform/services/authorization"
	"github.com/stretchr/testify/assert"
)

var entitlementsResponse authorization.GetEntitlementsResponse
var getAttributesByValueFqnsResponse attributes.GetAttributeValuesByFqnsResponse

var MockRetrieveAttributeDefinitions = func(ctx context.Context, ra *authorization.ResourceAttribute, as authorizationSvc.AuthorizationService) (*attr.GetAttributeValuesByFqnsResponse, error) {
	fmt.Print("Using mocked GetAttributeValuesByFqns")
	return &getAttributesByValueFqnsResponse, nil
}

var MockRetrieveEntitlements = func(ctx context.Context, req *authorization.GetEntitlementsRequest, as authorizationSvc.AuthorizationService) (*authorization.GetEntitlementsResponse, error) {
	fmt.Print("Using mocked GetEntitlements")
	return &entitlementsResponse, nil
}

func TestGetDecisionsAllOfPass(t *testing.T) {
	logLevel := &slog.LevelVar{} // INFO
	logLevel.Set(slog.LevelDebug)

	opts := &slog.HandlerOptions{
		Level: logLevel,
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, opts))

	slog.SetDefault(logger)

	authorizationSvc.RetrieveAttributeDefinitions = MockRetrieveAttributeDefinitions
	authorizationSvc.RetrieveEntitlements = MockRetrieveEntitlements
	// set entitlementsResponse and getAttributesByValueFqnsResponse
	entitlementsResponse = authorization.GetEntitlementsResponse{Entitlements: []*authorization.EntityEntitlements{
		{
			EntityId:    "e1",
			AttributeId: []string{"http://www.example.org/attr/foo/value/value1"},
		}}}
	attrDef := policy.Attribute{
		Name: "foo",
		Namespace: &policy.Namespace{
			Name: "http://www.example.org",
		},
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
		Values: []*policy.Value{
			{
				Value: "value1",
			},
			{
				Value: "value2",
			},
		},
	}
	getAttributesByValueFqnsResponse = attributes.GetAttributeValuesByFqnsResponse{FqnAttributeValues: map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{
		"http://www.example.org/attr/foo/value/value1": {
			Attribute: &attrDef,
			Value:     &policy.Value{},
		}}}

	// set the request
	req := authorization.GetDecisionsRequest{DecisionRequests: []*authorization.DecisionRequest{
		{Actions: []*policy.Action{},
			EntityChains: []*authorization.EntityChain{
				{Id: "ec1",
					Entities: []*authorization.Entity{
						{Id: "e1", EntityType: &authorization.Entity_UserName{UserName: "bob.smith"}},
					}},
			},
			ResourceAttributes: []*authorization.ResourceAttribute{
				{AttributeFqns: []string{"http://www.example.org/attr/foo/value/value1"}},
			},
		},
	}}

	as := authorizationSvc.AuthorizationService{}
	var ctxb = context.Background()

	resp, err := as.GetDecisions(ctxb, &req)

	assert.Nil(t, err)
	assert.NotNil(t, resp)

	// some asserts about resp
	fmt.Print(resp.String())
	assert.Equal(t, len(resp.DecisionResponses), 1)
	assert.Equal(t, resp.DecisionResponses[0].Decision, authorization.DecisionResponse_DECISION_PERMIT)
}

func TestGetDecisionsAllOfFail(t *testing.T) {
	logLevel := &slog.LevelVar{} // INFO
	logLevel.Set(slog.LevelDebug)

	opts := &slog.HandlerOptions{
		Level: logLevel,
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, opts))

	slog.SetDefault(logger)

	authorizationSvc.RetrieveAttributeDefinitions = MockRetrieveAttributeDefinitions
	authorizationSvc.RetrieveEntitlements = MockRetrieveEntitlements

	// set entitlementsResponse and getAttributesByValueFqnsResponse
	entitlementsResponse = authorization.GetEntitlementsResponse{Entitlements: []*authorization.EntityEntitlements{
		{
			EntityId:    "e1",
			AttributeId: []string{"http://www.example.org/attr/foo/value/value1"},
		}}}
	attrDef := policy.Attribute{
		Name: "foo",
		Namespace: &policy.Namespace{
			Name: "http://www.example.org",
		},
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
		Values: []*policy.Value{
			{
				Value: "value1",
			},
			{
				Value: "value2",
			},
		},
	}
	getAttributesByValueFqnsResponse = attributes.GetAttributeValuesByFqnsResponse{FqnAttributeValues: map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{
		"http://www.example.org/attr/foo/value/value1": {
			Attribute: &attrDef,
			Value:     &policy.Value{},
		}}}

	// set the request
	req := authorization.GetDecisionsRequest{DecisionRequests: []*authorization.DecisionRequest{
		{Actions: []*policy.Action{},
			EntityChains: []*authorization.EntityChain{
				{Id: "ec1",
					Entities: []*authorization.Entity{
						{Id: "e1", EntityType: &authorization.Entity_UserName{UserName: "bob.smith"}},
					}},
			},
			ResourceAttributes: []*authorization.ResourceAttribute{
				{AttributeFqns: []string{"http://www.example.org/attr/foo/value/value1", "http://www.example.org/attr/foo/value/value2"}},
			},
		},
	}}

	as := authorizationSvc.AuthorizationService{}
	var ctxb = context.Background()

	resp, err := as.GetDecisions(ctxb, &req)

	assert.Nil(t, err)
	assert.NotNil(t, resp)

	// some asserts about resp
	fmt.Print(resp.String())
	assert.Equal(t, len(resp.DecisionResponses), 1)
	assert.Equal(t, resp.DecisionResponses[0].Decision, authorization.DecisionResponse_DECISION_DENY)
}
