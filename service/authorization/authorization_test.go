package authorization

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/rego"
	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/policy"
	attr "github.com/opentdf/platform/protocol/go/policy/attributes"
	sm "github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	otdf "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
)

var (
	getAttributesByValueFqnsResponse attr.GetAttributeValuesByFqnsResponse
	listAttributeResp                attr.ListAttributesResponse
	listSubjectMappings              sm.ListSubjectMappingsResponse
	createEntityChainResp            entityresolution.CreateEntityChainFromJwtResponse
	resolveEntitiesResp              entityresolution.ResolveEntitiesResponse
	mockNamespace                    = "www.example.org"
	mockAttrName                     = "foo"
	mockAttrValue1                   = "value1"
	mockAttrValue2                   = "value2"
	mockFqn1                         = fmt.Sprintf("https://%s/attr/%s/value/%s", mockNamespace, mockAttrName, mockAttrValue1)
	mockFqn2                         = fmt.Sprintf("https://%s/attr/%s/value/%s", mockNamespace, mockAttrName, mockAttrValue2)
)

type myAttributesClient struct {
	attr.AttributesServiceClient
}

func (*myAttributesClient) ListAttributes(_ context.Context, _ *attr.ListAttributesRequest, _ ...grpc.CallOption) (*attr.ListAttributesResponse, error) {
	return &listAttributeResp, nil
}

func (*myAttributesClient) GetAttributeValuesByFqns(_ context.Context, _ *attr.GetAttributeValuesByFqnsRequest, _ ...grpc.CallOption) (*attr.GetAttributeValuesByFqnsResponse, error) {
	return &getAttributesByValueFqnsResponse, nil
}

type myERSClient struct {
	entityresolution.EntityResolutionServiceClient
}

type mySubjectMappingClient struct {
	sm.SubjectMappingServiceClient
}

func (*mySubjectMappingClient) ListSubjectMappings(_ context.Context, _ *sm.ListSubjectMappingsRequest, _ ...grpc.CallOption) (*sm.ListSubjectMappingsResponse, error) {
	return &listSubjectMappings, nil
}

func (*myERSClient) CreateEntityChainFromJwt(_ context.Context, _ *entityresolution.CreateEntityChainFromJwtRequest, _ ...grpc.CallOption) (*entityresolution.CreateEntityChainFromJwtResponse, error) {
	return &createEntityChainResp, nil
}
func (*myERSClient) ResolveEntities(_ context.Context, _ *entityresolution.ResolveEntitiesRequest, _ ...grpc.CallOption) (*entityresolution.ResolveEntitiesResponse, error) {
	return &resolveEntitiesResp, nil
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

	listAttributeResp = attr.ListAttributesResponse{}

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
	userRepresentation := map[string]interface{}{
		"A": "B",
		"C": "D",
	}
	userStruct, _ := structpb.NewStruct(userRepresentation)
	resolveEntitiesResp = entityresolution.ResolveEntitiesResponse{
		EntityRepresentations: []*entityresolution.EntityRepresentation{{
			OriginalId: "e1",
			AdditionalProps: []*structpb.Struct{
				userStruct,
			},
		},
		},
	}

	testTokenSource := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: "AccessToken",
		Expiry:      time.Now().Add(1 * time.Hour),
	})

	ctxb := context.Background()

	testrego := rego.New(
		rego.Query("data.example.p"),
		rego.Module("example.rego",
			`package example
			p = {"e1":["https://www.example.org/attr/foo/value/value1"]} { true }`,
		))

	// Run evaluation.
	prepared, err := testrego.PrepareForEval(ctxb)
	require.NoError(t, err)

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

	as := AuthorizationService{logger: logger, sdk: &otdf.SDK{
		SubjectMapping: &mySubjectMappingClient{},
		Attributes:     &myAttributesClient{}, EntityResoution: &myERSClient{}},
		tokenSource: &testTokenSource, eval: prepared}

	resp, err := as.GetDecisions(ctxb, &req)

	require.NoError(t, err)
	assert.NotNil(t, resp)

	// one entitlement, one attribute value throughout
	slog.Debug(resp.String())
	assert.Len(t, resp.GetDecisionResponses(), 1)
	assert.Equal(t, authorization.DecisionResponse_DECISION_PERMIT, resp.GetDecisionResponses()[0].GetDecision())

	// run again with two attribute values throughout
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
				{AttributeValueFqns: []string{mockFqn1, mockFqn2}},
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
	testrego = rego.New(
		rego.Query("data.example.p"),
		rego.Module("example.rego",
			`package example
			p = {"e1": ["https://www.example.org/attr/foo/value/value1", "https://www.example.org/attr/foo/value/value2"]} { true }`,
		))

	// Run evaluation.
	prepared, err = testrego.PrepareForEval(ctxb)
	require.NoError(t, err)

	as.eval = prepared

	resp, err = as.GetDecisions(ctxb, &req)
	require.NoError(t, err)
	assert.Len(t, resp.GetDecisionResponses(), 2)
	assert.Equal(t, authorization.DecisionResponse_DECISION_PERMIT, resp.GetDecisionResponses()[0].GetDecision())
	assert.Equal(t, authorization.DecisionResponse_DECISION_PERMIT, resp.GetDecisionResponses()[1].GetDecision())
}

func Test_GetDecisions_AllOf_Fail(t *testing.T) {
	logger := logger.CreateTestLogger()

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
	userRepresentation := map[string]interface{}{
		"A": "B",
		"C": "D",
	}
	userStruct, _ := structpb.NewStruct(userRepresentation)
	resolveEntitiesResp = entityresolution.ResolveEntitiesResponse{
		EntityRepresentations: []*entityresolution.EntityRepresentation{{
			OriginalId: "e1",
			AdditionalProps: []*structpb.Struct{
				userStruct,
			},
		},
		},
	}

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

	testTokenSource := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: "AccessToken",
		Expiry:      time.Now().Add(1 * time.Hour),
	})

	ctxb := context.Background()

	testrego := rego.New(
		rego.Query("data.example.p"),
		rego.Module("example.rego",
			`package example
			p = {"e1": ["https://www.example.org/attr/foo/value/value1"]} { true }`,
		))

	// Run evaluation.
	prepared, err := testrego.PrepareForEval(ctxb)
	require.NoError(t, err)

	as := AuthorizationService{logger: logger, sdk: &otdf.SDK{
		SubjectMapping: &mySubjectMappingClient{},
		Attributes:     &myAttributesClient{}, EntityResoution: &myERSClient{}},
		tokenSource: &testTokenSource, eval: prepared}

	resp, err := as.GetDecisions(ctxb, &req)

	require.NoError(t, err)
	assert.NotNil(t, resp)

	// NOTE: there should be two decision responses, one for each data attribute value, but authorization service
	// only responds with one permit/deny at the moment
	// entitlements only contain the first FQN, so we have a deny decision
	as.logger.Debug(resp.String())
	assert.Len(t, resp.GetDecisionResponses(), 1)
	assert.Equal(t, authorization.DecisionResponse_DECISION_DENY, resp.GetDecisionResponses()[0].GetDecision())
}

func Test_GetEntitlementsSimple(t *testing.T) {
	logger := logger.CreateTestLogger()

	listAttributeResp = attr.ListAttributesResponse{}
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
	}}
	userRepresentation := map[string]interface{}{
		"A": "B",
		"C": "D",
	}
	userStruct, _ := structpb.NewStruct(userRepresentation)
	resolveEntitiesResp = entityresolution.ResolveEntitiesResponse{
		EntityRepresentations: []*entityresolution.EntityRepresentation{{
			OriginalId: "e1",
			AdditionalProps: []*structpb.Struct{
				userStruct,
			},
		},
		},
	}
	testTokenSource := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: "AccessToken",
		Expiry:      time.Now().Add(1 * time.Hour),
	})

	ctxb := context.Background()

	rego := rego.New(
		rego.Query("data.example.p"),
		rego.Module("example.rego",
			`package example
			p = {"e1":["https://www.example.org/attr/foo/value/value1"]} { true }`,
		))

	// Run evaluation.
	prepared, err := rego.PrepareForEval(ctxb)
	require.NoError(t, err)

	as := AuthorizationService{logger: logger, sdk: &otdf.SDK{
		SubjectMapping: &mySubjectMappingClient{},
		Attributes:     &myAttributesClient{}, EntityResoution: &myERSClient{}},
		tokenSource: &testTokenSource, eval: prepared}

	req := authorization.GetEntitlementsRequest{
		Entities: []*authorization.Entity{{Id: "e1", EntityType: &authorization.Entity_ClientId{ClientId: "testclient"}}},
		Scope:    &authorization.ResourceAttribute{AttributeValueFqns: []string{"https://www.example.org/attr/foo/value/value1"}},
	}

	resp, err := as.GetEntitlements(ctxb, &req)

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Len(t, resp.GetEntitlements(), 1)
	assert.Equal(t, "e1", resp.GetEntitlements()[0].GetEntityId())
	assert.Equal(t, []string{"https://www.example.org/attr/foo/value/value1"}, resp.GetEntitlements()[0].GetAttributeValueFqns())
}

func Test_GetEntitlementsWithComprehensiveHierarchy(t *testing.T) {
	logger := logger.CreateTestLogger()
	attrDef := policy.Attribute{
		Name: mockAttrName,
		Namespace: &policy.Namespace{
			Name: mockNamespace,
		},
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
		Values: []*policy.Value{
			{
				Value: mockAttrValue1,
				Fqn:   mockFqn1,
			},
			{
				Value: mockAttrValue2,
				Fqn:   mockFqn2,
			},
		},
	}
	listAttributeResp.Attributes = []*policy.Attribute{&attrDef}
	getAttributesByValueFqnsResponse = attr.GetAttributeValuesByFqnsResponse{FqnAttributeValues: map[string]*attr.GetAttributeValuesByFqnsResponse_AttributeAndValue{
		"https://www.example.org/attr/foo/value/value1": {
			Attribute: &attrDef,
			Value: &policy.Value{
				Fqn: mockFqn1,
			},
		},
	}}
	userRepresentation := map[string]interface{}{
		"A": "B",
		"C": "D",
	}
	userStruct, _ := structpb.NewStruct(userRepresentation)
	resolveEntitiesResp = entityresolution.ResolveEntitiesResponse{
		EntityRepresentations: []*entityresolution.EntityRepresentation{{
			OriginalId: "e1",
			AdditionalProps: []*structpb.Struct{
				userStruct,
			},
		},
		},
	}
	testTokenSource := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: "AccessToken",
		Expiry:      time.Now().Add(1 * time.Hour),
	})

	ctxb := context.Background()

	rego := rego.New(
		rego.Query("data.example.p"),
		rego.Module("example.rego",
			`package example
			p = {"e1":["https://www.example.org/attr/foo/value/value1"]} { true }`,
		))

	// Run evaluation.
	prepared, err := rego.PrepareForEval(ctxb)
	require.NoError(t, err)
	as := AuthorizationService{logger: logger, sdk: &otdf.SDK{
		SubjectMapping: &mySubjectMappingClient{},
		Attributes:     &myAttributesClient{}, EntityResoution: &myERSClient{}},
		tokenSource: &testTokenSource, eval: prepared}

	withHierarchy := true
	req := authorization.GetEntitlementsRequest{
		Entities:                   []*authorization.Entity{{Id: "e1", EntityType: &authorization.Entity_ClientId{ClientId: "testclient"}}},
		Scope:                      &authorization.ResourceAttribute{AttributeValueFqns: []string{"https://www.example.org/attr/foo/value/value1"}},
		WithComprehensiveHierarchy: &withHierarchy,
	}

	resp, err := as.GetEntitlements(ctxb, &req)

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Len(t, resp.GetEntitlements(), 1)
	assert.Equal(t, "e1", resp.GetEntitlements()[0].GetEntityId())
	assert.Equal(t, []string{"https://www.example.org/attr/foo/value/value1", "https://www.example.org/attr/foo/value/value2"}, resp.GetEntitlements()[0].GetAttributeValueFqns())
}

func TestFqnBuilder(t *testing.T) {
	tests := []struct {
		name           string
		n              string
		a              string
		v              string
		expectedResult string
		expectedError  error
	}{
		{
			name:           "FullFqn",
			n:              "namespace1.com",
			a:              "attribute1",
			v:              "value1",
			expectedResult: "https://namespace1.com/attr/attribute1/value/value1",
			expectedError:  nil,
		},
		{
			name:           "EmptyValue",
			n:              "namespace1.com",
			a:              "attribute1",
			v:              "",
			expectedResult: "https://namespace1.com/attr/attribute1",
			expectedError:  nil,
		},
		{
			name:           "EmptyAttribute",
			n:              "namespace1.com",
			a:              "",
			v:              "",
			expectedResult: "https://namespace1.com",
			expectedError:  nil,
		},
		{
			name:           "EmptyNamespace",
			n:              "",
			a:              "attribute1",
			v:              "value1",
			expectedResult: "",
			expectedError:  errors.New("invalid FQN, unable to build fqn"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := fqnBuilder(
				tc.n,
				tc.a,
				tc.v,
			)
			assert.Equal(t, tc.expectedResult, result)
			assert.Equal(t, tc.expectedError, err)
		})
	}
}

func TestPopulateAttrFqns(t *testing.T) {
	tests := []struct {
		name           string
		attrDefs       []*policy.Attribute
		expectedResult []*policy.Attribute
		expectedError  error
	}{
		{
			name: "OneAttributeOneValue",
			attrDefs: []*policy.Attribute{
				{
					Namespace: &policy.Namespace{Name: "namespace1.com"},
					Name:      "attribute1",
					Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
					Values: []*policy.Value{
						{Value: "value1"},
					},
				},
			},
			expectedResult: []*policy.Attribute{
				{
					Namespace: &policy.Namespace{Name: "namespace1.com"},
					Name:      "attribute1",
					Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
					Values: []*policy.Value{
						{Value: "value1", Fqn: "https://namespace1.com/attr/attribute1/value/value1"},
					},
				},
			},
			expectedError: nil,
		},
		{
			name: "OneAttributeTwoValue",
			attrDefs: []*policy.Attribute{
				{
					Namespace: &policy.Namespace{Name: "namespace1.com"},
					Name:      "attribute1",
					Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
					Values: []*policy.Value{
						{Value: "value1"}, {Value: "value2"},
					},
				},
			},
			expectedResult: []*policy.Attribute{
				{
					Namespace: &policy.Namespace{Name: "namespace1.com"},
					Name:      "attribute1",
					Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
					Values: []*policy.Value{
						{Value: "value1", Fqn: "https://namespace1.com/attr/attribute1/value/value1"},
						{Value: "value2", Fqn: "https://namespace1.com/attr/attribute1/value/value2"},
					},
				},
			},
			expectedError: nil,
		},
		{
			name: "TwoAttributeTwoValue",
			attrDefs: []*policy.Attribute{
				{
					Namespace: &policy.Namespace{Name: "namespace1.com"},
					Name:      "attribute1",
					Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
					Values: []*policy.Value{
						{Value: "value1"}, {Value: "value2"},
					},
				},
				{
					Namespace: &policy.Namespace{Name: "namespace1.com"},
					Name:      "attribute2",
					Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
					Values: []*policy.Value{
						{Value: "value1"}, {Value: "value2"},
					},
				},
			},
			expectedResult: []*policy.Attribute{
				{
					Namespace: &policy.Namespace{Name: "namespace1.com"},
					Name:      "attribute1",
					Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
					Values: []*policy.Value{
						{Value: "value1", Fqn: "https://namespace1.com/attr/attribute1/value/value1"},
						{Value: "value2", Fqn: "https://namespace1.com/attr/attribute1/value/value2"},
					},
				},
				{
					Namespace: &policy.Namespace{Name: "namespace1.com"},
					Name:      "attribute2",
					Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
					Values: []*policy.Value{
						{Value: "value1", Fqn: "https://namespace1.com/attr/attribute2/value/value1"},
						{Value: "value2", Fqn: "https://namespace1.com/attr/attribute2/value/value2"},
					},
				},
			},
			expectedError: nil,
		},
		{
			name: "ErrorFqn",
			attrDefs: []*policy.Attribute{
				{
					Namespace: &policy.Namespace{Name: ""},
					Name:      "attribute1",
					Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
					Values: []*policy.Value{
						{Value: "value1"},
					},
				},
			},
			expectedResult: nil,
			expectedError:  errors.New("invalid FQN, unable to build fqn"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := populateAttrDefValueFqns(
				tc.attrDefs,
			)
			assert.Equal(t, tc.expectedResult, result)
			assert.Equal(t, tc.expectedError, err)
		})
	}
}
