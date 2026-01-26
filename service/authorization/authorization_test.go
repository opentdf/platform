package authorization

import (
	"errors"
	"log/slog"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/trace/noop"

	"connectrpc.com/connect"
	"github.com/open-policy-agent/opa/rego"
	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/policy"
	attr "github.com/opentdf/platform/protocol/go/policy/attributes"
	otdf "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

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
		EntityRepresentations: []*entityresolution.EntityRepresentation{
			{
				OriginalId: "e1",
				AdditionalProps: []*structpb.Struct{
					userStruct,
				},
			},
		},
	}

	testrego := rego.New(
		rego.Query("data.example.p"),
		rego.Module("example.rego",
			`package example
			p = {"e1":["https://www.example.org/attr/foo/value/value1"]} { true }`,
		))

	// Run evaluation.
	prepared, err := testrego.PrepareForEval(t.Context())
	require.NoError(t, err)

	// set the request
	req := connect.Request[authorization.GetDecisionsRequest]{
		Msg: &authorization.GetDecisionsRequest{
			DecisionRequests: []*authorization.DecisionRequest{
				{
					Actions: []*policy.Action{},
					EntityChains: []*authorization.EntityChain{
						{
							Id: "ec1",
							Entities: []*authorization.Entity{
								{Id: "e1", EntityType: &authorization.Entity_UserName{UserName: "bob.smith"}, Category: authorization.Entity_CATEGORY_SUBJECT},
							},
						},
					},
					ResourceAttributes: []*authorization.ResourceAttribute{
						{AttributeValueFqns: []string{mockFqn1}},
					},
				},
			},
		},
	}

	as := AuthorizationService{
		logger: logger,
		sdk: &otdf.SDK{
			SubjectMapping:  &mySubjectMappingClient{},
			Attributes:      &myAttributesClient{},
			EntityResoution: &myERSClient{},
		},
		eval:   prepared,
		Tracer: noop.NewTracerProvider().Tracer(""),
	}

	ctx := audit.ContextWithActorID(t.Context(), "test-actor-id")
	resp, err := as.GetDecisions(ctx, &req)

	require.NoError(t, err)
	assert.NotNil(t, resp)

	// one entitlement, one attribute value throughout
	assert.Len(t, resp.Msg.GetDecisionResponses(), 1)
	assert.Equal(t, authorization.DecisionResponse_DECISION_PERMIT, resp.Msg.GetDecisionResponses()[0].GetDecision())

	// run again with two attribute values throughout
	// set the request
	req = connect.Request[authorization.GetDecisionsRequest]{
		Msg: &authorization.GetDecisionsRequest{
			DecisionRequests: []*authorization.DecisionRequest{
				{
					Actions: []*policy.Action{},
					EntityChains: []*authorization.EntityChain{
						{
							Id: "ec1",
							Entities: []*authorization.Entity{
								{Id: "e1", EntityType: &authorization.Entity_UserName{UserName: "bob.smith"}, Category: authorization.Entity_CATEGORY_SUBJECT},
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
								{Id: "e1", EntityType: &authorization.Entity_UserName{UserName: "bob.smith"}, Category: authorization.Entity_CATEGORY_SUBJECT},
							},
						},
					},
					ResourceAttributes: []*authorization.ResourceAttribute{
						{AttributeValueFqns: []string{mockFqn1, mockFqn2}},
					},
				},
			},
		},
	}
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
	prepared, err = testrego.PrepareForEval(t.Context())
	require.NoError(t, err)

	as.eval = prepared

	resp, err = as.GetDecisions(ctx, &req)
	require.NoError(t, err)
	assert.Len(t, resp.Msg.GetDecisionResponses(), 2)
	assert.Equal(t, authorization.DecisionResponse_DECISION_PERMIT, resp.Msg.GetDecisionResponses()[0].GetDecision())
	assert.Equal(t, authorization.DecisionResponse_DECISION_PERMIT, resp.Msg.GetDecisionResponses()[1].GetDecision())
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
		EntityRepresentations: []*entityresolution.EntityRepresentation{
			{
				OriginalId: "e1",
				AdditionalProps: []*structpb.Struct{
					userStruct,
				},
			},
		},
	}

	// set the request
	req := connect.Request[authorization.GetDecisionsRequest]{
		Msg: &authorization.GetDecisionsRequest{
			DecisionRequests: []*authorization.DecisionRequest{
				{
					Actions: []*policy.Action{},
					EntityChains: []*authorization.EntityChain{
						{
							Id: "ec1",
							Entities: []*authorization.Entity{
								{Id: "e1", EntityType: &authorization.Entity_UserName{UserName: "bob.smith"}, Category: authorization.Entity_CATEGORY_SUBJECT},
							},
						},
					},
					ResourceAttributes: []*authorization.ResourceAttribute{
						{AttributeValueFqns: []string{mockFqn1, mockFqn2}},
					},
				},
			},
		},
	}

	testrego := rego.New(
		rego.Query("data.example.p"),
		rego.Module("example.rego",
			`package example
			p = {"e1": ["https://www.example.org/attr/foo/value/value1"]} { true }`,
		))

	// Run evaluation.
	prepared, err := testrego.PrepareForEval(t.Context())
	require.NoError(t, err)

	as := AuthorizationService{
		logger: logger,
		sdk: &otdf.SDK{
			SubjectMapping:  &mySubjectMappingClient{},
			Attributes:      &myAttributesClient{},
			EntityResoution: &myERSClient{},
		},
		eval:   prepared,
		Tracer: noop.NewTracerProvider().Tracer(""),
	}

	ctx := audit.ContextWithActorID(t.Context(), "test-actor-id")
	resp, err := as.GetDecisions(ctx, &req)

	require.NoError(t, err)
	assert.NotNil(t, resp)

	// NOTE: there should be two decision responses, one for each data attribute value, but authorization service
	// only responds with one permit/deny at the moment
	// entitlements only contain the first FQN, so we have a deny decision
	as.logger.Debug("response", slog.String("response", resp.Msg.String()))
	assert.Len(t, resp.Msg.GetDecisionResponses(), 1)
	assert.Equal(t, authorization.DecisionResponse_DECISION_DENY, resp.Msg.GetDecisionResponses()[0].GetDecision())
}

// Subject entitled and environment entity not entitled -- still pass
func Test_GetDecisionsAllOfWithEnvironmental_Pass(t *testing.T) {
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
		EntityRepresentations: []*entityresolution.EntityRepresentation{
			{
				OriginalId: "e1",
				AdditionalProps: []*structpb.Struct{
					userStruct,
				},
			},
		},
	}

	testrego := rego.New(
		rego.Query("data.example.p"),
		rego.Module("example.rego",
			`package example
			p = {"e2":["https://www.example.org/attr/foo/value/value1"], "e1":[]} { true }`,
		))

	// Run evaluation.
	prepared, err := testrego.PrepareForEval(t.Context())
	require.NoError(t, err)

	// set the request
	req := connect.Request[authorization.GetDecisionsRequest]{
		Msg: &authorization.GetDecisionsRequest{
			DecisionRequests: []*authorization.DecisionRequest{
				{
					Actions: []*policy.Action{},
					EntityChains: []*authorization.EntityChain{
						{
							Id: "ec1",
							Entities: []*authorization.Entity{
								{Id: "e1", EntityType: &authorization.Entity_ClientId{ClientId: "opentdf"}, Category: authorization.Entity_CATEGORY_ENVIRONMENT},
								{Id: "e2", EntityType: &authorization.Entity_UserName{UserName: "bob.smith"}, Category: authorization.Entity_CATEGORY_SUBJECT},
							},
						},
					},
					ResourceAttributes: []*authorization.ResourceAttribute{
						{AttributeValueFqns: []string{mockFqn1}},
					},
				},
			},
		},
	}

	as := AuthorizationService{
		logger: logger,
		sdk: &otdf.SDK{
			SubjectMapping:  &mySubjectMappingClient{},
			Attributes:      &myAttributesClient{},
			EntityResoution: &myERSClient{},
		},
		eval:   prepared,
		Tracer: noop.NewTracerProvider().Tracer(""),
	}

	ctx := audit.ContextWithActorID(t.Context(), "test-actor-id")
	resp, err := as.GetDecisions(ctx, &req)

	require.NoError(t, err)
	assert.NotNil(t, resp)

	// one entitlement, one attribute value throughout
	assert.Len(t, resp.Msg.GetDecisionResponses(), 1)
	assert.Equal(t, authorization.DecisionResponse_DECISION_PERMIT, resp.Msg.GetDecisionResponses()[0].GetDecision())
}

// Subject not entitled and environment entity entitled -- still fail
func Test_GetDecisionsAllOfWithEnvironmental_Fail(t *testing.T) {
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
		EntityRepresentations: []*entityresolution.EntityRepresentation{
			{
				OriginalId: "e1",
				AdditionalProps: []*structpb.Struct{
					userStruct,
				},
			},
		},
	}

	testrego := rego.New(
		rego.Query("data.example.p"),
		rego.Module("example.rego",
			`package example
			p = {"e2":["https://www.example.org/attr/foo/value/value1"], "e1":[]} { true }`,
		))

	// Run evaluation.
	prepared, err := testrego.PrepareForEval(t.Context())
	require.NoError(t, err)

	// set the request
	req := connect.Request[authorization.GetDecisionsRequest]{
		Msg: &authorization.GetDecisionsRequest{
			DecisionRequests: []*authorization.DecisionRequest{
				{
					Actions: []*policy.Action{},
					EntityChains: []*authorization.EntityChain{
						{
							Id: "ec1",
							Entities: []*authorization.Entity{
								{Id: "e2", EntityType: &authorization.Entity_ClientId{ClientId: "opentdf"}, Category: authorization.Entity_CATEGORY_ENVIRONMENT},
								{Id: "e1", EntityType: &authorization.Entity_UserName{UserName: "bob.smith"}, Category: authorization.Entity_CATEGORY_SUBJECT},
							},
						},
					},
					ResourceAttributes: []*authorization.ResourceAttribute{
						{AttributeValueFqns: []string{mockFqn1}},
					},
				},
			},
		},
	}

	as := AuthorizationService{
		logger: logger,
		sdk: &otdf.SDK{
			SubjectMapping:  &mySubjectMappingClient{},
			Attributes:      &myAttributesClient{},
			EntityResoution: &myERSClient{},
		},
		eval:   prepared,
		Tracer: noop.NewTracerProvider().Tracer(""),
	}

	ctx := audit.ContextWithActorID(t.Context(), "test-actor-id")
	resp, err := as.GetDecisions(ctx, &req)

	require.NoError(t, err)
	assert.NotNil(t, resp)

	// one entitlement, one attribute value throughout
	assert.Len(t, resp.Msg.GetDecisionResponses(), 1)
	assert.Equal(t, authorization.DecisionResponse_DECISION_DENY, resp.Msg.GetDecisionResponses()[0].GetDecision())
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
		EntityRepresentations: []*entityresolution.EntityRepresentation{
			{
				OriginalId: "e1",
				AdditionalProps: []*structpb.Struct{
					userStruct,
				},
			},
		},
	}

	rego := rego.New(
		rego.Query("data.example.p"),
		rego.Module("example.rego",
			`package example
			p = {"e1":["https://www.example.org/attr/foo/value/value1"]} { true }`,
		))

	// Run evaluation.
	prepared, err := rego.PrepareForEval(t.Context())
	require.NoError(t, err)

	as := AuthorizationService{
		logger: logger,
		sdk: &otdf.SDK{
			SubjectMapping:  &mySubjectMappingClient{},
			Attributes:      &myAttributesClient{},
			EntityResoution: &myERSClient{},
		},
		eval:   prepared,
		Tracer: noop.NewTracerProvider().Tracer(""),
	}

	req := connect.Request[authorization.GetEntitlementsRequest]{
		Msg: &authorization.GetEntitlementsRequest{
			Entities: []*authorization.Entity{{Id: "e1", EntityType: &authorization.Entity_ClientId{ClientId: "testclient"}, Category: authorization.Entity_CATEGORY_ENVIRONMENT}},
			Scope:    &authorization.ResourceAttribute{AttributeValueFqns: []string{"https://www.example.org/attr/foo/value/value1"}},
		},
	}

	resp, err := as.GetEntitlements(t.Context(), &req)

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Len(t, resp.Msg.GetEntitlements(), 1)
	assert.Equal(t, "e1", resp.Msg.GetEntitlements()[0].GetEntityId())
	assert.Equal(t, []string{"https://www.example.org/attr/foo/value/value1"}, resp.Msg.GetEntitlements()[0].GetAttributeValueFqns())
}

func Test_GetEntitlementsFqnCasing(t *testing.T) {
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
	listAttributeResp.Attributes = []*policy.Attribute{&attrDef}
	userRepresentation := map[string]interface{}{
		"A": "B",
		"C": "D",
	}
	userStruct, _ := structpb.NewStruct(userRepresentation)
	resolveEntitiesResp = entityresolution.ResolveEntitiesResponse{
		EntityRepresentations: []*entityresolution.EntityRepresentation{
			{
				OriginalId: "e1",
				AdditionalProps: []*structpb.Struct{
					userStruct,
				},
			},
		},
	}

	rego := rego.New(
		rego.Query("data.example.p"),
		rego.Module("example.rego",
			`package example
			p = {"e1":["https://www.example.org/attr/foo/value/value1"]} { true }`,
		))

	// Run evaluation.
	prepared, err := rego.PrepareForEval(t.Context())
	require.NoError(t, err)

	as := AuthorizationService{
		logger: logger,
		sdk: &otdf.SDK{
			SubjectMapping:  &mySubjectMappingClient{},
			Attributes:      &myAttributesClient{},
			EntityResoution: &myERSClient{},
		},
		eval:   prepared,
		Tracer: noop.NewTracerProvider().Tracer(""),
	}

	req := connect.Request[authorization.GetEntitlementsRequest]{
		Msg: &authorization.GetEntitlementsRequest{
			Entities: []*authorization.Entity{{Id: "e1", EntityType: &authorization.Entity_ClientId{ClientId: "testclient"}, Category: authorization.Entity_CATEGORY_ENVIRONMENT}},
			// Using mixed case here
			Scope: &authorization.ResourceAttribute{AttributeValueFqns: []string{"https://www.example.org/attr/foo/value/VaLuE1"}},
		},
	}

	for fqn := range makeScopeMap(req.Msg.GetScope()) {
		assert.Equal(t, fqn, strings.ToLower(fqn))
	}

	resp, err := as.GetEntitlements(t.Context(), &req)

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Len(t, resp.Msg.GetEntitlements(), 1)
	assert.Equal(t, "e1", resp.Msg.GetEntitlements()[0].GetEntityId())
	assert.Equal(t, []string{"https://www.example.org/attr/foo/value/value1"}, resp.Msg.GetEntitlements()[0].GetAttributeValueFqns())
}

func Test_GetEntitlements_HandlesPagination(t *testing.T) {
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
	listAttributeResp.Attributes = []*policy.Attribute{&attrDef}
	userRepresentation := map[string]interface{}{
		"A": "B",
		"C": "D",
	}
	userStruct, _ := structpb.NewStruct(userRepresentation)
	resolveEntitiesResp = entityresolution.ResolveEntitiesResponse{
		EntityRepresentations: []*entityresolution.EntityRepresentation{
			{
				OriginalId: "e1",
				AdditionalProps: []*structpb.Struct{
					userStruct,
				},
			},
		},
	}

	rego := rego.New(
		rego.Query("data.example.p"),
		rego.Module("example.rego",
			`package example
			p = {"e1":["https://www.example.org/attr/foo/value/value1"]} { true }`,
		))

	// Run evaluation.
	prepared, err := rego.PrepareForEval(t.Context())
	require.NoError(t, err)

	as := AuthorizationService{
		logger: logger,
		sdk: &otdf.SDK{
			SubjectMapping:  &paginatedMockSubjectMappingClient{},
			Attributes:      &paginatedMockAttributesClient{},
			EntityResoution: &myERSClient{},
		},
		eval:   prepared,
		Tracer: noop.NewTracerProvider().Tracer(""),
	}

	req := connect.Request[authorization.GetEntitlementsRequest]{
		Msg: &authorization.GetEntitlementsRequest{
			Entities: []*authorization.Entity{{Id: "e1", EntityType: &authorization.Entity_ClientId{ClientId: "testclient"}, Category: authorization.Entity_CATEGORY_ENVIRONMENT}},
			// Using mixed case here
			Scope: &authorization.ResourceAttribute{AttributeValueFqns: []string{"https://www.example.org/attr/foo/value/VaLuE1"}},
		},
	}

	for fqn := range makeScopeMap(req.Msg.GetScope()) {
		assert.Equal(t, fqn, strings.ToLower(fqn))
	}

	resp, err := as.GetEntitlements(t.Context(), &req)

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Len(t, resp.Msg.GetEntitlements(), 1)
	assert.Equal(t, "e1", resp.Msg.GetEntitlements()[0].GetEntityId())
	assert.Equal(t, []string{"https://www.example.org/attr/foo/value/value1"}, resp.Msg.GetEntitlements()[0].GetAttributeValueFqns())

	// paginated successfully
	assert.Equal(t, 2, smListCallCount)
	assert.Zero(t, smPaginationOffset)
	assert.Equal(t, 2, attrListCallCount)
	assert.Zero(t, attrPaginationOffset)
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
		EntityRepresentations: []*entityresolution.EntityRepresentation{
			{
				OriginalId: "e1",
				AdditionalProps: []*structpb.Struct{
					userStruct,
				},
			},
		},
	}

	rego := rego.New(
		rego.Query("data.example.p"),
		rego.Module("example.rego",
			`package example
			p = {"e1":["https://www.example.org/attr/foo/value/value1"]} { true }`,
		))

	// Run evaluation.
	prepared, err := rego.PrepareForEval(t.Context())
	require.NoError(t, err)
	as := AuthorizationService{
		logger: logger,
		sdk: &otdf.SDK{
			SubjectMapping:  &mySubjectMappingClient{},
			Attributes:      &myAttributesClient{},
			EntityResoution: &myERSClient{},
		},
		eval:   prepared,
		Tracer: noop.NewTracerProvider().Tracer(""),
	}

	withHierarchy := true
	req := connect.Request[authorization.GetEntitlementsRequest]{
		Msg: &authorization.GetEntitlementsRequest{
			Entities:                   []*authorization.Entity{{Id: "e1", EntityType: &authorization.Entity_ClientId{ClientId: "testclient"}, Category: authorization.Entity_CATEGORY_ENVIRONMENT}},
			Scope:                      &authorization.ResourceAttribute{AttributeValueFqns: []string{"https://www.example.org/attr/foo/value/value1"}},
			WithComprehensiveHierarchy: &withHierarchy,
		},
	}

	resp, err := as.GetEntitlements(t.Context(), &req)

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Len(t, resp.Msg.GetEntitlements(), 1)
	assert.Equal(t, "e1", resp.Msg.GetEntitlements()[0].GetEntityId())
	assert.Equal(t, []string{"https://www.example.org/attr/foo/value/value1", "https://www.example.org/attr/foo/value/value2"}, resp.Msg.GetEntitlements()[0].GetAttributeValueFqns())
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

func Test_GetDecisions_RA_FQN_Edge_Cases(t *testing.T) {
	////////////////////// SETUP //////////////////////
	logger := logger.CreateTestLogger()

	listAttributeResp = attr.ListAttributesResponse{}

	userRepresentation := map[string]interface{}{
		"A": "B",
		"C": "D",
	}
	userStruct, _ := structpb.NewStruct(userRepresentation)
	resolveEntitiesResp = entityresolution.ResolveEntitiesResponse{
		EntityRepresentations: []*entityresolution.EntityRepresentation{
			{
				OriginalId: "e1",
				AdditionalProps: []*structpb.Struct{
					userStruct,
				},
			},
		},
	}

	testrego := rego.New(
		rego.Query("data.example.p"),
		rego.Module("example.rego",
			`package example
			p = {"e1":[]} { true }`,
		))

	// Run evaluation.
	prepared, err := testrego.PrepareForEval(t.Context())
	require.NoError(t, err)

	as := AuthorizationService{
		logger: logger,
		sdk: &otdf.SDK{
			SubjectMapping:  &mySubjectMappingClient{},
			Attributes:      &myAttributesClient{},
			EntityResoution: &myERSClient{},
		},
		eval:   prepared,
		Tracer: noop.NewTracerProvider().Tracer(""),
	}

	///////////// TEST1: Only empty string /////////////

	// should not hit get attributes by value fqns
	getAttributesByValueFqnsResponse = attr.GetAttributeValuesByFqnsResponse{}
	errGetAttributesByValueFqns = errors.New("should not hit")

	// set the request
	req := connect.Request[authorization.GetDecisionsRequest]{
		Msg: &authorization.GetDecisionsRequest{
			DecisionRequests: []*authorization.DecisionRequest{
				{
					Actions: []*policy.Action{},
					EntityChains: []*authorization.EntityChain{
						{
							Id: "ec1",
							Entities: []*authorization.Entity{
								{Id: "e1", EntityType: &authorization.Entity_UserName{UserName: "bob.smith"}, Category: authorization.Entity_CATEGORY_SUBJECT},
							},
						},
					},
					ResourceAttributes: []*authorization.ResourceAttribute{
						{AttributeValueFqns: []string{""}},
					},
				},
			},
		},
	}

	ctx := audit.ContextWithActorID(t.Context(), "test-actor-id")
	resp, err := as.GetDecisions(ctx, &req)

	require.NoError(t, err)
	assert.NotNil(t, resp)

	assert.Len(t, resp.Msg.GetDecisionResponses(), 1)
	assert.Equal(t, authorization.DecisionResponse_DECISION_DENY, resp.Msg.GetDecisionResponses()[0].GetDecision())

	//////////  TEST2: FQN that doesnt exist //////////

	// will hit getAttributesByValueFqns but will get error
	getAttributesByValueFqnsResponse = attr.GetAttributeValuesByFqnsResponse{}
	errGetAttributesByValueFqns = status.Error(codes.NotFound, db.ErrTextNotFound)

	// set the request
	req = connect.Request[authorization.GetDecisionsRequest]{
		Msg: &authorization.GetDecisionsRequest{
			DecisionRequests: []*authorization.DecisionRequest{
				{
					Actions: []*policy.Action{},
					EntityChains: []*authorization.EntityChain{
						{
							Id: "ec1",
							Entities: []*authorization.Entity{
								{Id: "e1", EntityType: &authorization.Entity_UserName{UserName: "bob.smith"}, Category: authorization.Entity_CATEGORY_SUBJECT},
							},
						},
					},
					ResourceAttributes: []*authorization.ResourceAttribute{
						{AttributeValueFqns: []string{"https://example.com/attr/foo/value/doesntexist"}},
					},
				},
			},
		},
	}

	resp, err = as.GetDecisions(ctx, &req)

	require.NoError(t, err)
	assert.NotNil(t, resp)

	assert.Len(t, resp.Msg.GetDecisionResponses(), 1)
	assert.Equal(t, authorization.DecisionResponse_DECISION_DENY, resp.Msg.GetDecisionResponses()[0].GetDecision())

	////////// TEST4: FQN present but value missing //////////

	// getAttributesByFQN with allow_travesal=true. Will return an attribute definition but no attribute value (bc it doesn't exist)
	getAttributesByValueFqnsResponse = attr.GetAttributeValuesByFqnsResponse{FqnAttributeValues: map[string]*attr.GetAttributeValuesByFqnsResponse_AttributeAndValue{
		"https://example.com/attr/foo/value/doesntexist_allow_traversal": {
			Attribute: &policy.Attribute{
				AllowTraversal: wrapperspb.Bool(true),
			},
			Value: nil,
		},
	}}
	errGetAttributesByValueFqns = nil

	// set the request
	req = connect.Request[authorization.GetDecisionsRequest]{
		Msg: &authorization.GetDecisionsRequest{
			DecisionRequests: []*authorization.DecisionRequest{
				{
					Actions: []*policy.Action{},
					EntityChains: []*authorization.EntityChain{
						{
							Id: "ec1",
							Entities: []*authorization.Entity{
								{Id: "e1", EntityType: &authorization.Entity_UserName{UserName: "bob.smith"}, Category: authorization.Entity_CATEGORY_SUBJECT},
							},
						},
					},
					ResourceAttributes: []*authorization.ResourceAttribute{
						{AttributeValueFqns: []string{"https://example.com/attr/foo/value/doesntexist_allow_traversal"}},
					},
				},
			},
		},
	}

	resp, err = as.GetDecisions(ctx, &req)

	require.NoError(t, err)
	assert.NotNil(t, resp)

	assert.Len(t, resp.Msg.GetDecisionResponses(), 1)
	assert.Equal(t, authorization.DecisionResponse_DECISION_DENY, resp.Msg.GetDecisionResponses()[0].GetDecision())

	////////// TEST5: No FQNs in Resource Attribute /////////

	// should not hit get attributes by value fqns
	getAttributesByValueFqnsResponse = attr.GetAttributeValuesByFqnsResponse{}
	errGetAttributesByValueFqns = errors.New("should not hit")

	// set the request
	req = connect.Request[authorization.GetDecisionsRequest]{
		Msg: &authorization.GetDecisionsRequest{
			DecisionRequests: []*authorization.DecisionRequest{
				{
					Actions: []*policy.Action{},
					EntityChains: []*authorization.EntityChain{
						{
							Id: "ec1",
							Entities: []*authorization.Entity{
								{Id: "e1", EntityType: &authorization.Entity_UserName{UserName: "bob.smith"}, Category: authorization.Entity_CATEGORY_SUBJECT},
							},
						},
					},
					ResourceAttributes: []*authorization.ResourceAttribute{
						{ResourceAttributesId: "r1"},
					},
				},
			},
		},
	}

	resp, err = as.GetDecisions(ctx, &req)

	require.NoError(t, err)
	assert.NotNil(t, resp)

	assert.Len(t, resp.Msg.GetDecisionResponses(), 1)
	assert.Equal(t, authorization.DecisionResponse_DECISION_PERMIT, resp.Msg.GetDecisionResponses()[0].GetDecision())
}

func Test_GetDecisionsAllOf_Pass_EC_RA_Length_Mismatch(t *testing.T) {
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
	errGetAttributesByValueFqns = nil
	userRepresentation := map[string]interface{}{
		"A": "B",
		"C": "D",
	}
	userStruct, _ := structpb.NewStruct(userRepresentation)
	resolveEntitiesResp = entityresolution.ResolveEntitiesResponse{
		EntityRepresentations: []*entityresolution.EntityRepresentation{
			{
				OriginalId: "e1",
				AdditionalProps: []*structpb.Struct{
					userStruct,
				},
			},
		},
	}

	/////// TEST1: Three entity chains, one resource attribute ///////
	testrego := rego.New(
		rego.Query("data.example.p"),
		rego.Module("example.rego",
			`package example
			p = {"e1":["https://www.example.org/attr/foo/value/value1"]} { true }`,
		))

	// Run evaluation.
	prepared, err := testrego.PrepareForEval(t.Context())
	require.NoError(t, err)

	// set the request
	req := connect.Request[authorization.GetDecisionsRequest]{
		Msg: &authorization.GetDecisionsRequest{
			DecisionRequests: []*authorization.DecisionRequest{
				{
					Actions: []*policy.Action{},
					EntityChains: []*authorization.EntityChain{
						{
							Id: "ec1",
							Entities: []*authorization.Entity{
								{Id: "e1", EntityType: &authorization.Entity_UserName{UserName: "bob.smith"}, Category: authorization.Entity_CATEGORY_SUBJECT},
							},
						},
						{
							Id: "ec2",
							Entities: []*authorization.Entity{
								{Id: "e1", EntityType: &authorization.Entity_UserName{UserName: "bob.smith"}, Category: authorization.Entity_CATEGORY_SUBJECT},
							},
						},
						{
							Id: "ec3",
							Entities: []*authorization.Entity{
								{Id: "e1", EntityType: &authorization.Entity_UserName{UserName: "bob.smith"}, Category: authorization.Entity_CATEGORY_SUBJECT},
							},
						},
					},
					ResourceAttributes: []*authorization.ResourceAttribute{
						{AttributeValueFqns: []string{mockFqn1}, ResourceAttributesId: "ra1"},
					},
				},
			},
		},
	}

	as := AuthorizationService{
		logger: logger,
		sdk: &otdf.SDK{
			SubjectMapping:  &mySubjectMappingClient{},
			Attributes:      &myAttributesClient{},
			EntityResoution: &myERSClient{},
		},
		eval:   prepared,
		Tracer: noop.NewTracerProvider().Tracer(""),
	}

	ctx := audit.ContextWithActorID(t.Context(), "test-actor-id")
	resp, err := as.GetDecisions(ctx, &req)

	require.NoError(t, err)
	assert.NotNil(t, resp)

	// one entitlement, one attribute value throughout
	slog.Debug("response", slog.String("response", resp.Msg.String()))
	assert.Len(t, resp.Msg.GetDecisionResponses(), 3)
	assert.Equal(t, "ec1", resp.Msg.GetDecisionResponses()[0].GetEntityChainId())
	assert.Equal(t, "ec2", resp.Msg.GetDecisionResponses()[1].GetEntityChainId())
	assert.Equal(t, "ec3", resp.Msg.GetDecisionResponses()[2].GetEntityChainId())
	assert.Equal(t, "ra1", resp.Msg.GetDecisionResponses()[0].GetResourceAttributesId())
	assert.Equal(t, "ra1", resp.Msg.GetDecisionResponses()[1].GetResourceAttributesId())
	assert.Equal(t, "ra1", resp.Msg.GetDecisionResponses()[2].GetResourceAttributesId())
	for i := 0; i < len(resp.Msg.GetDecisionResponses()); i++ {
		assert.Equal(t, authorization.DecisionResponse_DECISION_PERMIT, resp.Msg.GetDecisionResponses()[i].GetDecision())
	}

	/////// TEST2: Three entity chain, two resource attributes ///////
	// set the request
	req = connect.Request[authorization.GetDecisionsRequest]{
		Msg: &authorization.GetDecisionsRequest{
			DecisionRequests: []*authorization.DecisionRequest{
				{
					Actions: []*policy.Action{},
					EntityChains: []*authorization.EntityChain{
						{
							Id: "ec1",
							Entities: []*authorization.Entity{
								{Id: "e1", EntityType: &authorization.Entity_UserName{UserName: "bob.smith"}, Category: authorization.Entity_CATEGORY_SUBJECT},
							},
						},
						{
							Id: "ec2",
							Entities: []*authorization.Entity{
								{Id: "e1", EntityType: &authorization.Entity_UserName{UserName: "bob.smith"}, Category: authorization.Entity_CATEGORY_SUBJECT},
							},
						},
						{
							Id: "ec3",
							Entities: []*authorization.Entity{
								{Id: "e1", EntityType: &authorization.Entity_UserName{UserName: "bob.smith"}, Category: authorization.Entity_CATEGORY_SUBJECT},
							},
						},
					},
					ResourceAttributes: []*authorization.ResourceAttribute{
						{AttributeValueFqns: []string{mockFqn1}, ResourceAttributesId: "ra1"},
						{AttributeValueFqns: []string{mockFqn2}, ResourceAttributesId: "ra2"},
					},
				},
			},
		},
	}
	attrDef.Values = append(attrDef.Values, &policy.Value{
		Value: mockAttrValue2,
	}, &policy.Value{
		Value: mockAttrValue3,
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
	prepared, err = testrego.PrepareForEval(t.Context())
	require.NoError(t, err)

	as.eval = prepared

	resp, err = as.GetDecisions(ctx, &req)
	require.NoError(t, err)
	assert.Len(t, resp.Msg.GetDecisionResponses(), 6)

	assert.Equal(t, "ec1", resp.Msg.GetDecisionResponses()[0].GetEntityChainId())
	assert.Equal(t, "ra1", resp.Msg.GetDecisionResponses()[0].GetResourceAttributesId())
	assert.Equal(t, "ec2", resp.Msg.GetDecisionResponses()[1].GetEntityChainId())
	assert.Equal(t, "ra1", resp.Msg.GetDecisionResponses()[1].GetResourceAttributesId())
	assert.Equal(t, "ec3", resp.Msg.GetDecisionResponses()[2].GetEntityChainId())
	assert.Equal(t, "ra1", resp.Msg.GetDecisionResponses()[2].GetResourceAttributesId())

	assert.Equal(t, "ec1", resp.Msg.GetDecisionResponses()[3].GetEntityChainId())
	assert.Equal(t, "ra2", resp.Msg.GetDecisionResponses()[3].GetResourceAttributesId())
	assert.Equal(t, "ec2", resp.Msg.GetDecisionResponses()[4].GetEntityChainId())
	assert.Equal(t, "ra2", resp.Msg.GetDecisionResponses()[4].GetResourceAttributesId())
	assert.Equal(t, "ec3", resp.Msg.GetDecisionResponses()[5].GetEntityChainId())
	assert.Equal(t, "ra2", resp.Msg.GetDecisionResponses()[5].GetResourceAttributesId())

	for i := 0; i < len(resp.Msg.GetDecisionResponses()); i++ {
		assert.Equal(t, authorization.DecisionResponse_DECISION_PERMIT, resp.Msg.GetDecisionResponses()[i].GetDecision())
	}

	/////// TEST3: One entity chain, three resource attributes ///////
	// set the request
	req = connect.Request[authorization.GetDecisionsRequest]{
		Msg: &authorization.GetDecisionsRequest{
			DecisionRequests: []*authorization.DecisionRequest{
				{
					Actions: []*policy.Action{},
					EntityChains: []*authorization.EntityChain{
						{
							Id: "ec1",
							Entities: []*authorization.Entity{
								{Id: "e1", EntityType: &authorization.Entity_UserName{UserName: "bob.smith"}, Category: authorization.Entity_CATEGORY_SUBJECT},
							},
						},
					},
					ResourceAttributes: []*authorization.ResourceAttribute{
						{AttributeValueFqns: []string{mockFqn1}, ResourceAttributesId: "ra1"},
						{AttributeValueFqns: []string{mockFqn2}, ResourceAttributesId: "ra2"},
						{AttributeValueFqns: []string{mockFqn3}, ResourceAttributesId: "ra3"},
					},
				},
			},
		},
	}
	attrDef.Values = append(attrDef.Values, &policy.Value{
		Value: mockAttrValue3,
	})

	getAttributesByValueFqnsResponse.FqnAttributeValues["https://www.example.org/attr/foo/value/value3"] = &attr.GetAttributeValuesByFqnsResponse_AttributeAndValue{
		Attribute: &attrDef,
		Value: &policy.Value{
			Fqn: mockFqn3,
		},
	}
	testrego = rego.New(
		rego.Query("data.example.p"),
		rego.Module("example.rego",
			`package example
			p = {"e1": ["https://www.example.org/attr/foo/value/value1", "https://www.example.org/attr/foo/value/value2", "https://www.example.org/attr/foo/value/value3"]} { true }`,
		))

	// Run evaluation.
	prepared, err = testrego.PrepareForEval(t.Context())
	require.NoError(t, err)

	as.eval = prepared

	resp, err = as.GetDecisions(ctx, &req)
	require.NoError(t, err)
	assert.Len(t, resp.Msg.GetDecisionResponses(), 3)
	assert.Equal(t, "ec1", resp.Msg.GetDecisionResponses()[0].GetEntityChainId())
	assert.Equal(t, "ec1", resp.Msg.GetDecisionResponses()[1].GetEntityChainId())
	assert.Equal(t, "ec1", resp.Msg.GetDecisionResponses()[2].GetEntityChainId())
	assert.Equal(t, "ra1", resp.Msg.GetDecisionResponses()[0].GetResourceAttributesId())
	assert.Equal(t, "ra2", resp.Msg.GetDecisionResponses()[1].GetResourceAttributesId())
	assert.Equal(t, "ra3", resp.Msg.GetDecisionResponses()[2].GetResourceAttributesId())
	for i := 0; i < len(resp.Msg.GetDecisionResponses()); i++ {
		assert.Equal(t, authorization.DecisionResponse_DECISION_PERMIT, resp.Msg.GetDecisionResponses()[i].GetDecision())
	}

	/////// TEST4: Two entity chain, three resource attributes ///////
	// set the request
	req = connect.Request[authorization.GetDecisionsRequest]{
		Msg: &authorization.GetDecisionsRequest{
			DecisionRequests: []*authorization.DecisionRequest{
				{
					Actions: []*policy.Action{},
					EntityChains: []*authorization.EntityChain{
						{
							Id: "ec1",
							Entities: []*authorization.Entity{
								{Id: "e1", EntityType: &authorization.Entity_UserName{UserName: "bob.smith"}, Category: authorization.Entity_CATEGORY_SUBJECT},
							},
						},
						{
							Id: "ec2",
							Entities: []*authorization.Entity{
								{Id: "e1", EntityType: &authorization.Entity_UserName{UserName: "bob.smith"}, Category: authorization.Entity_CATEGORY_SUBJECT},
							},
						},
					},
					ResourceAttributes: []*authorization.ResourceAttribute{
						{AttributeValueFqns: []string{mockFqn1}, ResourceAttributesId: "ra1"},
						{AttributeValueFqns: []string{mockFqn2}, ResourceAttributesId: "ra2"},
						{AttributeValueFqns: []string{mockFqn3}, ResourceAttributesId: "ra3"},
					},
				},
			},
		},
	}

	resp, err = as.GetDecisions(ctx, &req)
	require.NoError(t, err)
	assert.Len(t, resp.Msg.GetDecisionResponses(), 6)
	assert.Equal(t, "ec1", resp.Msg.GetDecisionResponses()[0].GetEntityChainId())
	assert.Equal(t, "ra1", resp.Msg.GetDecisionResponses()[0].GetResourceAttributesId())
	assert.Equal(t, "ec2", resp.Msg.GetDecisionResponses()[1].GetEntityChainId())
	assert.Equal(t, "ra1", resp.Msg.GetDecisionResponses()[1].GetResourceAttributesId())

	assert.Equal(t, "ec1", resp.Msg.GetDecisionResponses()[2].GetEntityChainId())
	assert.Equal(t, "ra2", resp.Msg.GetDecisionResponses()[2].GetResourceAttributesId())
	assert.Equal(t, "ec2", resp.Msg.GetDecisionResponses()[3].GetEntityChainId())
	assert.Equal(t, "ra2", resp.Msg.GetDecisionResponses()[3].GetResourceAttributesId())

	assert.Equal(t, "ec1", resp.Msg.GetDecisionResponses()[4].GetEntityChainId())
	assert.Equal(t, "ra3", resp.Msg.GetDecisionResponses()[4].GetResourceAttributesId())
	assert.Equal(t, "ec2", resp.Msg.GetDecisionResponses()[5].GetEntityChainId())
	assert.Equal(t, "ra3", resp.Msg.GetDecisionResponses()[5].GetResourceAttributesId())

	for i := 0; i < len(resp.Msg.GetDecisionResponses()); i++ {
		assert.Equal(t, authorization.DecisionResponse_DECISION_PERMIT, resp.Msg.GetDecisionResponses()[i].GetDecision())
	}
}

func Test_GetDecisions_Empty_EC_RA(t *testing.T) {
	////////////////////// SETUP //////////////////////
	logger := logger.CreateTestLogger()

	listAttributeResp = attr.ListAttributesResponse{}
	errGetAttributesByValueFqns = nil

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
		EntityRepresentations: []*entityresolution.EntityRepresentation{
			{
				OriginalId: "e1",
				AdditionalProps: []*structpb.Struct{
					userStruct,
				},
			},
		},
	}

	testrego := rego.New(
		rego.Query("data.example.p"),
		rego.Module("example.rego",
			`package example
			p = {"e1":[]} { true }`,
		))

	// Run evaluation.
	prepared, err := testrego.PrepareForEval(t.Context())
	require.NoError(t, err)

	as := AuthorizationService{
		logger: logger,
		sdk: &otdf.SDK{
			SubjectMapping:  &mySubjectMappingClient{},
			Attributes:      &myAttributesClient{},
			EntityResoution: &myERSClient{},
		},
		eval:   prepared,
		Tracer: noop.NewTracerProvider().Tracer(""),
	}

	///////////// Test Cases /////////////////////
	tests := []struct {
		name           string
		req            connect.Request[authorization.GetDecisionsRequest]
		numDecisions   int
		decisionResult authorization.DecisionResponse_Decision
	}{
		{
			name: "Empty Resource attributes",
			req: connect.Request[authorization.GetDecisionsRequest]{
				Msg: &authorization.GetDecisionsRequest{
					DecisionRequests: []*authorization.DecisionRequest{
						{
							Actions: []*policy.Action{},
							EntityChains: []*authorization.EntityChain{
								{
									Id: "ec1",
									Entities: []*authorization.Entity{
										{Id: "e1", EntityType: &authorization.Entity_UserName{UserName: "bob.smith"}, Category: authorization.Entity_CATEGORY_SUBJECT},
									},
								},
							},
							ResourceAttributes: []*authorization.ResourceAttribute{},
						},
					},
				},
			},
			numDecisions: 0,
		},
		{
			name: "Empty entity chains",
			req: connect.Request[authorization.GetDecisionsRequest]{
				Msg: &authorization.GetDecisionsRequest{
					DecisionRequests: []*authorization.DecisionRequest{
						{
							Actions:      []*policy.Action{},
							EntityChains: []*authorization.EntityChain{},
							ResourceAttributes: []*authorization.ResourceAttribute{
								{AttributeValueFqns: []string{mockFqn1}},
							},
						},
					},
				},
			},
			numDecisions: 0,
		},
		{
			name: "Entity Chain with empty entity list",
			req: connect.Request[authorization.GetDecisionsRequest]{
				Msg: &authorization.GetDecisionsRequest{
					DecisionRequests: []*authorization.DecisionRequest{
						{
							Actions: []*policy.Action{},
							EntityChains: []*authorization.EntityChain{
								{
									Id:       "ec1",
									Entities: []*authorization.Entity{},
								},
							},
							ResourceAttributes: []*authorization.ResourceAttribute{
								{AttributeValueFqns: []string{mockFqn1}},
							},
						},
					},
				},
			},
			numDecisions:   1,
			decisionResult: authorization.DecisionResponse_DECISION_DENY,
		},
		{
			name: "Resource attribute with empty fqn list",
			req: connect.Request[authorization.GetDecisionsRequest]{
				Msg: &authorization.GetDecisionsRequest{
					DecisionRequests: []*authorization.DecisionRequest{
						{
							Actions: []*policy.Action{},
							EntityChains: []*authorization.EntityChain{
								{
									Id: "ec1",
									Entities: []*authorization.Entity{
										{Id: "e1", EntityType: &authorization.Entity_UserName{UserName: "bob.smith"}, Category: authorization.Entity_CATEGORY_SUBJECT},
									},
								},
							},
							ResourceAttributes: []*authorization.ResourceAttribute{
								{AttributeValueFqns: []string{}},
							},
						},
					},
				},
			},
			numDecisions:   1,
			decisionResult: authorization.DecisionResponse_DECISION_PERMIT,
		},
		{
			name: "Entity Chain with empty entity list and Resource attribute with empty fqn list",
			req: connect.Request[authorization.GetDecisionsRequest]{
				Msg: &authorization.GetDecisionsRequest{
					DecisionRequests: []*authorization.DecisionRequest{
						{
							Actions: []*policy.Action{},
							EntityChains: []*authorization.EntityChain{
								{
									Id:       "ec1",
									Entities: []*authorization.Entity{},
								},
							},
							ResourceAttributes: []*authorization.ResourceAttribute{
								{AttributeValueFqns: []string{}},
							},
						},
					},
				},
			},
			numDecisions:   1,
			decisionResult: authorization.DecisionResponse_DECISION_DENY,
		},
	}

	///////////// Run tests /////////////////////
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := audit.ContextWithActorID(t.Context(), "test-actor-id")
			resp, err := as.GetDecisions(ctx, &tc.req)
			require.NoError(t, err)
			assert.NotNil(t, resp)
			assert.Len(t, resp.Msg.GetDecisionResponses(), tc.numDecisions)
			if tc.decisionResult != authorization.DecisionResponse_DECISION_UNSPECIFIED {
				assert.Equal(t, resp.Msg.GetDecisionResponses()[0].GetDecision(), tc.decisionResult)
			}
		})
	}
}
