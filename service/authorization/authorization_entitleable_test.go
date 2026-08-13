package authorization

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/policy"
	attr "github.com/opentdf/platform/protocol/go/policy/attributes"
	otdf "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/protobuf/types/known/structpb"
)

func resetTargetedLookupMocks(t *testing.T) {
	t.Helper()
	getEntitleableAttributesResponse = nil
	errGetAttributesByValueFqns = nil
	errMatchSubjectMappings = nil
	getEntitleableAttributesRequests = nil
	matchSubjectMappingsRequests = nil
	listAttributesCallCount = 0
	listSubjectMappingsCallCount = 0
	getAttributeValuesCallCount = 0
	t.Cleanup(func() {
		getAttributesByValueFqnsResponse = attr.GetAttributeValuesByFqnsResponse{}
		getEntitleableAttributesResponse = nil
		errGetAttributesByValueFqns = nil
		errMatchSubjectMappings = nil
		getEntitleableAttributesRequests = nil
		matchSubjectMappingsRequests = nil
		resolveEntitiesResp = entityresolution.ResolveEntitiesResponse{}
	})
}

func TestRetrieveAttributeDefinitionsMapsEntitleableResponse(t *testing.T) {
	resetTargetedLookupMocks(t)

	definitionFQN := "https://example.com/attr/classification"
	valueFQN := definitionFQN + "/value/confidential"
	lowerValueFQN := definitionFQN + "/value/public"
	subjectMapping := &policy.SubjectMapping{Id: "subject-mapping-id"}
	getEntitleableAttributesResponse = &attr.GetEntitleableAttributesByFqnsResponse{
		Definitions: map[string]*attr.GetEntitleableAttributesByFqnsResponse_EntitleableDefinition{
			definitionFQN: {
				Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
				Namespace: &policy.Namespace{Id: "namespace-id", Fqn: "https://example.com"},
				Values: []*attr.GetEntitleableAttributesByFqnsResponse_EntitleableValue{
					{Fqn: valueFQN, ValueId: "confidential-id", SubjectMappings: []*policy.SubjectMapping{subjectMapping}},
					{Fqn: lowerValueFQN, ValueId: "public-id"},
				},
			},
		},
		FqnEntitleableAttributes: map[string]*attr.GetEntitleableAttributesByFqnsResponse_EntitleableAttribute{
			valueFQN: {
				DefinitionFqn: definitionFQN,
				Value: &attr.GetEntitleableAttributesByFqnsResponse_EntitleableValue{
					Fqn: valueFQN, ValueId: "confidential-id", SubjectMappings: []*policy.SubjectMapping{subjectMapping},
				},
			},
		},
	}

	sdk := &otdf.SDK{Attributes: &myAttributesClient{}}
	mapped, err := retrieveAttributeDefinitions(t.Context(), []string{strings.ToUpper(valueFQN), valueFQN}, sdk)
	require.NoError(t, err)
	require.Len(t, mapped, 1)
	require.Len(t, getEntitleableAttributesRequests, 1)
	assert.Equal(t, []string{valueFQN}, getEntitleableAttributesRequests[0].GetFqns())
	assert.Zero(t, getAttributeValuesCallCount)

	attributeAndValue := mapped[valueFQN]
	require.NotNil(t, attributeAndValue)
	assert.Equal(t, definitionFQN, attributeAndValue.GetAttribute().GetFqn())
	assert.Equal(t, policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY, attributeAndValue.GetAttribute().GetRule())
	assert.Equal(t, "namespace-id", attributeAndValue.GetAttribute().GetNamespace().GetId())
	require.Len(t, attributeAndValue.GetAttribute().GetValues(), 2)
	assert.Equal(t, []string{valueFQN, lowerValueFQN}, []string{
		attributeAndValue.GetAttribute().GetValues()[0].GetFqn(),
		attributeAndValue.GetAttribute().GetValues()[1].GetFqn(),
	})
	assert.Equal(t, "confidential-id", attributeAndValue.GetValue().GetId())
	assert.Equal(t, valueFQN, attributeAndValue.GetValue().GetFqn())
	assert.Equal(t, "subject-mapping-id", attributeAndValue.GetValue().GetSubjectMappings()[0].GetId())
}

func TestRetrieveAttributeDefinitionsBatchesRequests(t *testing.T) {
	resetTargetedLookupMocks(t)

	definitionFQN := "https://example.com/attr/classification"
	response := &attr.GetEntitleableAttributesByFqnsResponse{
		Definitions: map[string]*attr.GetEntitleableAttributesByFqnsResponse_EntitleableDefinition{
			definitionFQN: {Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF},
		},
		FqnEntitleableAttributes: make(map[string]*attr.GetEntitleableAttributesByFqnsResponse_EntitleableAttribute),
	}
	fqns := make([]string, maxEntitleableFQNsPerRequest+1)
	for i := range fqns {
		fqns[i] = fmt.Sprintf("%s/value/value-%03d", definitionFQN, i)
		response.FqnEntitleableAttributes[fqns[i]] = &attr.GetEntitleableAttributesByFqnsResponse_EntitleableAttribute{
			DefinitionFqn: definitionFQN,
			Value:         &attr.GetEntitleableAttributesByFqnsResponse_EntitleableValue{Fqn: fqns[i], ValueId: fmt.Sprintf("value-%03d-id", i)},
		}
	}
	getEntitleableAttributesResponse = response

	mapped, err := retrieveAttributeDefinitions(t.Context(), fqns, &otdf.SDK{Attributes: &myAttributesClient{}})
	require.NoError(t, err)
	assert.Len(t, mapped, len(fqns))
	require.Len(t, getEntitleableAttributesRequests, 2)
	assert.Len(t, getEntitleableAttributesRequests[0].GetFqns(), maxEntitleableFQNsPerRequest)
	assert.Len(t, getEntitleableAttributesRequests[1].GetFqns(), 1)
}

func TestRetrieveAttributeDefinitionsRejectsMissingDefinition(t *testing.T) {
	resetTargetedLookupMocks(t)

	fqn := "https://example.com/attr/classification/value/confidential"
	getEntitleableAttributesResponse = &attr.GetEntitleableAttributesByFqnsResponse{
		FqnEntitleableAttributes: map[string]*attr.GetEntitleableAttributesByFqnsResponse_EntitleableAttribute{
			fqn: {
				DefinitionFqn: "https://example.com/attr/classification",
				Value:         &attr.GetEntitleableAttributesByFqnsResponse_EntitleableValue{Fqn: fqn, ValueId: "value-id"},
			},
		},
	}

	result, err := retrieveAttributeDefinitions(t.Context(), []string{fqn}, &otdf.SDK{Attributes: &myAttributesClient{}})
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err))
	assert.Contains(t, err.Error(), "references missing definition")
}

func TestRetrieveMatchedAttributeMappingsFiltersScope(t *testing.T) {
	resetTargetedLookupMocks(t)

	fqn1 := "https://example.com/attr/classification/value/confidential"
	fqn2 := "https://example.com/attr/classification/value/public"
	getAttributesByValueFqnsResponse = attr.GetAttributeValuesByFqnsResponse{
		FqnAttributeValues: map[string]*attr.GetAttributeValuesByFqnsResponse_AttributeAndValue{
			fqn1: {Attribute: &policy.Attribute{Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF}, Value: &policy.Value{Id: "one", Fqn: fqn1}},
			fqn2: {Attribute: &policy.Attribute{Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF}, Value: &policy.Value{Id: "two", Fqn: fqn2}},
		},
	}
	props1, err := structpb.NewStruct(map[string]any{"department": "engineering", "region": "east"})
	require.NoError(t, err)
	props2, err := structpb.NewStruct(map[string]any{"department": "engineering"})
	require.NoError(t, err)
	ersResp := &entityresolution.ResolveEntitiesResponse{EntityRepresentations: []*entityresolution.EntityRepresentation{
		{OriginalId: "one", AdditionalProps: []*structpb.Struct{props1}},
		{OriginalId: "two", AdditionalProps: []*structpb.Struct{props2}},
	}}
	as := &AuthorizationService{sdk: &otdf.SDK{Attributes: &myAttributesClient{}, SubjectMapping: &mySubjectMappingClient{}}}

	mapped, err := as.retrieveMatchedAttributeMappings(t.Context(), ersResp, &authorization.ResourceAttribute{
		AttributeValueFqns: []string{strings.ToUpper(fqn1)},
	})
	require.NoError(t, err)
	require.Len(t, matchSubjectMappingsRequests, 1)
	selectors := make([]string, 0, len(matchSubjectMappingsRequests[0].GetSubjectProperties()))
	for _, property := range matchSubjectMappingsRequests[0].GetSubjectProperties() {
		selectors = append(selectors, property.GetExternalSelectorValue())
	}
	assert.ElementsMatch(t, []string{".department", ".region"}, selectors)
	require.Len(t, getEntitleableAttributesRequests, 1)
	assert.Equal(t, []string{fqn1}, getEntitleableAttributesRequests[0].GetFqns())
	assert.Contains(t, mapped, fqn1)
	assert.NotContains(t, mapped, fqn2)
	assert.Zero(t, listAttributesCallCount)
	assert.Zero(t, listSubjectMappingsCallCount)
	assert.Zero(t, getAttributeValuesCallCount)
}

func TestRetrieveMatchedAttributeMappingsPropagatesMatchError(t *testing.T) {
	resetTargetedLookupMocks(t)

	props, err := structpb.NewStruct(map[string]any{"department": "engineering"})
	require.NoError(t, err)
	errMatchSubjectMappings = errors.New("match failed")
	as := &AuthorizationService{sdk: &otdf.SDK{Attributes: &myAttributesClient{}, SubjectMapping: &mySubjectMappingClient{}}}

	mapped, err := as.retrieveMatchedAttributeMappings(t.Context(), &entityresolution.ResolveEntitiesResponse{
		EntityRepresentations: []*entityresolution.EntityRepresentation{{AdditionalProps: []*structpb.Struct{props}}},
	}, nil)
	require.Error(t, err)
	assert.Nil(t, mapped)
	assert.Contains(t, err.Error(), "failed to match subject mappings")
	assert.Empty(t, getEntitleableAttributesRequests)
}

func TestGetEntitlementsEvaluatesRegoWithoutMatchedSelectors(t *testing.T) {
	resetTargetedLookupMocks(t)
	getAttributesByValueFqnsResponse = attr.GetAttributeValuesByFqnsResponse{}
	resolveEntitiesResp = entityresolution.ResolveEntitiesResponse{
		EntityRepresentations: []*entityresolution.EntityRepresentation{{OriginalId: "e1"}},
	}

	prepared, err := rego.New(
		rego.SetRegoVersion(ast.RegoV0),
		rego.Query("data.example.p"),
		rego.Module("example.rego", `package example
			p = {"e1":["https://example.com/attr/classification/value/confidential"]} { true }`),
	).PrepareForEval(t.Context())
	require.NoError(t, err)
	as := &AuthorizationService{
		logger: logger.CreateTestLogger(),
		sdk: &otdf.SDK{
			SubjectMapping:  &mySubjectMappingClient{},
			Attributes:      &myAttributesClient{},
			EntityResoution: &myERSClient{},
		},
		eval:   prepared,
		Tracer: noop.NewTracerProvider().Tracer(""),
	}

	resp, err := as.GetEntitlements(t.Context(), &connect.Request[authorization.GetEntitlementsRequest]{
		Msg: &authorization.GetEntitlementsRequest{Entities: []*authorization.Entity{{Id: "e1"}}},
	})
	require.NoError(t, err)
	require.Len(t, resp.Msg.GetEntitlements(), 1)
	assert.Equal(t, []string{"https://example.com/attr/classification/value/confidential"}, resp.Msg.GetEntitlements()[0].GetAttributeValueFqns())
	assert.Empty(t, matchSubjectMappingsRequests)
	assert.Empty(t, getEntitleableAttributesRequests)
	assert.Zero(t, listAttributesCallCount)
	assert.Zero(t, listSubjectMappingsCallCount)
}
