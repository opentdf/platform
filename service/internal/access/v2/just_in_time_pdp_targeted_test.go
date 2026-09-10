package access

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	otdfSDK "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/sdk/sdkconnect"
	"github.com/opentdf/platform/service/internal/access/v2/obligations"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

// fakeSubjectMappingClient embeds the interface (nil) and only overrides MatchSubjectMappings.
type fakeSubjectMappingClient struct {
	sdkconnect.SubjectMappingServiceClient
	resp     *subjectmapping.MatchSubjectMappingsResponse
	err      error
	requests []*subjectmapping.MatchSubjectMappingsRequest
}

func (f *fakeSubjectMappingClient) MatchSubjectMappings(_ context.Context, req *subjectmapping.MatchSubjectMappingsRequest) (*subjectmapping.MatchSubjectMappingsResponse, error) {
	f.requests = append(f.requests, req)
	return f.resp, f.err
}

func clientIDInConditionSet(clientID string) *policy.SubjectConditionSet {
	return &policy.SubjectConditionSet{
		SubjectSets: []*policy.SubjectSet{{
			ConditionGroups: []*policy.ConditionGroup{{
				BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
				Conditions: []*policy.Condition{{
					SubjectExternalSelectorValue: ".clientId",
					Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
					SubjectExternalValues:        []string{clientID},
				}},
			}},
		}},
	}
}

func entityChainIdentifier() *authzV2.EntityIdentifier {
	return &authzV2.EntityIdentifier{
		Identifier: &authzV2.EntityIdentifier_EntityChain{
			EntityChain: &entity.EntityChain{
				EphemeralId: "chain-1",
				Entities:    []*entity.Entity{{EphemeralId: "e1", Category: entity.Entity_CATEGORY_SUBJECT}},
			},
		},
	}
}

func entityRepWithClientID(clientID string) *entityresolutionV2.EntityRepresentation {
	props, _ := structpb.NewStruct(map[string]any{"clientId": clientID})
	return &entityresolutionV2.EntityRepresentation{
		OriginalId:      "e1",
		AdditionalProps: []*structpb.Struct{props},
	}
}

func TestJITPDP_GetEntitlements_TargetedFetch(t *testing.T) {
	definitionFQN := "https://example.com/attr/classification"
	valueFQN := definitionFQN + "/value/confidential"

	matchedSM := &policy.SubjectMapping{
		Id:                  "sm-1",
		AttributeValue:      &policy.Value{Fqn: valueFQN},
		SubjectConditionSet: clientIDInConditionSet("abc"),
		Actions:             []*policy.Action{{Name: "read"}},
	}
	attrFake := &fakeAttributesClient{
		respFunc: func(_ *attrs.GetEntitleableAttributesByFqnsRequest) (*attrs.GetEntitleableAttributesByFqnsResponse, error) {
			return &attrs.GetEntitleableAttributesByFqnsResponse{
				Definitions: map[string]*attrs.GetEntitleableAttributesByFqnsResponse_EntitleableDefinition{
					definitionFQN: {Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF},
				},
				FqnEntitleableAttributes: map[string]*attrs.GetEntitleableAttributesByFqnsResponse_EntitleableAttribute{
					valueFQN: {DefinitionFqn: definitionFQN, Value: &attrs.GetEntitleableAttributesByFqnsResponse_EntitleableValue{Fqn: valueFQN, ValueId: "conf-id"}},
				},
			}, nil
		},
	}
	smFake := &fakeSubjectMappingClient{resp: &subjectmapping.MatchSubjectMappingsResponse{SubjectMappings: []*policy.SubjectMapping{matchedSM}}}
	ers := &recordingERSV2Client{resolveResponse: &entityresolutionV2.ResolveEntitiesResponse{
		EntityRepresentations: []*entityresolutionV2.EntityRepresentation{entityRepWithClientID("abc")},
	}}

	p := &JustInTimePDP{
		logger: logger.CreateTestLogger(),
		sdk:    &otdfSDK.SDK{Attributes: attrFake, SubjectMapping: smFake, EntityResolutionV2: ers},
	}

	ents, err := p.GetEntitlements(context.Background(), entityChainIdentifier(), false)
	require.NoError(t, err)
	require.Len(t, ents, 1)
	assert.Equal(t, "e1", ents[0].GetEphemeralId())
	require.Contains(t, ents[0].GetActionsPerAttributeValueFqn(), valueFQN)

	// The entitleable fetch was targeted to only the matched value FQN.
	require.Len(t, attrFake.requests, 1)
	assert.Equal(t, []string{valueFQN}, attrFake.requests[0].GetFqns())
}

func TestJITPDP_GetEntitlements_NoMatchReturnsNil(t *testing.T) {
	attrFake := &fakeAttributesClient{
		respFunc: func(_ *attrs.GetEntitleableAttributesByFqnsRequest) (*attrs.GetEntitleableAttributesByFqnsResponse, error) {
			return &attrs.GetEntitleableAttributesByFqnsResponse{}, nil
		},
	}
	smFake := &fakeSubjectMappingClient{resp: &subjectmapping.MatchSubjectMappingsResponse{}}
	ers := &recordingERSV2Client{resolveResponse: &entityresolutionV2.ResolveEntitiesResponse{
		EntityRepresentations: []*entityresolutionV2.EntityRepresentation{entityRepWithClientID("abc")},
	}}
	p := &JustInTimePDP{
		logger: logger.CreateTestLogger(),
		sdk:    &otdfSDK.SDK{Attributes: attrFake, SubjectMapping: smFake, EntityResolutionV2: ers},
	}

	ents, err := p.GetEntitlements(context.Background(), entityChainIdentifier(), false)
	require.NoError(t, err)
	assert.Nil(t, ents)
	// No match means no entitleable fetch is performed.
	assert.Empty(t, attrFake.requests)
}

func newTestObligationsPDP(t *testing.T) *obligations.ObligationsPolicyDecisionPoint {
	t.Helper()
	oPDP, err := obligations.NewObligationsPolicyDecisionPoint(
		context.Background(),
		logger.CreateTestLogger(),
		make(map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue),
		make(map[string]*policy.RegisteredResourceValue),
		nil,
	)
	require.NoError(t, err)
	return oPDP
}

func decisionAttrFake(definitionFQN, valueFQN, clientID string) *fakeAttributesClient {
	sm := &policy.SubjectMapping{
		Id:                  "sm-1",
		AttributeValue:      &policy.Value{Fqn: valueFQN},
		SubjectConditionSet: clientIDInConditionSet(clientID),
		Actions:             []*policy.Action{{Name: "read"}},
	}
	return &fakeAttributesClient{
		respFunc: func(_ *attrs.GetEntitleableAttributesByFqnsRequest) (*attrs.GetEntitleableAttributesByFqnsResponse, error) {
			return &attrs.GetEntitleableAttributesByFqnsResponse{
				Definitions: map[string]*attrs.GetEntitleableAttributesByFqnsResponse_EntitleableDefinition{
					definitionFQN: {Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF},
				},
				FqnEntitleableAttributes: map[string]*attrs.GetEntitleableAttributesByFqnsResponse_EntitleableAttribute{
					valueFQN: {
						DefinitionFqn: definitionFQN,
						Value: &attrs.GetEntitleableAttributesByFqnsResponse_EntitleableValue{
							Fqn: valueFQN, ValueId: "conf-id", SubjectMappings: []*policy.SubjectMapping{sm},
						},
					},
				},
			}, nil
		},
	}
}

func attrValueResource(valueFQN string) []*authzV2.Resource {
	return []*authzV2.Resource{{
		Resource: &authzV2.Resource_AttributeValues_{
			AttributeValues: &authzV2.Resource_AttributeValues{Fqns: []string{valueFQN}},
		},
	}}
}

func TestJITPDP_GetDecision_TargetedPermit(t *testing.T) {
	definitionFQN := "https://example.com/attr/classification"
	valueFQN := definitionFQN + "/value/confidential"

	attrFake := decisionAttrFake(definitionFQN, valueFQN, "abc")
	ers := &recordingERSV2Client{resolveResponse: &entityresolutionV2.ResolveEntitiesResponse{
		EntityRepresentations: []*entityresolutionV2.EntityRepresentation{entityRepWithClientID("abc")},
	}}
	p := &JustInTimePDP{
		logger:                        logger.CreateTestLogger(),
		sdk:                           &otdfSDK.SDK{Attributes: attrFake, EntityResolutionV2: ers},
		obligationsPDP:                newTestObligationsPDP(t),
		registeredResourceValuesByFQN: make(map[string]*policy.RegisteredResourceValue),
	}

	ctx := audit.ContextWithActorID(context.Background(), "test-actor")
	decision, err := p.GetDecision(ctx, entityChainIdentifier(), &policy.Action{Name: "read"}, attrValueResource(valueFQN), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, decision)
	assert.True(t, decision.AllPermitted)

	require.Len(t, attrFake.requests, 1)
	assert.Equal(t, []string{valueFQN}, attrFake.requests[0].GetFqns())
}

func TestJITPDP_GetDecision_TargetedDenyOnEntityMismatch(t *testing.T) {
	definitionFQN := "https://example.com/attr/classification"
	valueFQN := definitionFQN + "/value/confidential"

	// Subject mapping requires clientId "abc" but the entity presents "other".
	attrFake := decisionAttrFake(definitionFQN, valueFQN, "abc")
	ers := &recordingERSV2Client{resolveResponse: &entityresolutionV2.ResolveEntitiesResponse{
		EntityRepresentations: []*entityresolutionV2.EntityRepresentation{entityRepWithClientID("other")},
	}}
	p := &JustInTimePDP{
		logger:                        logger.CreateTestLogger(),
		sdk:                           &otdfSDK.SDK{Attributes: attrFake, EntityResolutionV2: ers},
		obligationsPDP:                newTestObligationsPDP(t),
		registeredResourceValuesByFQN: make(map[string]*policy.RegisteredResourceValue),
	}

	ctx := audit.ContextWithActorID(context.Background(), "test-actor")
	decision, err := p.GetDecision(ctx, entityChainIdentifier(), &policy.Action{Name: "read"}, attrValueResource(valueFQN), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, decision)
	assert.False(t, decision.AllPermitted)
}

func TestJITPDP_GetDecision_NotFoundDegradesToDeny(t *testing.T) {
	definitionFQN := "https://example.com/attr/classification"
	valueFQN := definitionFQN + "/value/finance"

	// The attributes service returns NotFound for the requested value (does not exist in policy).
	attrFake := &fakeAttributesClient{
		respFunc: func(_ *attrs.GetEntitleableAttributesByFqnsRequest) (*attrs.GetEntitleableAttributesByFqnsResponse, error) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("not found"))
		},
	}
	ers := &recordingERSV2Client{resolveResponse: &entityresolutionV2.ResolveEntitiesResponse{
		EntityRepresentations: []*entityresolutionV2.EntityRepresentation{entityRepWithClientID("abc")},
	}}
	p := &JustInTimePDP{
		logger:                        logger.CreateTestLogger(),
		sdk:                           &otdfSDK.SDK{Attributes: attrFake, EntityResolutionV2: ers},
		obligationsPDP:                newTestObligationsPDP(t),
		registeredResourceValuesByFQN: make(map[string]*policy.RegisteredResourceValue),
	}

	ctx := audit.ContextWithActorID(context.Background(), "test-actor")
	decision, err := p.GetDecision(ctx, entityChainIdentifier(), &policy.Action{Name: "read"}, attrValueResource(valueFQN), nil, nil)
	// A NotFound must degrade to a per-resource deny, not surface as an internal error.
	require.NoError(t, err)
	require.NotNil(t, decision)
	assert.False(t, decision.AllPermitted)
}

func TestJITPDP_GetDecision_MixedKnownUnknownFQNsPreservesKnown(t *testing.T) {
	definitionFQN := "https://example.com/attr/department"
	knownFQN := definitionFQN + "/value/eng"
	unknownFQN := definitionFQN + "/value/finance"

	sm := &policy.SubjectMapping{
		Id:                  "sm-1",
		AttributeValue:      &policy.Value{Fqn: knownFQN},
		SubjectConditionSet: clientIDInConditionSet("abc"),
		Actions:             []*policy.Action{{Name: "read"}},
	}
	// The server rejects any batch containing the unknown FQN with NotFound; a per-FQN retry resolves
	// the known FQN and skips the unknown one.
	attrFake := &fakeAttributesClient{
		respFunc: func(req *attrs.GetEntitleableAttributesByFqnsRequest) (*attrs.GetEntitleableAttributesByFqnsResponse, error) {
			for _, f := range req.GetFqns() {
				if f == unknownFQN {
					return nil, connect.NewError(connect.CodeNotFound, errors.New("not found"))
				}
			}
			resp := &attrs.GetEntitleableAttributesByFqnsResponse{
				Definitions: map[string]*attrs.GetEntitleableAttributesByFqnsResponse_EntitleableDefinition{
					definitionFQN: {Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF},
				},
				FqnEntitleableAttributes: make(map[string]*attrs.GetEntitleableAttributesByFqnsResponse_EntitleableAttribute),
			}
			for _, f := range req.GetFqns() {
				resp.FqnEntitleableAttributes[f] = &attrs.GetEntitleableAttributesByFqnsResponse_EntitleableAttribute{
					DefinitionFqn: definitionFQN,
					Value:         &attrs.GetEntitleableAttributesByFqnsResponse_EntitleableValue{Fqn: f, ValueId: f + "-id", SubjectMappings: []*policy.SubjectMapping{sm}},
				}
			}
			return resp, nil
		},
	}
	ers := &recordingERSV2Client{resolveResponse: &entityresolutionV2.ResolveEntitiesResponse{
		EntityRepresentations: []*entityresolutionV2.EntityRepresentation{entityRepWithClientID("abc")},
	}}
	p := &JustInTimePDP{
		logger:                        logger.CreateTestLogger(),
		sdk:                           &otdfSDK.SDK{Attributes: attrFake, EntityResolutionV2: ers},
		obligationsPDP:                newTestObligationsPDP(t),
		registeredResourceValuesByFQN: make(map[string]*policy.RegisteredResourceValue),
	}

	resources := []*authzV2.Resource{
		{Resource: &authzV2.Resource_AttributeValues_{AttributeValues: &authzV2.Resource_AttributeValues{Fqns: []string{knownFQN}}}},
		{Resource: &authzV2.Resource_AttributeValues_{AttributeValues: &authzV2.Resource_AttributeValues{Fqns: []string{unknownFQN}}}},
	}

	ctx := audit.ContextWithActorID(context.Background(), "test-actor")
	decision, err := p.GetDecision(ctx, entityChainIdentifier(), &policy.Action{Name: "read"}, resources, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, decision)
	require.Len(t, decision.Results, 2)
	// The known resource is still decided (entitled); only the unknown one is denied.
	assert.True(t, decision.Results[0].Entitled, "known resource should remain entitled")
	assert.False(t, decision.Results[1].Entitled, "unknown resource should be denied")
	assert.False(t, decision.AllPermitted)
}

func TestJITPDP_buildInnerPDP_UsesFullPolicyPDPWhenSet(t *testing.T) {
	// When the full-policy PDP is set (direct entitlements / dynamic value mappings mode),
	// buildInnerPDP returns it without performing a targeted entitleable fetch.
	definitionFQN := "https://example.com/attr/classification"
	valueFQN := definitionFQN + "/value/confidential"
	fullPDP, err := NewPolicyDecisionPoint(
		context.Background(),
		logger.CreateTestLogger(),
		[]*policy.Attribute{{
			Fqn:    definitionFQN,
			Rule:   policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			Values: []*policy.Value{{Fqn: valueFQN}},
		}},
		[]*policy.SubjectMapping{},
		nil,
		true,
		false,
	)
	require.NoError(t, err)

	attrFake := &fakeAttributesClient{
		respFunc: func(_ *attrs.GetEntitleableAttributesByFqnsRequest) (*attrs.GetEntitleableAttributesByFqnsResponse, error) {
			t.Fatal("targeted fetch should not be called when full-policy PDP is set")
			return nil, errors.New("unreachable")
		},
	}
	p := &JustInTimePDP{
		logger:        logger.CreateTestLogger(),
		sdk:           &otdfSDK.SDK{Attributes: attrFake},
		fullPolicyPDP: fullPDP,
	}

	got, err := p.buildInnerPDP(context.Background(), []string{valueFQN})
	require.NoError(t, err)
	assert.Same(t, fullPDP, got)
	assert.Empty(t, attrFake.requests)
}

func TestJITPDP_GetDecision_TargetedDenyOnUnknownFQN(t *testing.T) {
	definitionFQN := "https://example.com/attr/classification"
	valueFQN := definitionFQN + "/value/confidential"

	// The attributes service returns nothing for the requested FQN (unknown value).
	attrFake := &fakeAttributesClient{
		respFunc: func(_ *attrs.GetEntitleableAttributesByFqnsRequest) (*attrs.GetEntitleableAttributesByFqnsResponse, error) {
			return &attrs.GetEntitleableAttributesByFqnsResponse{}, nil
		},
	}
	ers := &recordingERSV2Client{resolveResponse: &entityresolutionV2.ResolveEntitiesResponse{
		EntityRepresentations: []*entityresolutionV2.EntityRepresentation{entityRepWithClientID("abc")},
	}}
	p := &JustInTimePDP{
		logger:                        logger.CreateTestLogger(),
		sdk:                           &otdfSDK.SDK{Attributes: attrFake, EntityResolutionV2: ers},
		obligationsPDP:                newTestObligationsPDP(t),
		registeredResourceValuesByFQN: make(map[string]*policy.RegisteredResourceValue),
	}

	ctx := audit.ContextWithActorID(context.Background(), "test-actor")
	decision, err := p.GetDecision(ctx, entityChainIdentifier(), &policy.Action{Name: "read"}, attrValueResource(valueFQN), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, decision)
	assert.False(t, decision.AllPermitted)
}

func TestMatchedSubjectMappingsDeduplicatesSelectorsAcrossRepresentations(t *testing.T) {
	fake := &fakeSubjectMappingClient{resp: &subjectmapping.MatchSubjectMappingsResponse{}}
	pdp := &JustInTimePDP{sdk: &otdfSDK.SDK{SubjectMapping: fake}}
	_, err := pdp.getMatchedSubjectMappings(t.Context(), []*entityresolutionV2.EntityRepresentation{entityRepWithClientID("one"), entityRepWithClientID("two")})
	require.NoError(t, err)
	require.Len(t, fake.requests, 1)
	require.Len(t, fake.requests[0].GetSubjectProperties(), 1)
	require.Equal(t, ".clientId", fake.requests[0].GetSubjectProperties()[0].GetExternalSelectorValue())
}
