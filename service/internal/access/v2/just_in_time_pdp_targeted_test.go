package access

import (
	"context"
	"errors"
	"testing"

	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/dynamicvaluemapping"
	policyobligations "github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	otdfSDK "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/sdk/sdkconnect"
	"github.com/opentdf/platform/service/internal/access/v2/obligations"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
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

type decisionPolicyStore struct {
	EntitlementPolicyStore
	enabled, ready                      bool
	attributes                          []*policy.Attribute
	subjectMappings                     []*policy.SubjectMapping
	attributeReads, subjectMappingReads int
	dynamicMappings                     []*policy.DynamicValueMapping
	dynamicMappingReads                 int
}

type emptyRegisteredResourcesClient struct {
	sdkconnect.RegisteredResourcesServiceClient
}

func (emptyRegisteredResourcesClient) ListRegisteredResources(context.Context, *registeredresources.ListRegisteredResourcesRequest) (*registeredresources.ListRegisteredResourcesResponse, error) {
	return &registeredresources.ListRegisteredResourcesResponse{}, nil
}

type emptyObligationsClient struct {
	sdkconnect.ObligationsServiceClient
}

func (emptyObligationsClient) ListObligations(context.Context, *policyobligations.ListObligationsRequest) (*policyobligations.ListObligationsResponse, error) {
	return &policyobligations.ListObligationsResponse{}, nil
}

func (s *decisionPolicyStore) IsEnabled() bool              { return s.enabled }
func (s *decisionPolicyStore) IsReady(context.Context) bool { return s.ready }
func (s *decisionPolicyStore) ListAllRegisteredResources(context.Context) ([]*policy.RegisteredResource, error) {
	return []*policy.RegisteredResource{}, nil
}

func (s *decisionPolicyStore) ListAllObligations(context.Context) ([]*policy.Obligation, error) {
	return []*policy.Obligation{}, nil
}

func (s *decisionPolicyStore) ListAllAttributes(context.Context) ([]*policy.Attribute, error) {
	s.attributeReads++
	return s.attributes, nil
}

func (s *decisionPolicyStore) ListAllSubjectMappings(context.Context) ([]*policy.SubjectMapping, error) {
	s.subjectMappingReads++
	return s.subjectMappings, nil
}

func (s *decisionPolicyStore) ListAllDynamicValueMappings(context.Context) ([]*policy.DynamicValueMapping, error) {
	s.dynamicMappingReads++
	return s.dynamicMappings, nil
}

type rejectFullDynamicMappingsClient struct {
	sdkconnect.DynamicValueMappingServiceClient
}

func (rejectFullDynamicMappingsClient) ListDynamicValueMappings(context.Context, *dynamicvaluemapping.ListDynamicValueMappingsRequest) (*dynamicvaluemapping.ListDynamicValueMappingsResponse, error) {
	return nil, errors.New("full dynamic mapping listing is not allowed in targeted decisions")
}

func TestJITPDP_UncachedDynamicDecisions(t *testing.T) {
	defFQN := "https://example.com/attr/projects"
	valueFQN := defFQN + "/value/alpha"
	ns := &policy.Namespace{Id: "namespace-id", Fqn: "https://example.com"}
	for _, tc := range []struct {
		name                                                                  string
		persisted, inactive, gated, gateMismatch, namespaceMismatch, disabled bool
		operator                                                              policy.SubjectMappingOperatorEnum
		action                                                                string
		permit                                                                bool
	}{
		{name: "unprovisioned", operator: policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN, action: "read", permit: true},
		{name: "active", persisted: true, operator: policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN, action: "read", permit: true},
		{name: "disabled_unprovisioned", disabled: true, operator: policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN, action: "read"},
		{name: "disabled_persisted", disabled: true, persisted: true, operator: policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN, action: "read"},
		{name: "inactive", persisted: true, inactive: true, operator: policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN, action: "read"},
		{name: "contains", operator: policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS, action: "read", permit: true},
		{name: "gate_allow", gated: true, operator: policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN, action: "read", permit: true},
		{name: "gate_deny", gated: true, gateMismatch: true, operator: policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN, action: "read"},
		{name: "namespace_mismatch", namespaceMismatch: true, operator: policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN, action: "read"},
		{name: "action_mismatch", operator: policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN, action: "write"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mapping := &policy.DynamicValueMapping{
				Id: "mapping-id", Namespace: ns,
				AttributeDefinition: &policy.Attribute{Fqn: defFQN, Namespace: ns, Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF},
				ValueResolver:       &policy.DynamicValueResolver{SubjectExternalSelectorValue: ".projects[]", Operator: tc.operator},
				Actions:             []*policy.Action{{Name: "read", Namespace: ns}},
			}
			if tc.gated {
				mapping.SubjectConditionSet = clientIDInConditionSet("abc")
			}
			if tc.namespaceMismatch {
				mapping.Actions[0].Namespace = &policy.Namespace{Fqn: "https://other.example"}
			}
			attrFake := &fakeAttributesClient{respFunc: func(_ *attrs.GetEntitleableAttributesByFqnsRequest) (*attrs.GetEntitleableAttributesByFqnsResponse, error) {
				value := &attrs.GetEntitleableAttributesByFqnsResponse_EntitleableValue{Fqn: valueFQN}
				if tc.persisted {
					value.ValueId = "value-id"
					value.Active = wrapperspb.Bool(!tc.inactive)
				}
				return &attrs.GetEntitleableAttributesByFqnsResponse{
					Definitions: map[string]*attrs.GetEntitleableAttributesByFqnsResponse_EntitleableDefinition{
						defFQN: {Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF, Namespace: ns, DynamicValueMappings: []*policy.DynamicValueMapping{mapping}},
					},
					FqnEntitleableAttributes: map[string]*attrs.GetEntitleableAttributesByFqnsResponse_EntitleableAttribute{valueFQN: {DefinitionFqn: defFQN, Value: value}},
				}, nil
			}}
			clientID := "abc"
			if tc.gateMismatch {
				clientID = "other"
			}
			props, err := structpb.NewStruct(map[string]any{"clientId": clientID, "projects": []any{"alpha", "beta"}})
			require.NoError(t, err)
			ers := &recordingERSV2Client{resolveResponse: &entityresolutionV2.ResolveEntitiesResponse{EntityRepresentations: []*entityresolutionV2.EntityRepresentation{{OriginalId: "e1", AdditionalProps: []*structpb.Struct{props}}}}}
			p, err := NewJustInTimePDP(context.Background(), logger.CreateTestLogger(), &otdfSDK.SDK{
				Attributes: attrFake, EntityResolutionV2: ers, RegisteredResources: emptyRegisteredResourcesClient{},
				Obligations: emptyObligationsClient{}, DynamicValueMapping: rejectFullDynamicMappingsClient{},
			}, &decisionPolicyStore{}, false, !tc.disabled, true)
			require.NoError(t, err)
			decision, err := p.GetDecision(audit.ContextWithActorID(context.Background(), "test-actor"), entityChainIdentifier(),
				&policy.Action{Name: tc.action, Namespace: ns}, attrValueResource(valueFQN), nil, nil)
			require.NoError(t, err)
			assert.Equal(t, tc.permit, decision.AllPermitted)
			require.Len(t, attrFake.requests, 1)
			assert.Equal(t, []string{valueFQN}, attrFake.requests[0].GetFqns())
		})
	}
}

func TestJITPDP_UncachedDirectDecisions(t *testing.T) {
	defFQN := "https://example.com/attr/projects"
	valueFQN := defFQN + "/value/alpha"
	for _, rule := range []policy.AttributeRuleTypeEnum{
		policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
		policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
	} {
		for _, tc := range []struct {
			name            string
			value           *attrs.GetEntitleableAttributesByFqnsResponse_EntitleableValue
			knownDefinition bool
			action          string
			permit          bool
		}{
			{"unprovisioned", &attrs.GetEntitleableAttributesByFqnsResponse_EntitleableValue{Fqn: valueFQN}, true, "read", true},
			{"active", &attrs.GetEntitleableAttributesByFqnsResponse_EntitleableValue{Fqn: valueFQN, ValueId: "value-id", Active: wrapperspb.Bool(true)}, true, "read", true},
			{"inactive", &attrs.GetEntitleableAttributesByFqnsResponse_EntitleableValue{Fqn: valueFQN, ValueId: "value-id", Active: wrapperspb.Bool(false)}, true, "read", false},
			{"unknown_definition", nil, false, "read", false},
			{"action_mismatch", &attrs.GetEntitleableAttributesByFqnsResponse_EntitleableValue{Fqn: valueFQN}, true, "write", false},
		} {
			t.Run(rule.String()+"/"+tc.name, func(t *testing.T) {
				attrFake := &fakeAttributesClient{respFunc: func(_ *attrs.GetEntitleableAttributesByFqnsRequest) (*attrs.GetEntitleableAttributesByFqnsResponse, error) {
					resp := &attrs.GetEntitleableAttributesByFqnsResponse{}
					if tc.knownDefinition {
						def := &attrs.GetEntitleableAttributesByFqnsResponse_EntitleableDefinition{Rule: rule}
						if rule == policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY && tc.value.GetActive().GetValue() {
							def.Values = []*attrs.GetEntitleableAttributesByFqnsResponse_EntitleableValue{tc.value}
						}
						resp.Definitions = map[string]*attrs.GetEntitleableAttributesByFqnsResponse_EntitleableDefinition{defFQN: def}
						resp.FqnEntitleableAttributes = map[string]*attrs.GetEntitleableAttributesByFqnsResponse_EntitleableAttribute{
							valueFQN: {DefinitionFqn: defFQN, Value: tc.value},
						}
					}
					return resp, nil
				}}
				rep := entityRepWithClientID("abc")
				rep.DirectEntitlements = []*entityresolutionV2.DirectEntitlement{{AttributeValueFqn: valueFQN, Actions: []string{"read"}}}
				ers := &recordingERSV2Client{resolveResponse: &entityresolutionV2.ResolveEntitiesResponse{EntityRepresentations: []*entityresolutionV2.EntityRepresentation{rep}}}
				store := &decisionPolicyStore{}
				p, err := NewJustInTimePDP(context.Background(), logger.CreateTestLogger(), &otdfSDK.SDK{
					Attributes: attrFake, EntityResolutionV2: ers,
					RegisteredResources: emptyRegisteredResourcesClient{}, Obligations: emptyObligationsClient{},
				}, store, true, false, false)
				require.NoError(t, err)
				ctx := audit.ContextWithActorID(context.Background(), "test-actor")
				decision, err := p.GetDecision(ctx, entityChainIdentifier(), &policy.Action{Name: tc.action}, attrValueResource(valueFQN), nil, nil)
				require.NoError(t, err)
				assert.Equal(t, tc.permit, decision.AllPermitted)
				require.Len(t, attrFake.requests, 1)
				assert.Equal(t, []string{valueFQN}, attrFake.requests[0].GetFqns())
				assert.Zero(t, store.attributeReads)
				assert.Zero(t, store.subjectMappingReads)
			})
		}
	}
}

func TestJITPDP_CacheAndEnumerationRetainFullPolicy(t *testing.T) {
	defFQN := "https://example.com/attr/classification"
	valueFQN := defFQN + "/value/high"
	sm := &policy.SubjectMapping{
		Id: "sm-1", AttributeValue: &policy.Value{Fqn: valueFQN},
		SubjectConditionSet: clientIDInConditionSet("abc"), Actions: []*policy.Action{{Name: "read"}},
	}
	store := &decisionPolicyStore{
		enabled: true, ready: true,
		attributes: []*policy.Attribute{{
			Fqn: defFQN, Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
			Values: []*policy.Value{{Fqn: valueFQN}, {Fqn: defFQN + "/value/low"}},
		}},
		subjectMappings: []*policy.SubjectMapping{sm},
	}
	attrFake := &fakeAttributesClient{respFunc: func(*attrs.GetEntitleableAttributesByFqnsRequest) (*attrs.GetEntitleableAttributesByFqnsResponse, error) {
		t.Fatal("full-policy paths should not perform a targeted read")
		return nil, errors.New("unexpected read")
	}}
	ers := &recordingERSV2Client{resolveResponse: &entityresolutionV2.ResolveEntitiesResponse{
		EntityRepresentations: []*entityresolutionV2.EntityRepresentation{entityRepWithClientID("abc")},
	}}
	sdk := &otdfSDK.SDK{
		Attributes: attrFake, EntityResolutionV2: ers,
		SubjectMapping: &fakeSubjectMappingClient{resp: &subjectmapping.MatchSubjectMappingsResponse{SubjectMappings: []*policy.SubjectMapping{sm}}},
	}
	p, err := NewJustInTimePDP(context.Background(), logger.CreateTestLogger(), sdk, store, true, true, false)
	require.NoError(t, err)
	require.NotNil(t, p.fullPolicyPDP)
	inner, err := p.buildInnerPDP(context.Background(), []string{valueFQN})
	require.NoError(t, err)
	assert.Same(t, p.fullPolicyPDP, inner)
	assert.Equal(t, 1, store.attributeReads)
	assert.Equal(t, 1, store.subjectMappingReads)
	assert.Equal(t, 1, store.dynamicMappingReads)

	// An uncached enumeration still reads the broader policy, including hierarchy siblings.
	p.fullPolicyPDP = nil
	entitlements, err := p.GetEntitlements(context.Background(), entityChainIdentifier(), true)
	require.NoError(t, err)
	require.Len(t, entitlements, 1)
	assert.Contains(t, entitlements[0].GetActionsPerAttributeValueFqn(), valueFQN)
	assert.Contains(t, entitlements[0].GetActionsPerAttributeValueFqn(), defFQN+"/value/low")
	assert.Equal(t, 2, store.attributeReads)
	assert.Equal(t, 2, store.subjectMappingReads)
	assert.Equal(t, 2, store.dynamicMappingReads)
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

func TestJITPDP_GetDecision_UnknownFQNIsDenied(t *testing.T) {
	definitionFQN := "https://example.com/attr/classification"
	valueFQN := definitionFQN + "/value/finance"

	// Unknown definitions are omitted from the policy response.
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
	// Missing policy context produces a per-resource deny.
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
	// One batch returns the known value and definition context for the unprovisioned value.
	attrFake := &fakeAttributesClient{
		respFunc: func(_ *attrs.GetEntitleableAttributesByFqnsRequest) (*attrs.GetEntitleableAttributesByFqnsResponse, error) {
			return &attrs.GetEntitleableAttributesByFqnsResponse{
				Definitions: map[string]*attrs.GetEntitleableAttributesByFqnsResponse_EntitleableDefinition{
					definitionFQN: {Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF},
				},
				FqnEntitleableAttributes: map[string]*attrs.GetEntitleableAttributesByFqnsResponse_EntitleableAttribute{
					knownFQN: {DefinitionFqn: definitionFQN, Value: &attrs.GetEntitleableAttributesByFqnsResponse_EntitleableValue{
						Fqn: knownFQN, ValueId: "known-id", SubjectMappings: []*policy.SubjectMapping{sm},
					}},
					unknownFQN: {DefinitionFqn: definitionFQN, Value: &attrs.GetEntitleableAttributesByFqnsResponse_EntitleableValue{Fqn: unknownFQN}},
				},
			}, nil
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
	require.Len(t, attrFake.requests, 1)
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
