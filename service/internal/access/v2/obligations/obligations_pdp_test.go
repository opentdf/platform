package obligations

import (
	"testing"

	"github.com/stretchr/testify/suite"

	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/service/logger"
)

const (
	mockAttrValFQN1 = "https://example.org/attr/attr1/value/val1"
	mockAttrValFQN2 = "https://example.org/attr/attr2/value/val2"
	mockAttrValFQN3 = "https://example.org/attr/attr2/value/val3"

	mockObligationFQN1 = "https://example.org/obl/some_obligation/value/some_value"
	mockObligationFQN2 = "https://example.org/obl/another_obligation/value/another_value"
	mockObligationFQN3 = "https://example.org/obl/create_obligation/value/create_value"
	mockObligationFQN4 = "https://example.org/obl/custom_obligation/value/custom_value"

	mockRegResValFQN1 = "https://example.org/reg_res/resource1/value/val1"
	mockRegResValFQN2 = "https://example.org/reg_res/resource2/value/val2"
	mockRegResValFQN3 = "https://example.org/reg_res/resource2/value/val3"

	mockClientID = "mock-client-id"

	actionNameRead   = "read"
	actionNameCreate = "create"
	actionNameCustom = "custom_action"
)

var (
	actionRead   = &policy.Action{Name: actionNameRead}
	actionCreate = &policy.Action{Name: actionNameCreate}
	actionCustom = &policy.Action{Name: actionNameCustom}

	emptyDecisionRequestContext = &policy.RequestContext{}
)

type ObligationsPDPSuite struct {
	suite.Suite
	pdp *ObligationsPolicyDecisionPoint
}

func Test_ObligationsPDPSuite(t *testing.T) {
	suite.Run(t, new(ObligationsPDPSuite))
}

func (s *ObligationsPDPSuite) SetupSuite() {
	// Mock attributes
	attributesByValueFQN := map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
		mockAttrValFQN1: {
			Attribute: &policy.Attribute{Name: "attr1"},
			Value:     &policy.Value{Fqn: mockAttrValFQN1},
		},
		mockAttrValFQN2: {
			Attribute: &policy.Attribute{Name: "attr2"},
			Value:     &policy.Value{Fqn: mockAttrValFQN2},
		},
		mockAttrValFQN3: {
			Attribute: &policy.Attribute{Name: "attr2"},
			Value:     &policy.Value{Fqn: mockAttrValFQN3},
		},
	}

	// Mock registered resources
	registeredResourceValuesByFQN := map[string]*policy.RegisteredResourceValue{
		mockRegResValFQN1: {
			Value: "val1",
			ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
				{
					Action:         actionRead,
					AttributeValue: &policy.Value{Fqn: mockAttrValFQN1},
				},
				{
					Action:         actionCreate,
					AttributeValue: &policy.Value{Fqn: mockAttrValFQN1},
				},
			},
		},
		mockRegResValFQN2: {
			Value: "val2",
			ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
				{
					Action:         actionRead,
					AttributeValue: &policy.Value{Fqn: mockAttrValFQN2},
				},
			},
		},
		mockRegResValFQN3: {
			Value: "val3",
			ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
				{
					Action:         actionCustom,
					AttributeValue: &policy.Value{Fqn: mockAttrValFQN3},
				},
			},
		},
	}

	// Mock obligations
	allObligations := []*policy.Obligation{
		{
			Values: []*policy.ObligationValue{
				// No client PEP scope - triggered by 'read' action
				{
					Fqn: mockObligationFQN1,
					Triggers: []*policy.ObligationTrigger{
						{
							Action:         actionRead,
							AttributeValue: &policy.Value{Fqn: mockAttrValFQN1},
						},
					},
				},
				// Scoped to the mockClientID PEP - triggered by 'read' action
				{
					Fqn: mockObligationFQN2,
					Triggers: []*policy.ObligationTrigger{
						{
							Action:         actionRead,
							AttributeValue: &policy.Value{Fqn: mockAttrValFQN2},
							Context: []*policy.RequestContext{
								{
									Pep: &policy.PolicyEnforcementPoint{
										ClientId: mockClientID,
									},
								},
							},
						},
					},
				},
				// No client PEP scope - triggered by 'create' action
				{
					Fqn: mockObligationFQN3,
					Triggers: []*policy.ObligationTrigger{
						{
							Action:         actionCreate,
							AttributeValue: &policy.Value{Fqn: mockAttrValFQN1},
						},
					},
				},
				// No client PEP scope - triggered by 'custom' action
				{
					Fqn: mockObligationFQN4,
					Triggers: []*policy.ObligationTrigger{
						{
							Action:         actionCustom,
							AttributeValue: &policy.Value{Fqn: mockAttrValFQN3},
						},
					},
				},
			},
		},
	}

	// Create a new PDP instance
	var err error
	s.pdp, err = NewObligationsPolicyDecisionPoint(
		s.T().Context(),
		logger.CreateTestLogger(),
		attributesByValueFQN,
		registeredResourceValuesByFQN,
		allObligations,
	)
	s.Require().NoError(err)
}

func (s *ObligationsPDPSuite) Test_NewObligationsPolicyDecisionPoint_Success() {
	attributesByValueFQN := s.createAttributesByValueFQN(mockAttrValFQN1, "attr1")
	var noClientID string
	var noRegisteredResources map[string]*policy.RegisteredResourceValue
	allObligations := []*policy.Obligation{s.createObligation(mockObligationFQN1, mockAttrValFQN1, noClientID, actionRead)}

	pdp, err := NewObligationsPolicyDecisionPoint(
		s.T().Context(),
		logger.CreateTestLogger(),
		attributesByValueFQN,
		noRegisteredResources,
		allObligations,
	)

	s.Require().NoError(err)
	s.NotNil(pdp)
	s.NotNil(pdp.logger)
	s.Equal(attributesByValueFQN, pdp.attributesByValueFQN)
	s.Empty(pdp.registeredResourceValuesByFQN)
	s.NotNil(pdp.simpleTriggerActionsToAttributes)
	s.NotNil(pdp.clientIDScopedTriggerActionsToAttributes)
}

func (s *ObligationsPDPSuite) Test_NewObligationsPolicyDecisionPoint_WithClientScoped() {
	attributesByValueFQN := s.createAttributesByValueFQN(mockAttrValFQN2, "attr2")
	allObligations := []*policy.Obligation{s.createObligation(mockObligationFQN2, mockAttrValFQN2, mockClientID, actionRead)}
	var noRegisteredResources map[string]*policy.RegisteredResourceValue

	pdp, err := NewObligationsPolicyDecisionPoint(
		s.T().Context(),
		logger.CreateTestLogger(),
		attributesByValueFQN,
		noRegisteredResources,
		allObligations,
	)

	s.Require().NoError(err)
	s.NotNil(pdp)
	s.Contains(pdp.clientIDScopedTriggerActionsToAttributes, mockClientID)
	s.Contains(pdp.clientIDScopedTriggerActionsToAttributes[mockClientID], actionNameRead)
	s.Contains(pdp.clientIDScopedTriggerActionsToAttributes[mockClientID][actionNameRead], mockAttrValFQN2)
}

func (s *ObligationsPDPSuite) Test_NewObligationsPolicyDecisionPoint_EmptyClientID_Fails() {
	attributesByValueFQN := s.createAttributesByValueFQN(mockAttrValFQN1, "attr1")
	var noRegisteredResources map[string]*policy.RegisteredResourceValue

	// Create obligation with empty client ID using special case
	allObligations := []*policy.Obligation{
		{
			Values: []*policy.ObligationValue{
				{
					Fqn: mockObligationFQN1,
					Triggers: []*policy.ObligationTrigger{
						{
							Action:         actionRead,
							AttributeValue: &policy.Value{Fqn: mockAttrValFQN1},
							Context: []*policy.RequestContext{
								{
									Pep: &policy.PolicyEnforcementPoint{
										ClientId: "",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	pdp, err := NewObligationsPolicyDecisionPoint(
		s.T().Context(),
		logger.CreateTestLogger(),
		attributesByValueFQN,
		noRegisteredResources,
		allObligations,
	)

	s.Require().Error(err)
	s.Require().ErrorIs(err, ErrEmptyPEPClientID)
	s.Nil(pdp)
}

func (s *ObligationsPDPSuite) Test_NewObligationsPolicyDecisionPoint_EmptyObligations() {
	attributesByValueFQN := s.createAttributesByValueFQN(mockAttrValFQN1, "attr1")
	var noRegisteredResources map[string]*policy.RegisteredResourceValue

	pdp, err := NewObligationsPolicyDecisionPoint(
		s.T().Context(),
		logger.CreateTestLogger(),
		attributesByValueFQN,
		noRegisteredResources,
		[]*policy.Obligation{},
	)

	s.Require().NoError(err)
	s.NotNil(pdp)
	s.Empty(pdp.simpleTriggerActionsToAttributes)
	s.Empty(pdp.clientIDScopedTriggerActionsToAttributes)
}

func (s *ObligationsPDPSuite) Test_getTriggeredObligations_NoObligationsTriggered() {
	type args struct {
		action                 *policy.Action
		resources              []*authz.Resource
		decisionRequestContext *policy.RequestContext
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "no obligation triggered by known but unobligated attribute value",
			args: args{
				action: actionRead,
				resources: []*authz.Resource{
					{
						Resource: &authz.Resource_AttributeValues_{
							AttributeValues: &authz.Resource_AttributeValues{
								Fqns: []string{mockAttrValFQN3},
							},
						},
					},
				},
			},
		},
		{
			name: "no obligation triggered by unobligated action",
			args: args{
				action: &policy.Action{Name: "random-action-name"},
				resources: []*authz.Resource{
					{
						Resource: &authz.Resource_AttributeValues_{
							AttributeValues: &authz.Resource_AttributeValues{
								Fqns: []string{mockAttrValFQN1},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			perResource, all, err := s.pdp.getTriggeredObligations(t.Context(), tt.args.action, tt.args.resources, tt.args.decisionRequestContext)
			s.Require().NoError(err)
			s.Len(perResource, len(tt.args.resources))

			for _, r := range perResource {
				s.Empty(r)
			}
			s.Empty(all)
		})
	}
}

func (s *ObligationsPDPSuite) Test_getTriggeredObligations_SimpleObligation_NoRequestContextPEP_Triggered() {
	resources := []*authz.Resource{
		{
			Resource: &authz.Resource_AttributeValues_{
				AttributeValues: &authz.Resource_AttributeValues{
					Fqns: []string{mockAttrValFQN1},
				},
			},
		},
	}
	decisionRequestContext := emptyDecisionRequestContext

	perResource, all, err := s.pdp.getTriggeredObligations(s.T().Context(), actionRead, resources, decisionRequestContext)

	s.Require().NoError(err)
	s.Equal([][]string{{mockObligationFQN1}}, perResource)
	s.Equal([]string{mockObligationFQN1}, all)
}

func (s *ObligationsPDPSuite) Test_getTriggeredObligations_ClientScopedObligation_Triggered() {
	resources := []*authz.Resource{
		{
			Resource: &authz.Resource_AttributeValues_{
				AttributeValues: &authz.Resource_AttributeValues{
					Fqns: []string{mockAttrValFQN2},
				},
			},
		},
	}
	decisionRequestContext := &policy.RequestContext{
		Pep: &policy.PolicyEnforcementPoint{
			ClientId: mockClientID,
		},
	}

	// Found when client provided and matching
	perResource, all, err := s.pdp.getTriggeredObligations(s.T().Context(), actionRead, resources, decisionRequestContext)
	s.Require().NoError(err)
	s.Equal([][]string{{mockObligationFQN2}}, perResource)
	s.Equal([]string{mockObligationFQN2}, all)

	// Not found when client not provided
	decisionRequestContext.Pep.ClientId = ""
	perResource, all, err = s.pdp.getTriggeredObligations(s.T().Context(), actionRead, resources, decisionRequestContext)
	s.Require().NoError(err)
	for _, r := range perResource {
		s.Empty(r)
	}
	s.Empty(all)
}

func (s *ObligationsPDPSuite) Test_getTriggeredObligations_MixedObligations_Triggered() {
	resources := []*authz.Resource{
		{
			Resource: &authz.Resource_AttributeValues_{
				AttributeValues: &authz.Resource_AttributeValues{
					Fqns: []string{mockAttrValFQN1},
				},
			},
		},
		{
			Resource: &authz.Resource_AttributeValues_{
				AttributeValues: &authz.Resource_AttributeValues{
					Fqns: []string{mockAttrValFQN2},
				},
			},
		},
		{
			Resource: &authz.Resource_AttributeValues_{
				AttributeValues: &authz.Resource_AttributeValues{
					Fqns: []string{mockAttrValFQN1, mockAttrValFQN2},
				},
			},
		},
	}
	decisionRequestContext := &policy.RequestContext{
		Pep: &policy.PolicyEnforcementPoint{
			ClientId: mockClientID,
		},
	}

	perResource, all, err := s.pdp.getTriggeredObligations(s.T().Context(), actionRead, resources, decisionRequestContext)
	s.Require().NoError(err)
	// Obligations in order of resources: unscoped, scoped, both
	s.Equal([][]string{{mockObligationFQN1}, {mockObligationFQN2}, {mockObligationFQN1, mockObligationFQN2}}, perResource)
	// Deduplicated obligations
	s.ElementsMatch([]string{mockObligationFQN1, mockObligationFQN2}, all)
}

func (s *ObligationsPDPSuite) Test_getTriggeredObligations_UnknownRegisteredResourceValue_Fails() {
	badRegResValFQN := "https://reg_res/not_found_reg_res"
	resources := []*authz.Resource{
		{
			Resource: &authz.Resource_RegisteredResourceValueFqn{
				RegisteredResourceValueFqn: badRegResValFQN,
			},
		},
	}
	decisionRequestContext := emptyDecisionRequestContext

	perResource, all, err := s.pdp.getTriggeredObligations(s.T().Context(), actionRead, resources, decisionRequestContext)
	s.Require().Error(err)
	s.Require().ErrorIs(err, ErrUnknownRegisteredResourceValue)
	s.Contains(err.Error(), badRegResValFQN, "error should contain the FQN that was not found")
	s.Empty(perResource)
	s.Empty(all)
}

func (s *ObligationsPDPSuite) Test_getTriggeredObligations_CreateAction_SimpleObligation_Triggered() {
	resources := []*authz.Resource{
		{
			Resource: &authz.Resource_AttributeValues_{
				AttributeValues: &authz.Resource_AttributeValues{
					Fqns: []string{mockAttrValFQN1},
				},
			},
		},
	}
	decisionRequestContext := emptyDecisionRequestContext

	perResource, all, err := s.pdp.getTriggeredObligations(s.T().Context(), actionCreate, resources, decisionRequestContext)

	s.Require().NoError(err)
	s.Equal([][]string{{mockObligationFQN3}}, perResource)
	s.Equal([]string{mockObligationFQN3}, all)
}

func (s *ObligationsPDPSuite) Test_getTriggeredObligations_CreateAction_NoObligationsTriggered() {
	// Test that 'create' action doesn't trigger 'read' obligations
	resources := []*authz.Resource{
		{
			Resource: &authz.Resource_AttributeValues_{
				AttributeValues: &authz.Resource_AttributeValues{
					Fqns: []string{mockAttrValFQN2},
				},
			},
		},
	}
	decisionRequestContext := &policy.RequestContext{
		Pep: &policy.PolicyEnforcementPoint{
			ClientId: mockClientID,
		},
	}

	perResource, all, err := s.pdp.getTriggeredObligations(s.T().Context(), actionCreate, resources, decisionRequestContext)

	s.Require().NoError(err)
	// No create obligations exist for mockAttrValFQN2, so nothing should be triggered
	s.Len(perResource, len(resources))
	for _, r := range perResource {
		s.Empty(r)
	}
	s.Empty(all)
}

func (s *ObligationsPDPSuite) Test_getTriggeredObligations_ReadVsCreateAction_DifferentObligationsTriggered() {
	// Test the same resource with both actions to verify action-specific filtering
	resources := []*authz.Resource{
		{
			Resource: &authz.Resource_AttributeValues_{
				AttributeValues: &authz.Resource_AttributeValues{
					Fqns: []string{mockAttrValFQN1},
				},
			},
		},
	}
	decisionRequestContext := emptyDecisionRequestContext

	// Test with 'read' action - should trigger read obligation
	perResourceRead, allRead, err := s.pdp.getTriggeredObligations(s.T().Context(), actionRead, resources, decisionRequestContext)
	s.Require().NoError(err)
	s.Equal([][]string{{mockObligationFQN1}}, perResourceRead)
	s.Equal([]string{mockObligationFQN1}, allRead)

	// Test with 'create' action - should trigger create obligation
	perResourceCreate, allCreate, err := s.pdp.getTriggeredObligations(s.T().Context(), actionCreate, resources, decisionRequestContext)
	s.Require().NoError(err)
	s.Equal([][]string{{mockObligationFQN3}}, perResourceCreate)
	s.Equal([]string{mockObligationFQN3}, allCreate)

	// Verify the obligations are different
	s.NotEqual(allRead, allCreate)
}

func (s *ObligationsPDPSuite) Test_getTriggeredObligations_RegisteredResource_ReadAction_Triggered() {
	resources := []*authz.Resource{
		{
			Resource: &authz.Resource_RegisteredResourceValueFqn{
				RegisteredResourceValueFqn: mockRegResValFQN1,
			},
		},
	}
	decisionRequestContext := emptyDecisionRequestContext

	perResource, all, err := s.pdp.getTriggeredObligations(s.T().Context(), actionRead, resources, decisionRequestContext)

	s.Require().NoError(err)
	s.Require().Len(perResource, 1, "should have obligations for exactly one resource")
	s.Require().Len(perResource[0], 1, "should have exactly one obligation for the resource")
	s.Equal(mockObligationFQN1, perResource[0][0])
	s.Require().Len(all, 1, "should have exactly one obligation total")
	s.Contains(all, mockObligationFQN1)
}

func (s *ObligationsPDPSuite) Test_getTriggeredObligations_RegisteredResource_CreateAction_Triggered() {
	resources := []*authz.Resource{
		{
			Resource: &authz.Resource_RegisteredResourceValueFqn{
				RegisteredResourceValueFqn: mockRegResValFQN1,
			},
		},
	}
	decisionRequestContext := emptyDecisionRequestContext

	perResource, all, err := s.pdp.getTriggeredObligations(s.T().Context(), actionCreate, resources, decisionRequestContext)

	s.Require().NoError(err)
	s.Require().Len(perResource, 1, "should have obligations for exactly one resource")
	s.Require().Len(perResource[0], 1, "should have exactly one obligation for the resource")
	s.Equal(mockObligationFQN3, perResource[0][0])
	s.Require().Len(all, 1, "should have exactly one obligation total")
	s.Contains(all, mockObligationFQN3)
}

func (s *ObligationsPDPSuite) Test_getTriggeredObligations_RegisteredResource_NoCreateAction_NoObligationsTriggered() {
	// Use mockRegResValFQN2 which only has read action, not create
	resources := []*authz.Resource{
		{
			Resource: &authz.Resource_RegisteredResourceValueFqn{
				RegisteredResourceValueFqn: mockRegResValFQN2,
			},
		},
	}
	decisionRequestContext := &policy.RequestContext{
		Pep: &policy.PolicyEnforcementPoint{
			ClientId: mockClientID,
		},
	}

	perResource, all, err := s.pdp.getTriggeredObligations(s.T().Context(), actionCreate, resources, decisionRequestContext)

	s.Require().NoError(err)
	s.Len(perResource, len(resources))
	for _, r := range perResource {
		s.Empty(r, "no obligations should be triggered for create action on read-only registered resource")
	}
	s.Empty(all)
}

func (s *ObligationsPDPSuite) Test_getTriggeredObligations_RegisteredResource_ClientScoped_Triggered() {
	// Use mockRegResValFQN2 which maps to mockAttrValFQN2 (has client-scoped read obligation)
	resources := []*authz.Resource{
		{
			Resource: &authz.Resource_RegisteredResourceValueFqn{
				RegisteredResourceValueFqn: mockRegResValFQN2,
			},
		},
	}
	decisionRequestContext := &policy.RequestContext{
		Pep: &policy.PolicyEnforcementPoint{
			ClientId: mockClientID,
		},
	}

	perResource, all, err := s.pdp.getTriggeredObligations(s.T().Context(), actionRead, resources, decisionRequestContext)

	s.Require().NoError(err)
	s.Require().Len(perResource, 1, "should have obligations for exactly one resource")
	s.Require().Len(perResource[0], 1, "should have exactly one obligation for the resource")
	s.Equal(mockObligationFQN2, perResource[0][0])
	s.Require().Len(all, 1, "should have exactly one obligation total")
	s.Contains(all, mockObligationFQN2)

	// Nothing should be triggered if no client
	decisionRequestContext.Pep.ClientId = ""
	perResource, all, err = s.pdp.getTriggeredObligations(s.T().Context(), actionRead, resources, decisionRequestContext)
	s.Require().NoError(err)
	s.Len(perResource, len(resources))
	for _, r := range perResource {
		s.Empty(r, "no obligations should be triggered for create action on read-only registered resource")
	}
	s.Empty(all)
}

func (s *ObligationsPDPSuite) Test_getTriggeredObligations_MixedResources_RegisteredAndDirect_Triggered() {
	// Mix registered resource and direct attribute values
	resources := []*authz.Resource{
		{
			Resource: &authz.Resource_RegisteredResourceValueFqn{
				RegisteredResourceValueFqn: mockRegResValFQN1,
			},
		},
		{
			Resource: &authz.Resource_AttributeValues_{
				AttributeValues: &authz.Resource_AttributeValues{
					Fqns: []string{mockAttrValFQN2},
				},
			},
		},
	}
	decisionRequestContext := &policy.RequestContext{
		Pep: &policy.PolicyEnforcementPoint{
			ClientId: mockClientID,
		},
	}

	perResource, all, err := s.pdp.getTriggeredObligations(s.T().Context(), actionRead, resources, decisionRequestContext)

	s.Require().NoError(err)
	s.Require().Len(perResource, 2, "should have obligations for exactly two resources")

	// First resource (registered resource mapping to mockAttrValFQN1) -> mockObligationFQN1
	s.Require().Len(perResource[0], 1, "first resource should have exactly one obligation")
	s.Equal(mockObligationFQN1, perResource[0][0])

	// Second resource (direct attribute mockAttrValFQN2 with client scoping) -> mockObligationFQN2
	s.Require().Len(perResource[1], 1, "second resource should have exactly one obligation")
	s.Equal(mockObligationFQN2, perResource[1][0])

	// Should have both obligations in total
	s.Require().Len(all, 2, "should have exactly two obligations total")
	s.ElementsMatch([]string{mockObligationFQN1, mockObligationFQN2}, all)
}

func (s *ObligationsPDPSuite) Test_getTriggeredObligations_RegisteredResource_CustomAction_Triggered() {
	// Use mockRegResValFQN3 which has custom action and should trigger mockObligationFQN4
	resources := []*authz.Resource{
		{
			Resource: &authz.Resource_RegisteredResourceValueFqn{
				RegisteredResourceValueFqn: mockRegResValFQN3,
			},
		},
	}
	decisionRequestContext := emptyDecisionRequestContext

	perResource, all, err := s.pdp.getTriggeredObligations(s.T().Context(), actionCustom, resources, decisionRequestContext)

	s.Require().NoError(err)
	s.Require().Len(perResource, 1, "should have obligations for exactly one resource")
	s.Require().Len(perResource[0], 1, "should have exactly one obligation for the resource")
	s.Equal(mockObligationFQN4, perResource[0][0])
	s.Require().Len(all, 1, "should have exactly one obligation total")
	s.Contains(all, mockObligationFQN4)

	// Same result even if a client is provided
	decisionRequestContext = &policy.RequestContext{
		Pep: &policy.PolicyEnforcementPoint{
			ClientId: mockClientID,
		},
	}
	perResource, all, err = s.pdp.getTriggeredObligations(s.T().Context(), actionCustom, resources, decisionRequestContext)

	s.Require().NoError(err)
	s.Require().Len(perResource, 1, "should have obligations for exactly one resource")
	s.Require().Len(perResource[0], 1, "should have exactly one obligation for the resource")
	s.Equal(mockObligationFQN4, perResource[0][0])
	s.Require().Len(all, 1, "should have exactly one obligation total")
	s.Contains(all, mockObligationFQN4)
}

func (s *ObligationsPDPSuite) Test_getTriggeredObligations_RegisteredResource_CustomAction_WrongAction_NoObligationsTriggered() {
	// Use mockRegResValFQN3 (has custom action) but call with read action - should trigger nothing
	resources := []*authz.Resource{
		{
			Resource: &authz.Resource_RegisteredResourceValueFqn{
				RegisteredResourceValueFqn: mockRegResValFQN3,
			},
		},
	}
	decisionRequestContext := emptyDecisionRequestContext

	perResource, all, err := s.pdp.getTriggeredObligations(s.T().Context(), actionRead, resources, decisionRequestContext)

	s.Require().NoError(err)
	s.Require().Len(perResource, 1, "should have results for exactly one resource")
	s.Empty(perResource[0], "no obligations should be triggered for read action on resource that only has custom action mapping")
	s.Empty(all, "no obligations should be triggered globally")
}

func (s *ObligationsPDPSuite) Test_getTriggeredObligations_CustomAction_RegisteredResource_Triggered() {
	// Test custom action with registered resource
	resources := []*authz.Resource{
		{
			Resource: &authz.Resource_RegisteredResourceValueFqn{
				RegisteredResourceValueFqn: mockRegResValFQN3,
			},
		},
	}
	decisionRequestContext := emptyDecisionRequestContext

	perResource, all, err := s.pdp.getTriggeredObligations(s.T().Context(), actionCustom, resources, decisionRequestContext)

	s.Require().NoError(err)
	s.Require().Len(perResource, 1, "should have obligations for exactly one resource")
	s.Require().Len(perResource[0], 1, "should have exactly one obligation for the resource")
	s.Equal(mockObligationFQN4, perResource[0][0])
	s.Require().Len(all, 1, "should have exactly one obligation total")
	s.Contains(all, mockObligationFQN4)
}

func (s *ObligationsPDPSuite) Test_getTriggeredObligations_CustomAction_MixedResources_Triggered() {
	// Test custom action with mixed resource types
	resources := []*authz.Resource{
		// Direct attribute that triggers custom obligation
		{
			Resource: &authz.Resource_AttributeValues_{
				AttributeValues: &authz.Resource_AttributeValues{
					Fqns: []string{mockAttrValFQN3},
				},
			},
		},
		// Registered resource that also triggers custom obligation
		{
			Resource: &authz.Resource_RegisteredResourceValueFqn{
				RegisteredResourceValueFqn: mockRegResValFQN3,
			},
		},
		// Registered resource that doesn't trigger custom obligation (only has read action)
		{
			Resource: &authz.Resource_RegisteredResourceValueFqn{
				RegisteredResourceValueFqn: mockRegResValFQN2,
			},
		},
	}
	decisionRequestContext := emptyDecisionRequestContext

	perResource, all, err := s.pdp.getTriggeredObligations(s.T().Context(), actionCustom, resources, decisionRequestContext)

	s.Require().NoError(err)
	s.Require().Len(perResource, 3, "should have results for exactly three resources")

	// First resource (direct attribute) should trigger custom obligation
	s.Require().Len(perResource[0], 1, "first resource should have exactly one obligation")
	s.Equal(mockObligationFQN4, perResource[0][0])

	// Second resource (registered resource with custom action) should trigger custom obligation
	s.Require().Len(perResource[1], 1, "second resource should have exactly one obligation")
	s.Equal(mockObligationFQN4, perResource[1][0])

	// Third resource (registered resource without custom action) should trigger no obligations
	s.Empty(perResource[2], "third resource should have no obligations for custom action")

	// Should have exactly one unique obligation in total (deduplicated)
	s.Require().Len(all, 1, "should have exactly one unique obligation total")
	s.Contains(all, mockObligationFQN4)
}

func (s *ObligationsPDPSuite) Test_getAllObligationsAreFulfilled_MoreFulfilledThanTriggered() {
	allTriggeredObligationValueFQNs := []string{mockObligationFQN1, mockObligationFQN2}
	pepFulfillableObligationValueFQNs := []string{mockObligationFQN1, mockObligationFQN2, mockObligationFQN3}
	decisionRequestContext := emptyDecisionRequestContext

	fulfilled := s.pdp.getAllObligationsAreFulfilled(s.T().Context(), allTriggeredObligationValueFQNs, pepFulfillableObligationValueFQNs, decisionRequestContext)
	s.True(fulfilled)
}

func (s *ObligationsPDPSuite) Test_getAllObligationsAreFulfilled_ExactMatch() {
	allTriggeredObligationValueFQNs := []string{mockObligationFQN1, mockObligationFQN2}
	pepFulfillableObligationValueFQNs := []string{mockObligationFQN2, mockObligationFQN1}
	decisionRequestContext := emptyDecisionRequestContext

	fulfilled := s.pdp.getAllObligationsAreFulfilled(s.T().Context(), allTriggeredObligationValueFQNs, pepFulfillableObligationValueFQNs, decisionRequestContext)
	s.True(fulfilled)
}

func (s *ObligationsPDPSuite) Test_getAllObligationsAreFulfilled_MissingObligation() {
	allTriggeredObligationValueFQNs := []string{mockObligationFQN1, mockObligationFQN3}
	pepFulfillableObligationValueFQNs := []string{mockObligationFQN1}
	decisionRequestContext := emptyDecisionRequestContext

	fulfilled := s.pdp.getAllObligationsAreFulfilled(s.T().Context(), allTriggeredObligationValueFQNs, pepFulfillableObligationValueFQNs, decisionRequestContext)

	s.False(fulfilled)
}

func (s *ObligationsPDPSuite) Test_getAllObligationsAreFulfilled_EmptyTriggered() {
	allTriggeredObligationValueFQNs := []string{}
	pepFulfillableObligationValueFQNs := []string{mockObligationFQN1, mockObligationFQN2}
	decisionRequestContext := emptyDecisionRequestContext

	fulfilled := s.pdp.getAllObligationsAreFulfilled(s.T().Context(), allTriggeredObligationValueFQNs, pepFulfillableObligationValueFQNs, decisionRequestContext)
	s.True(fulfilled)
}

func (s *ObligationsPDPSuite) Test_getAllObligationsAreFulfilled_EmptyFulfillable() {
	allTriggeredObligationValueFQNs := []string{mockObligationFQN1}
	pepFulfillableObligationValueFQNs := []string{}
	decisionRequestContext := emptyDecisionRequestContext

	fulfilled := s.pdp.getAllObligationsAreFulfilled(s.T().Context(), allTriggeredObligationValueFQNs, pepFulfillableObligationValueFQNs, decisionRequestContext)

	s.False(fulfilled)
}

func (s *ObligationsPDPSuite) Test_getAllObligationsAreFulfilled_BothEmpty() {
	allTriggeredObligationValueFQNs := []string{}
	pepFulfillableObligationValueFQNs := []string{}
	decisionRequestContext := emptyDecisionRequestContext

	fulfilled := s.pdp.getAllObligationsAreFulfilled(s.T().Context(), allTriggeredObligationValueFQNs, pepFulfillableObligationValueFQNs, decisionRequestContext)
	s.True(fulfilled)
}

func (s *ObligationsPDPSuite) Test_getAllObligationsAreFulfilled_SingleObligation_Fulfilled() {
	allTriggeredObligationValueFQNs := []string{mockObligationFQN1}
	pepFulfillableObligationValueFQNs := []string{mockObligationFQN1}
	decisionRequestContext := emptyDecisionRequestContext

	fulfilled := s.pdp.getAllObligationsAreFulfilled(s.T().Context(), allTriggeredObligationValueFQNs, pepFulfillableObligationValueFQNs, decisionRequestContext)
	s.True(fulfilled)
}

func (s *ObligationsPDPSuite) Test_getAllObligationsAreFulfilled_SingleObligation_NotFulfilled() {
	allTriggeredObligationValueFQNs := []string{mockObligationFQN3}
	pepFulfillableObligationValueFQNs := []string{mockObligationFQN2}
	decisionRequestContext := emptyDecisionRequestContext

	fulfilled := s.pdp.getAllObligationsAreFulfilled(s.T().Context(), allTriggeredObligationValueFQNs, pepFulfillableObligationValueFQNs, decisionRequestContext)

	s.False(fulfilled)
}

func (s *ObligationsPDPSuite) Test_getAllObligationsAreFulfilled_DuplicateTriggered() {
	allTriggeredObligationValueFQNs := []string{mockObligationFQN1, mockObligationFQN1, mockObligationFQN2}
	pepFulfillableObligationValueFQNs := []string{mockObligationFQN1, mockObligationFQN2}
	decisionRequestContext := emptyDecisionRequestContext

	fulfilled := s.pdp.getAllObligationsAreFulfilled(s.T().Context(), allTriggeredObligationValueFQNs, pepFulfillableObligationValueFQNs, decisionRequestContext)
	s.True(fulfilled)
}

func (s *ObligationsPDPSuite) Test_getAllObligationsAreFulfilled_DuplicateFulfillable() {
	allTriggeredObligationValueFQNs := []string{mockObligationFQN1, mockObligationFQN2}
	pepFulfillableObligationValueFQNs := []string{mockObligationFQN1, mockObligationFQN1, mockObligationFQN2, mockObligationFQN2}
	decisionRequestContext := emptyDecisionRequestContext

	fulfilled := s.pdp.getAllObligationsAreFulfilled(s.T().Context(), allTriggeredObligationValueFQNs, pepFulfillableObligationValueFQNs, decisionRequestContext)
	s.True(fulfilled)
}

func (s *ObligationsPDPSuite) Test_getAllObligationsAreFulfilled_AllObligations_Fulfilled() {
	allTriggeredObligationValueFQNs := []string{mockObligationFQN1, mockObligationFQN2, mockObligationFQN3, mockObligationFQN4}
	pepFulfillableObligationValueFQNs := []string{mockObligationFQN4, mockObligationFQN3, mockObligationFQN2, mockObligationFQN1}
	decisionRequestContext := emptyDecisionRequestContext

	fulfilled := s.pdp.getAllObligationsAreFulfilled(s.T().Context(), allTriggeredObligationValueFQNs, pepFulfillableObligationValueFQNs, decisionRequestContext)
	s.True(fulfilled)
}

func (s *ObligationsPDPSuite) Test_getAllObligationsAreFulfilled_WithPEPClientID() {
	allTriggeredObligationValueFQNs := []string{mockObligationFQN1, mockObligationFQN2}
	pepFulfillableObligationValueFQNs := []string{mockObligationFQN1, mockObligationFQN2}
	decisionRequestContext := &policy.RequestContext{
		Pep: &policy.PolicyEnforcementPoint{
			ClientId: mockClientID,
		},
	}

	fulfilled := s.pdp.getAllObligationsAreFulfilled(s.T().Context(), allTriggeredObligationValueFQNs, pepFulfillableObligationValueFQNs, decisionRequestContext)
	s.True(fulfilled)
}

func (s *ObligationsPDPSuite) Test_GetAllTriggeredObligationsAreFulfilled_Smoke() {
	type args struct {
		resources              []*authz.Resource
		action                 *policy.Action
		decisionRequestContext *policy.RequestContext
		pepFulfillable         []string
	}
	tests := []struct {
		name             string
		args             args
		wantAllFulfilled bool
		wantPerResource  [][]string
	}{
		{
			name: "fulfilled",
			args: args{
				action: actionRead,
				resources: []*authz.Resource{
					{
						Resource: &authz.Resource_AttributeValues_{
							AttributeValues: &authz.Resource_AttributeValues{
								Fqns: []string{mockAttrValFQN1},
							},
						},
					},
				},
				pepFulfillable: []string{mockObligationFQN1},
			},
			wantAllFulfilled: true,
			wantPerResource:  [][]string{{mockObligationFQN1}},
		},
		{
			name: "unfulfilled",
			args: args{
				action: actionRead,
				resources: []*authz.Resource{
					{
						Resource: &authz.Resource_AttributeValues_{
							AttributeValues: &authz.Resource_AttributeValues{
								Fqns: []string{mockAttrValFQN1},
							},
						},
					},
				},
				pepFulfillable: []string{mockObligationFQN2},
			},
			wantAllFulfilled: false,
			wantPerResource:  [][]string{{mockObligationFQN1}},
		},
		{
			name: "no obligations triggered",
			args: args{
				action: actionRead,
				resources: []*authz.Resource{
					{
						Resource: &authz.Resource_AttributeValues_{
							AttributeValues: &authz.Resource_AttributeValues{
								Fqns: []string{mockAttrValFQN3},
							},
						},
					},
				},
			},
			wantAllFulfilled: true,
			wantPerResource:  [][]string{{}},
		},
	}
	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			gotAllFulfilled, gotPerResource, err := s.pdp.GetAllTriggeredObligationsAreFulfilled(t.Context(), tt.args.resources, tt.args.action, tt.args.decisionRequestContext, tt.args.pepFulfillable)
			s.Require().NoError(err)
			s.Equal(tt.wantAllFulfilled, gotAllFulfilled)
			s.Equal(tt.wantPerResource, gotPerResource)
		})
	}
}

//
// Test suite helpers
//

func (s *ObligationsPDPSuite) createObligation(oblFQN, attrValFQN, clientID string, action *policy.Action) *policy.Obligation {
	trigger := &policy.ObligationTrigger{
		Action:         action,
		AttributeValue: &policy.Value{Fqn: attrValFQN},
	}

	if clientID != "" {
		trigger.Context = []*policy.RequestContext{
			{
				Pep: &policy.PolicyEnforcementPoint{
					ClientId: clientID,
				},
			},
		}
	}

	return &policy.Obligation{
		Values: []*policy.ObligationValue{
			{
				Fqn:      oblFQN,
				Triggers: []*policy.ObligationTrigger{trigger},
			},
		},
	}
}

func (s *ObligationsPDPSuite) createAttributesByValueFQN(attrValFQN, attrName string) map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue {
	return map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
		attrValFQN: {
			Attribute: &policy.Attribute{Name: attrName},
			Value:     &policy.Value{Fqn: attrValFQN},
		},
	}
}
