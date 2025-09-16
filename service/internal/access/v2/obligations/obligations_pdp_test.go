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
	mockAttrValFQN1    = "https://example.org/attr/attr1/value/val1"
	mockAttrValFQN2    = "https://example.org/attr/attr2/value/val2"
	mockAttrValFQN3    = "https://example.org/attr/attr2/value/val3"
	mockObligationFQN1 = "https://example.org/obl/some_obligation/value/some_value"
	mockObligationFQN2 = "https://example.org/obl/another_obligation/value/another_value"
	mockClientID       = "mock-client-id"
)

var (
	actionNameRead = "read"
	actionRead     = &policy.Action{Name: actionNameRead}
)

// TODO: registered resources

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

	// Mock obligations
	allObligations := []*policy.Obligation{
		{
			Values: []*policy.ObligationValue{
				// No client PEP scope
				{
					Fqn: mockObligationFQN1,
					Triggers: []*policy.ObligationTrigger{
						{
							Action:         actionRead,
							AttributeValue: &policy.Value{Fqn: mockAttrValFQN1},
						},
					},
				},
				// Scoped to the mockClientID PEP
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
			},
		},
	}

	// Create a new PDP instance
	var err error
	s.pdp, err = NewObligationsPolicyDecisionPoint(
		s.T().Context(),
		logger.CreateTestLogger(),
		attributesByValueFQN,
		nil,
		allObligations,
	)
	s.Require().NoError(err)
}

func (s *ObligationsPDPSuite) Test_NewObligationsPolicyDecisionPoint_Success() {
	attributesByValueFQN := s.createAttributesByValueFQN(mockAttrValFQN1, "attr1")
	var noClientID string
	allObligations := []*policy.Obligation{s.createObligation(mockObligationFQN1, mockAttrValFQN1, noClientID, actionRead)}

	pdp, err := NewObligationsPolicyDecisionPoint(
		s.T().Context(),
		logger.CreateTestLogger(),
		attributesByValueFQN,
		nil,
		allObligations,
	)

	s.Require().NoError(err)
	s.NotNil(pdp)
	s.NotNil(pdp.logger)
	s.Equal(attributesByValueFQN, pdp.attributesByValueFQN)
	s.Empty(pdp.registeredResourceValuesByFQN)
	s.Len(pdp.obligationValuesByFQN, 1)
	s.Contains(pdp.obligationValuesByFQN, mockObligationFQN1)
	s.NotNil(pdp.simpleTriggerActionsToAttributes)
	s.NotNil(pdp.clientIDScopedTriggerActionsToAttributes)
}

func (s *ObligationsPDPSuite) Test_NewObligationsPolicyDecisionPoint_WithClientScoped() {
	attributesByValueFQN := s.createAttributesByValueFQN(mockAttrValFQN2, "attr2")
	allObligations := []*policy.Obligation{s.createObligation(mockObligationFQN2, mockAttrValFQN2, mockClientID, actionRead)}

	pdp, err := NewObligationsPolicyDecisionPoint(
		s.T().Context(),
		logger.CreateTestLogger(),
		attributesByValueFQN,
		nil,
		allObligations,
	)

	s.Require().NoError(err)
	s.NotNil(pdp)
	s.Len(pdp.obligationValuesByFQN, 1)
	s.Contains(pdp.obligationValuesByFQN, mockObligationFQN2)
	s.Contains(pdp.clientIDScopedTriggerActionsToAttributes, mockClientID)
	s.Contains(pdp.clientIDScopedTriggerActionsToAttributes[mockClientID], actionNameRead)
	s.Contains(pdp.clientIDScopedTriggerActionsToAttributes[mockClientID][actionNameRead], mockAttrValFQN2)
}

func (s *ObligationsPDPSuite) Test_NewObligationsPolicyDecisionPoint_EmptyClientID_Fails() {
	attributesByValueFQN := s.createAttributesByValueFQN(mockAttrValFQN1, "attr1")

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
		nil,
		allObligations,
	)

	s.Require().Error(err)
	s.Nil(pdp)
}

func (s *ObligationsPDPSuite) Test_NewObligationsPolicyDecisionPoint_EmptyObligations() {
	attributesByValueFQN := s.createAttributesByValueFQN(mockAttrValFQN1, "attr1")

	pdp, err := NewObligationsPolicyDecisionPoint(
		s.T().Context(),
		logger.CreateTestLogger(),
		attributesByValueFQN,
		nil,
		[]*policy.Obligation{},
	)

	s.Require().NoError(err)
	s.NotNil(pdp)
	s.Empty(pdp.obligationValuesByFQN)
	s.Empty(pdp.simpleTriggerActionsToAttributes)
	s.Empty(pdp.clientIDScopedTriggerActionsToAttributes)
}

func (s *ObligationsPDPSuite) Test_GetRequiredObligations_NoObligationsTriggered() {
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
			perResource, all, err := s.pdp.GetRequiredObligations(t.Context(), tt.args.action, tt.args.resources, tt.args.decisionRequestContext)
			s.Require().NoError(err)
			s.Len(perResource, len(tt.args.resources))

			for _, r := range perResource {
				s.Empty(r)
			}
			s.Empty(all)
		})
	}
}

func (s *ObligationsPDPSuite) Test_GetRequiredObligations_SimpleObligation_NoRequestContextPEP_Triggered() {
	resources := []*authz.Resource{
		{
			Resource: &authz.Resource_AttributeValues_{
				AttributeValues: &authz.Resource_AttributeValues{
					Fqns: []string{mockAttrValFQN1},
				},
			},
		},
	}
	decisionRequestContext := &policy.RequestContext{}

	perResource, all, err := s.pdp.GetRequiredObligations(s.T().Context(), actionRead, resources, decisionRequestContext)

	s.Require().NoError(err)
	s.Equal([][]string{{mockObligationFQN1}}, perResource)
	s.Equal([]string{mockObligationFQN1}, all)
}

func (s *ObligationsPDPSuite) Test_GetRequiredObligations_ClientScopedObligation_Triggered() {
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

	perResource, all, err := s.pdp.GetRequiredObligations(s.T().Context(), actionRead, resources, decisionRequestContext)

	s.Require().NoError(err)
	s.Equal([][]string{{mockObligationFQN2}}, perResource)
	s.Equal([]string{mockObligationFQN2}, all)
}

func (s *ObligationsPDPSuite) Test_GetRequiredObligations_MixedObligations_Triggered() {
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

	perResource, all, err := s.pdp.GetRequiredObligations(s.T().Context(), actionRead, resources, decisionRequestContext)
	s.Require().NoError(err)
	// Obligations in order of resources: unscoped, scoped, both
	s.Equal([][]string{{mockObligationFQN1}, {mockObligationFQN2}, {mockObligationFQN1, mockObligationFQN2}}, perResource)
	// Deduplicated obligations
	s.ElementsMatch([]string{mockObligationFQN1, mockObligationFQN2}, all)
}

func (s *ObligationsPDPSuite) Test_GetRequiredObligations_UnknownRegisteredResourceValue_Fails() {
	badRegResValFQN := "https://reg_res/not_found_reg_res"
	resources := []*authz.Resource{
		{
			Resource: &authz.Resource_RegisteredResourceValueFqn{
				RegisteredResourceValueFqn: badRegResValFQN,
			},
		},
	}
	decisionRequestContext := &policy.RequestContext{}

	perResource, all, err := s.pdp.GetRequiredObligations(s.T().Context(), actionRead, resources, decisionRequestContext)
	s.Require().Error(err)
	s.Empty(perResource)
	s.Empty(all)
	s.Contains(err.Error(), badRegResValFQN)
}

func (s *ObligationsPDPSuite) createAttributesByValueFQN(attrValFQN, attrName string) map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue {
	return map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
		attrValFQN: {
			Attribute: &policy.Attribute{Name: attrName},
			Value:     &policy.Value{Fqn: attrValFQN},
		},
	}
}

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
