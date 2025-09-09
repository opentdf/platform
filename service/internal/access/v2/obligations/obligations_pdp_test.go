package obligations

import (
	"context"
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
	mockObligationFQN1 = "https://example.org/obl/some_obligation/value/some_value"
	mockObligationFQN2 = "https://example.org/obl/another_obligation/value/another_value"
	mockClientID       = "mock-client-id"
)

var mockAction = &policy.Action{Name: "read"}

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
	}

	// Mock obligations
	allObligations := []*policy.Obligation{
		{
			Values: []*policy.ObligationValue{
				{
					Fqn: mockObligationFQN1,
					Triggers: []*policy.ObligationTrigger{
						{
							Action:         mockAction,
							AttributeValue: &policy.Value{Fqn: mockAttrValFQN1},
						},
					},
				},
				{
					Fqn: mockObligationFQN2,
					Triggers: []*policy.ObligationTrigger{
						{
							Action:         mockAction,
							AttributeValue: &policy.Value{Fqn: mockAttrValFQN2},
							Context: &policy.ObligationTrigger_Context{
								Pep: &policy.ObligationTrigger_Context_PEP{
									ClientId: mockClientID,
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

func (s *ObligationsPDPSuite) Test_NoObligationsTriggered_AttributeValue() {
	nonObligatedAttributeValueFQN := "https://example.org/attr/other/value/val"
	resources := []*authz.Resource{
		{
			Resource: &authz.Resource_AttributeValues_{
				AttributeValues: &authz.Resource_AttributeValues{
					Fqns: []string{nonObligatedAttributeValueFQN},
				},
			},
		},
	}
	decisionRequestContext := &mockDecisionRequestContext{}

	perResource, all, err := s.pdp.GetRequiredObligations(context.Background(), mockAction, resources, decisionRequestContext)

	s.NoError(err)
	s.Len(perResource, len(resources))
	for _, r := range perResource {
		s.Empty(r)
	}
	s.Empty(all)
}

func (s *ObligationsPDPSuite) Test_NoObligationsTriggered_Action() {
	nonObligatedAction := &policy.Action{Name: "random-name"}
	resources := []*authz.Resource{
		{
			Resource: &authz.Resource_AttributeValues_{
				AttributeValues: &authz.Resource_AttributeValues{
					Fqns: []string{mockAttrValFQN1},
				},
			},
		},
	}
	decisionRequestContext := &mockDecisionRequestContext{}

	perResource, all, err := s.pdp.GetRequiredObligations(context.Background(), nonObligatedAction, resources, decisionRequestContext)

	s.NoError(err)
	s.Len(perResource, len(resources))
	for _, r := range perResource {
		s.Empty(r)
	}
	s.Empty(all)
}
func (s *ObligationsPDPSuite) Test_NoObligationsTriggered_RequestContext() {
	unknownClientID := "unknown-client-id"
	resources := []*authz.Resource{
		{
			Resource: &authz.Resource_AttributeValues_{
				AttributeValues: &authz.Resource_AttributeValues{
					Fqns: []string{mockAttrValFQN1},
				},
			},
		},
	}
	decisionRequestContext := &mockDecisionRequestContext{
		PEP: struct{ clientID string }{clientID: unknownClientID},
	}

	perResource, all, err := s.pdp.GetRequiredObligations(context.Background(), mockAction, resources, decisionRequestContext)

	s.NoError(err)
	s.Len(perResource, len(resources))
	for _, r := range perResource {
		s.Empty(r)
	}
	s.Empty(all)
}

func (s *ObligationsPDPSuite) Test_SimpleObligationTriggered() {
	resources := []*authz.Resource{
		{
			Resource: &authz.Resource_AttributeValues_{
				AttributeValues: &authz.Resource_AttributeValues{
					Fqns: []string{mockAttrValFQN1},
				},
			},
		},
	}
	decisionRequestContext := &mockDecisionRequestContext{}

	perResource, all, err := s.pdp.GetRequiredObligations(context.Background(), mockAction, resources, decisionRequestContext)

	s.NoError(err)
	s.Equal([][]string{{mockObligationFQN1}}, perResource)
	s.Equal([]string{mockObligationFQN1}, all)
}

func (s *ObligationsPDPSuite) Test_ClientScopedObligationTriggered() {
	resources := []*authz.Resource{
		{
			Resource: &authz.Resource_AttributeValues_{
				AttributeValues: &authz.Resource_AttributeValues{
					Fqns: []string{mockAttrValFQN2},
				},
			},
		},
	}
	decisionRequestContext := &mockDecisionRequestContext{
		PEP: struct{ clientID string }{clientID: mockClientID},
	}

	perResource, all, err := s.pdp.GetRequiredObligations(context.Background(), mockAction, resources, decisionRequestContext)

	s.NoError(err)
	s.Equal([][]string{{mockObligationFQN2}}, perResource)
	s.Equal([]string{mockObligationFQN2}, all)
}

func (s *ObligationsPDPSuite) Test_ClientScopedObligationNotTriggered() {
	resources := []*authz.Resource{
		{
			Resource: &authz.Resource_AttributeValues_{
				AttributeValues: &authz.Resource_AttributeValues{
					Fqns: []string{mockAttrValFQN2},
				},
			},
		},
	}
	decisionRequestContext := &mockDecisionRequestContext{
		PEP: struct{ clientID string }{clientID: "different-client-id"},
	}

	perResource, all, err := s.pdp.GetRequiredObligations(context.Background(), mockAction, resources, decisionRequestContext)

	s.NoError(err)
	s.Equal([][]string{{}}, perResource)
	s.Empty(all)
}

func (s *ObligationsPDPSuite) Test_MixedObligationsTriggered() {
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
	}
	decisionRequestContext := &mockDecisionRequestContext{
		PEP: struct{ clientID string }{clientID: mockClientID},
	}

	perResource, all, err := s.pdp.GetRequiredObligations(context.Background(), mockAction, resources, decisionRequestContext)

	s.NoError(err)
	s.Equal([][]string{{mockObligationFQN1}, {mockObligationFQN2}}, perResource)
	s.ElementsMatch([]string{mockObligationFQN1, mockObligationFQN2}, all)
}

func (s *ObligationsPDPSuite) Test_UnsupportedResourceType() {
	resources := []*authz.Resource{
		{
			Resource: &authz.Resource_RegisteredResourceValueFqn{
				RegisteredResourceValueFqn: "unsupported",
			},
		},
	}
	decisionRequestContext := &mockDecisionRequestContext{}

	_, _, err := s.pdp.GetRequiredObligations(context.Background(), mockAction, resources, decisionRequestContext)

	s.Error(err)
}
