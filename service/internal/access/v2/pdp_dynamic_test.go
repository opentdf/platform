package access

import (
	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/policy"
)

// Test_GetDecision_DynamicValueMapping_MultiValue exercises the full
// GetDecision path for dynamic, definition-level value entitlement (DSPX-2754), focused on
// the multi-value rule semantics: a single resource carries two dynamic values under one
// definition while the entity is entitled to only one. ANY_OF should permit, ALL_OF deny.
func (s *PDPTestSuite) Test_GetDecision_DynamicValueMapping_MultiValue() {
	const ns = "hospital.co"
	defFQN := createAttrFQN(ns, "mrn")
	v123 := createAttrValueFQN(ns, "mrn", "mrn-123")
	v456 := createAttrValueFQN(ns, "mrn", "mrn-456")
	namespace := &policy.Namespace{Name: ns, Fqn: "https://" + ns}

	buildPDP := func(rule policy.AttributeRuleTypeEnum) *PolicyDecisionPoint {
		// A dynamic definition has no statically provisioned values.
		attr := &policy.Attribute{
			Fqn:       defFQN,
			Rule:      rule,
			Namespace: namespace,
		}
		mapping := &policy.DynamicValueMapping{
			AttributeDefinition: attr,
			ValueResolver: &policy.DynamicValueResolver{
				SubjectExternalSelectorValue: ".properties.patientAssignments[]",
				Operator:                     policy.DynamicValueOperatorEnum_DYNAMIC_VALUE_OPERATOR_ENUM_RESOURCE_VALUE_IN,
			},
			Actions:   []*policy.Action{testActionRead},
			Namespace: namespace,
		}
		pdp, err := NewPolicyDecisionPointWithDynamicValueMappings(
			s.T().Context(),
			s.logger,
			[]*policy.Attribute{attr},
			[]*policy.SubjectMapping{},
			[]*policy.DynamicValueMapping{mapping},
			nil,
			false, // allowDirectEntitlements: dynamic mappings synthesize values on their own
			false, // namespacedPolicy
		)
		s.Require().NoError(err)
		s.Require().NotNil(pdp)
		return pdp
	}

	// Entity is assigned mrn-123 only (entitled to one of the two requested values).
	entityOne := s.createEntityWithProps("provider-1", map[string]interface{}{
		"patientAssignments": []interface{}{"mrn-123"},
	})
	// Single resource carrying BOTH dynamic values under the one definition.
	resourceBothValues := []*authz.Resource{createAttributeValueResource("resource-1", v123, v456)}

	s.Run("ANY_OF permits when entitled to one of two dynamic values", func() {
		pdp := buildPDP(policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
		decision, entitlements, err := pdp.GetDecision(s.T().Context(), entityOne, testActionRead, resourceBothValues)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.AllPermitted, "ANY_OF: one entitled dynamic value suffices")
		s.Contains(entitlements, v123, "should be entitled to the matched dynamic value")
		s.NotContains(entitlements, v456, "should not be entitled to the unmatched dynamic value")
		s.Require().Contains(entitlements[v123], testActionRead)
	})

	s.Run("ALL_OF denies when entitled to only one of two dynamic values", func() {
		pdp := buildPDP(policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF)
		decision, _, err := pdp.GetDecision(s.T().Context(), entityOne, testActionRead, resourceBothValues)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted, "ALL_OF: mrn-456 is not entitled, so the resource is denied")
	})

	s.Run("ALL_OF permits when entitled to both dynamic values", func() {
		entityBoth := s.createEntityWithProps("provider-2", map[string]interface{}{
			"patientAssignments": []interface{}{"mrn-123", "mrn-456"},
		})
		pdp := buildPDP(policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF)
		decision, _, err := pdp.GetDecision(s.T().Context(), entityBoth, testActionRead, resourceBothValues)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.AllPermitted, "ALL_OF: both dynamic values are entitled")
	})
}
