package access

import (
	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Deactivating an attribute value must fail closed on every decision path: data already tagged
// with the value can no longer be decrypted, and no entitlement source may resurrect it.
// Regression coverage for a TDF remaining decryptable after its value was deactivated.

const deactivatedTestNamespace = "deactivation.example.com"

var (
	testDeactivatedProjectFQN          = createAttrFQN(deactivatedTestNamespace, "project")
	testDeactivatedProjectAlphaActive  = createAttrValueFQN(deactivatedTestNamespace, "project", "alpha")
	testDeactivatedProjectBetaInactive = createAttrValueFQN(deactivatedTestNamespace, "project", "beta")

	testDeactivatedClearanceFQN            = createAttrFQN(deactivatedTestNamespace, "clearance")
	testDeactivatedClearanceHighInactive   = createAttrValueFQN(deactivatedTestNamespace, "clearance", "high")
	testDeactivatedClearanceLowActive      = createAttrValueFQN(deactivatedTestNamespace, "clearance", "low")
	testDeactivatedClearanceLowestInactive = createAttrValueFQN(deactivatedTestNamespace, "clearance", "lowest")

	testDeactivatedArchivedFQN      = createAttrFQN(deactivatedTestNamespace, "archived")
	testDeactivatedArchivedValue    = createAttrValueFQN(deactivatedTestNamespace, "archived", "value1")
	testDeactivatedArchivedAdHocVal = createAttrValueFQN(deactivatedTestNamespace, "archived", "adhoc")
)

// deactivationProjectAttr is an ANY_OF definition: alpha is active, beta is deactivated.
func deactivationProjectAttr() *policy.Attribute {
	return &policy.Attribute{
		Fqn:       testDeactivatedProjectFQN,
		Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Namespace: &policy.Namespace{Name: deactivatedTestNamespace, Fqn: "https://" + deactivatedTestNamespace},
		Values: []*policy.Value{
			{Fqn: testDeactivatedProjectAlphaActive, Value: "alpha", Active: wrapperspb.Bool(true)},
			{Fqn: testDeactivatedProjectBetaInactive, Value: "beta", Active: wrapperspb.Bool(false)},
		},
	}
}

// deactivationClearanceAttr is a HIERARCHY definition, highest first, with a deactivated value
// both above and below the active one.
func deactivationClearanceAttr() *policy.Attribute {
	return &policy.Attribute{
		Fqn:       testDeactivatedClearanceFQN,
		Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
		Namespace: &policy.Namespace{Name: deactivatedTestNamespace, Fqn: "https://" + deactivatedTestNamespace},
		Values: []*policy.Value{
			{Fqn: testDeactivatedClearanceHighInactive, Value: "high", Active: wrapperspb.Bool(false)},
			{Fqn: testDeactivatedClearanceLowActive, Value: "low", Active: wrapperspb.Bool(true)},
			{Fqn: testDeactivatedClearanceLowestInactive, Value: "lowest", Active: wrapperspb.Bool(false)},
		},
	}
}

// deactivationArchivedAttr is a deactivated ANY_OF definition whose values are all still active.
// The cascade_deactivation trigger makes this state unreachable in the database; it exists to
// cover the defensive definition-state check.
func deactivationArchivedAttr() *policy.Attribute {
	return &policy.Attribute{
		Fqn:       testDeactivatedArchivedFQN,
		Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Active:    wrapperspb.Bool(false),
		Namespace: &policy.Namespace{Name: deactivatedTestNamespace, Fqn: "https://" + deactivatedTestNamespace},
		Values: []*policy.Value{
			{Fqn: testDeactivatedArchivedValue, Value: "value1", Active: wrapperspb.Bool(true)},
		},
	}
}

// Test_GetDecision_DeactivatedValue_SubjectMappings covers the standard access PDP path: an entity
// entitled through a subject mapping on a value that is later deactivated.
func (s *PDPTestSuite) Test_GetDecision_DeactivatedValue_SubjectMappings() {
	ctx := s.T().Context()

	attr := deactivationProjectAttr()
	subjectMappings := []*policy.SubjectMapping{
		createSimpleSubjectMapping(testDeactivatedProjectAlphaActive, "alpha",
			[]*policy.Action{testActionRead}, ".properties.project[]", []string{"alpha"}, nil),
		createSimpleSubjectMapping(testDeactivatedProjectBetaInactive, "beta",
			[]*policy.Action{testActionRead}, ".properties.project[]", []string{"beta"}, nil),
	}

	pdp, err := NewPolicyDecisionPoint(ctx, s.logger, []*policy.Attribute{attr}, subjectMappings, nil, false, false)
	s.Require().NoError(err)

	entity := s.createEntityWithProps("entity-both-projects", map[string]interface{}{
		"project": []interface{}{"alpha", "beta"},
	})

	s.Run("resource tagged with the deactivated value is denied", func() {
		decision, entitlements, err := pdp.GetDecision(ctx, entity, testActionRead, []*authz.Resource{
			createAttributeValueResource(testDeactivatedProjectBetaInactive, testDeactivatedProjectBetaInactive),
		})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted, "subject mapping must not entitle a deactivated value")
		s.NotContains(entitlements, testDeactivatedProjectBetaInactive)
	})

	s.Run("ANY_OF resource carrying the deactivated value alongside an active one is denied", func() {
		decision, _, err := pdp.GetDecision(ctx, entity, testActionRead, []*authz.Resource{
			createAttributeValueResource("mixed-state-resource", testDeactivatedProjectAlphaActive, testDeactivatedProjectBetaInactive),
		})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted, "a resource carrying a deactivated value must fail closed even under ANY_OF")
	})

	s.Run("active sibling value is unaffected", func() {
		decision, entitlements, err := pdp.GetDecision(ctx, entity, testActionRead, []*authz.Resource{
			createAttributeValueResource(testDeactivatedProjectAlphaActive, testDeactivatedProjectAlphaActive),
		})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.AllPermitted)
		s.Contains(entitlements, testDeactivatedProjectAlphaActive)
	})
}

// Test_GetDecision_DeactivatedValue_Hierarchy asserts a deactivated higher hierarchy value neither
// entitles itself nor cascades entitlement down to the active values beneath it.
func (s *PDPTestSuite) Test_GetDecision_DeactivatedValue_Hierarchy() {
	ctx := s.T().Context()

	attr := deactivationClearanceAttr()
	subjectMappings := []*policy.SubjectMapping{
		createSimpleSubjectMapping(testDeactivatedClearanceHighInactive, "high",
			[]*policy.Action{testActionRead}, ".properties.clearance", []string{"high"}, nil),
	}

	pdp, err := NewPolicyDecisionPoint(ctx, s.logger, []*policy.Attribute{attr}, subjectMappings, nil, false, false)
	s.Require().NoError(err)

	entity := s.createEntityWithProps("entity-high-clearance", map[string]interface{}{
		"clearance": "high",
	})

	s.Run("deactivated highest value denies the resource tagged with it", func() {
		decision, _, err := pdp.GetDecision(ctx, entity, testActionRead, []*authz.Resource{
			createAttributeValueResource(testDeactivatedClearanceHighInactive, testDeactivatedClearanceHighInactive),
		})
		s.Require().NoError(err)
		s.False(decision.AllPermitted)
	})

	s.Run("deactivated higher value does not entitle a lower active value", func() {
		decision, _, err := pdp.GetDecision(ctx, entity, testActionRead, []*authz.Resource{
			createAttributeValueResource(testDeactivatedClearanceLowActive, testDeactivatedClearanceLowActive),
		})
		s.Require().NoError(err)
		s.False(decision.AllPermitted, "hierarchy must not cascade entitlement from a deactivated value")
	})
}

// Test_GetDecision_DeactivatedValue_DynamicValueMappings covers the experimental dynamic,
// definition-level value mapping path.
func (s *PDPTestSuite) Test_GetDecision_DeactivatedValue_DynamicValueMappings() {
	ctx := s.T().Context()

	attr := deactivationProjectAttr()
	mapping := &policy.DynamicValueMapping{
		AttributeDefinition: attr,
		ValueResolver: &policy.DynamicValueResolver{
			SubjectExternalSelectorValue: ".properties.project[]",
			Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
		},
		Actions:   []*policy.Action{testActionRead},
		Namespace: attr.GetNamespace(),
	}

	pdp, err := NewPolicyDecisionPoint(ctx, s.logger, []*policy.Attribute{attr}, []*policy.SubjectMapping{}, nil,
		false, false, WithDynamicValueMappings([]*policy.DynamicValueMapping{mapping}, true))
	s.Require().NoError(err)

	entity := s.createEntityWithProps("entity-dynamic", map[string]interface{}{
		"project": []interface{}{"alpha", "beta"},
	})

	s.Run("dynamic mapping does not entitle the deactivated value", func() {
		decision, entitlements, err := pdp.GetDecision(ctx, entity, testActionRead, []*authz.Resource{
			createAttributeValueResource(testDeactivatedProjectBetaInactive, testDeactivatedProjectBetaInactive),
		})
		s.Require().NoError(err)
		s.False(decision.AllPermitted)
		s.NotContains(entitlements, testDeactivatedProjectBetaInactive)
	})

	s.Run("dynamic mapping still entitles the active value", func() {
		decision, _, err := pdp.GetDecision(ctx, entity, testActionRead, []*authz.Resource{
			createAttributeValueResource(testDeactivatedProjectAlphaActive, testDeactivatedProjectAlphaActive),
		})
		s.Require().NoError(err)
		s.True(decision.AllPermitted)
	})
}

// Deactivated values on the direct-entitlement path are covered by the deactivation subtests of
// Test_GetDecision_DirectEntitlements in pdp_test.go; only the deactivated-definition case below
// is unique to this file.

// Test_GetDecision_DeactivatedValue_RegisteredResources covers registered resources on both sides
// of a decision: as the entity being entitled, and as the resource being accessed.
func (s *PDPTestSuite) Test_GetDecision_DeactivatedValue_RegisteredResources() {
	ctx := s.T().Context()

	attr := deactivationProjectAttr()
	regResName := "deactivation_service"
	entityRegResValueFQN := createRegisteredResourceValueFQN("", regResName, "entity")
	betaRegResValueFQN := createRegisteredResourceValueFQN("", regResName, "tagged_beta")
	alphaRegResValueFQN := createRegisteredResourceValueFQN("", regResName, "tagged_alpha")
	mixedActionsRegResValueFQN := createRegisteredResourceValueFQN("", regResName, "mixed_actions")

	actionAttributeValueFor := func(action *policy.Action, fqn, value string) *policy.RegisteredResourceValue_ActionAttributeValue {
		return &policy.RegisteredResourceValue_ActionAttributeValue{
			Action:         action,
			AttributeValue: &policy.Value{Fqn: fqn, Value: value},
		}
	}
	actionAttributeValue := func(fqn, value string) *policy.RegisteredResourceValue_ActionAttributeValue {
		return actionAttributeValueFor(testActionRead, fqn, value)
	}

	regRes := &policy.RegisteredResource{
		Name: regResName,
		Values: []*policy.RegisteredResourceValue{
			{
				Value: "entity",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
					actionAttributeValue(testDeactivatedProjectAlphaActive, "alpha"),
					actionAttributeValue(testDeactivatedProjectBetaInactive, "beta"),
				},
			},
			{
				Value:                 "tagged_beta",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{actionAttributeValue(testDeactivatedProjectBetaInactive, "beta")},
			},
			{
				Value:                 "tagged_alpha",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{actionAttributeValue(testDeactivatedProjectAlphaActive, "alpha")},
			},
			{
				// The deactivated value is bound to a different action than the one requested below.
				Value: "mixed_actions",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
					actionAttributeValueFor(testActionRead, testDeactivatedProjectAlphaActive, "alpha"),
					actionAttributeValueFor(testActionCreate, testDeactivatedProjectBetaInactive, "beta"),
				},
			},
		},
	}

	pdp, err := NewPolicyDecisionPoint(ctx, s.logger, []*policy.Attribute{attr}, []*policy.SubjectMapping{},
		[]*policy.RegisteredResource{regRes}, false, false)
	s.Require().NoError(err)

	s.Run("registered resource entity is not entitled to the deactivated value", func() {
		decision, entitlements, err := pdp.GetDecisionRegisteredResource(ctx, entityRegResValueFQN, testActionRead, []*authz.Resource{
			createAttributeValueResource(testDeactivatedProjectBetaInactive, testDeactivatedProjectBetaInactive),
		})
		s.Require().NoError(err)
		s.False(decision.AllPermitted)
		s.NotContains(entitlements, testDeactivatedProjectBetaInactive)
	})

	s.Run("registered resource entity remains entitled to the active value", func() {
		decision, _, err := pdp.GetDecisionRegisteredResource(ctx, entityRegResValueFQN, testActionRead, []*authz.Resource{
			createAttributeValueResource(testDeactivatedProjectAlphaActive, testDeactivatedProjectAlphaActive),
		})
		s.Require().NoError(err)
		s.True(decision.AllPermitted)
	})

	s.Run("registered resource tagged with the deactivated value is denied as a resource", func() {
		decision, _, err := pdp.GetDecisionRegisteredResource(ctx, entityRegResValueFQN, testActionRead, []*authz.Resource{
			createRegisteredResource("reg-res-inactive", betaRegResValueFQN),
		})
		s.Require().NoError(err)
		s.False(decision.AllPermitted, "a registered resource tagged with a deactivated value must fail closed")
	})

	s.Run("registered resource tagged with the active value is still permitted", func() {
		decision, _, err := pdp.GetDecisionRegisteredResource(ctx, entityRegResValueFQN, testActionRead, []*authz.Resource{
			createRegisteredResource("reg-res-active", alphaRegResValueFQN),
		})
		s.Require().NoError(err)
		s.True(decision.AllPermitted)
	})

	s.Run("registered resource is denied as a resource when the deactivated value is on another action", func() {
		decision, _, err := pdp.GetDecisionRegisteredResource(ctx, entityRegResValueFQN, testActionRead, []*authz.Resource{
			createRegisteredResource("reg-res-mixed", mixedActionsRegResValueFQN),
		})
		s.Require().NoError(err)
		s.False(decision.AllPermitted,
			"a deactivated value denies the whole registered resource regardless of the action it is bound to")
	})

	s.Run("registered resource entity remains entitled when the deactivated value is on another action", func() {
		decision, _, err := pdp.GetDecisionRegisteredResource(ctx, mixedActionsRegResValueFQN, testActionRead, []*authz.Resource{
			createAttributeValueResource(testDeactivatedProjectAlphaActive, testDeactivatedProjectAlphaActive),
		})
		s.Require().NoError(err)
		s.True(decision.AllPermitted,
			"a deactivated value in an entity's action-attribute-values must not strip its other entitlements")
	})

	s.Run("registered resource entitlements omit the deactivated value", func() {
		entitlements, err := pdp.GetEntitlementsRegisteredResource(ctx, entityRegResValueFQN, false)
		s.Require().NoError(err)
		s.Require().Len(entitlements, 1)
		s.Contains(entitlements[0].GetActionsPerAttributeValueFqn(), testDeactivatedProjectAlphaActive)
		s.NotContains(entitlements[0].GetActionsPerAttributeValueFqn(), testDeactivatedProjectBetaInactive)
	})
}

// Test_GetDecision_DeactivatedDefinition covers deactivation of the attribute definition rather
// than an individual value. Every value under it must be denied even though the values themselves
// are still active, including ad-hoc values synthesized by the direct entitlement and dynamic value
// mapping paths.
func (s *PDPTestSuite) Test_GetDecision_DeactivatedDefinition() {
	ctx := s.T().Context()

	archived := deactivationArchivedAttr()
	project := deactivationProjectAttr()
	allAttrs := []*policy.Attribute{archived, project}

	s.Run("subject mapping on a value of a deactivated definition denies", func() {
		subjectMappings := []*policy.SubjectMapping{
			createSimpleSubjectMapping(testDeactivatedArchivedValue, "value1",
				[]*policy.Action{testActionRead}, ".properties.archived[]", []string{"value1"}, nil),
			createSimpleSubjectMapping(testDeactivatedProjectAlphaActive, "alpha",
				[]*policy.Action{testActionRead}, ".properties.project[]", []string{"alpha"}, nil),
		}
		pdp, err := NewPolicyDecisionPoint(ctx, s.logger, allAttrs, subjectMappings, nil, false, false)
		s.Require().NoError(err)

		entity := s.createEntityWithProps("entity-archived", map[string]interface{}{
			"archived": []interface{}{"value1"},
			"project":  []interface{}{"alpha"},
		})

		decision, entitlements, err := pdp.GetDecision(ctx, entity, testActionRead, []*authz.Resource{
			createAttributeValueResource(testDeactivatedArchivedValue, testDeactivatedArchivedValue),
		})
		s.Require().NoError(err)
		s.False(decision.AllPermitted, "a value under a deactivated definition must not be satisfiable")
		s.NotContains(entitlements, testDeactivatedArchivedValue)

		// A value under an active definition is unaffected.
		decision, _, err = pdp.GetDecision(ctx, entity, testActionRead, []*authz.Resource{
			createAttributeValueResource(testDeactivatedProjectAlphaActive, testDeactivatedProjectAlphaActive),
		})
		s.Require().NoError(err)
		s.True(decision.AllPermitted)
	})

	s.Run("direct entitlement on a deactivated definition denies known and ad-hoc values", func() {
		pdp, err := NewPolicyDecisionPoint(ctx, s.logger, allAttrs, []*policy.SubjectMapping{}, nil, true, false)
		s.Require().NoError(err)

		entity := &entityresolutionV2.EntityRepresentation{
			OriginalId: "entity-direct-archived",
			DirectEntitlements: []*entityresolutionV2.DirectEntitlement{
				{AttributeValueFqn: testDeactivatedArchivedValue, Actions: []string{testActionRead.GetName()}},
				{AttributeValueFqn: testDeactivatedArchivedAdHocVal, Actions: []string{testActionRead.GetName()}},
			},
		}

		for _, resourceFQN := range []string{testDeactivatedArchivedValue, testDeactivatedArchivedAdHocVal} {
			decision, entitlements, err := pdp.GetDecision(ctx, entity, testActionRead, []*authz.Resource{
				createAttributeValueResource(resourceFQN, resourceFQN),
			})
			s.Require().NoError(err)
			s.False(decision.AllPermitted, "direct entitlement must not permit %s under a deactivated definition", resourceFQN)
			s.NotContains(entitlements, resourceFQN)
		}
	})

	s.Run("dynamic value mapping on a deactivated definition denies", func() {
		mapping := &policy.DynamicValueMapping{
			AttributeDefinition: archived,
			ValueResolver: &policy.DynamicValueResolver{
				SubjectExternalSelectorValue: ".properties.archived[]",
				Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
			},
			Actions:   []*policy.Action{testActionRead},
			Namespace: archived.GetNamespace(),
		}
		pdp, err := NewPolicyDecisionPoint(ctx, s.logger, allAttrs, []*policy.SubjectMapping{}, nil,
			false, false, WithDynamicValueMappings([]*policy.DynamicValueMapping{mapping}, true))
		s.Require().NoError(err)

		entity := s.createEntityWithProps("entity-dynamic-archived", map[string]interface{}{
			"archived": []interface{}{"value1", "adhoc"},
		})

		for _, resourceFQN := range []string{testDeactivatedArchivedValue, testDeactivatedArchivedAdHocVal} {
			decision, entitlements, err := pdp.GetDecision(ctx, entity, testActionRead, []*authz.Resource{
				createAttributeValueResource(resourceFQN, resourceFQN),
			})
			s.Require().NoError(err)
			s.False(decision.AllPermitted, "dynamic value mapping must not permit %s under a deactivated definition", resourceFQN)
			s.NotContains(entitlements, resourceFQN)
		}
	})

	s.Run("entitlements omit values of a deactivated definition", func() {
		subjectMappings := []*policy.SubjectMapping{
			createSimpleSubjectMapping(testDeactivatedArchivedValue, "value1",
				[]*policy.Action{testActionRead}, ".properties.archived[]", []string{"value1"}, nil),
			createSimpleSubjectMapping(testDeactivatedProjectAlphaActive, "alpha",
				[]*policy.Action{testActionRead}, ".properties.project[]", []string{"alpha"}, nil),
		}
		pdp, err := NewPolicyDecisionPoint(ctx, s.logger, allAttrs, subjectMappings, nil, false, false)
		s.Require().NoError(err)

		entity := s.createEntityWithProps("entity-archived-entitlements", map[string]interface{}{
			"archived": []interface{}{"value1"},
			"project":  []interface{}{"alpha"},
		})

		entitlements, err := pdp.GetEntitlements(ctx, []*entityresolutionV2.EntityRepresentation{entity}, nil, false)
		s.Require().NoError(err)
		s.Require().Len(entitlements, 1)
		s.Contains(entitlements[0].GetActionsPerAttributeValueFqn(), testDeactivatedProjectAlphaActive)
		s.NotContains(entitlements[0].GetActionsPerAttributeValueFqn(), testDeactivatedArchivedValue)
	})
}

// Test_GetEntitlements_ComprehensiveHierarchy_DeactivatedLowerValue asserts the comprehensive
// hierarchy cascade skips deactivated lower values.
func (s *PDPTestSuite) Test_GetEntitlements_ComprehensiveHierarchy_DeactivatedLowerValue() {
	ctx := s.T().Context()

	attr := deactivationClearanceAttr()
	subjectMappings := []*policy.SubjectMapping{
		createSimpleSubjectMapping(testDeactivatedClearanceLowActive, "low",
			[]*policy.Action{testActionRead}, ".properties.clearance", []string{"low"}, nil),
	}

	pdp, err := NewPolicyDecisionPoint(ctx, s.logger, []*policy.Attribute{attr}, subjectMappings, nil, false, false)
	s.Require().NoError(err)

	entity := s.createEntityWithProps("entity-low-clearance", map[string]interface{}{
		"clearance": "low",
	})

	entitlements, err := pdp.GetEntitlements(ctx, []*entityresolutionV2.EntityRepresentation{entity}, nil, true)
	s.Require().NoError(err)
	s.Require().Len(entitlements, 1)

	perValueFQN := entitlements[0].GetActionsPerAttributeValueFqn()
	s.Contains(perValueFQN, testDeactivatedClearanceLowActive)
	s.NotContains(perValueFQN, testDeactivatedClearanceLowestInactive,
		"comprehensive hierarchy must not cascade entitlement into a deactivated lower value")
}

// Test_GetEntitlements_DeactivatedValue asserts deactivated values never surface as entitlements.
func (s *PDPTestSuite) Test_GetEntitlements_DeactivatedValue() {
	ctx := s.T().Context()

	attr := deactivationProjectAttr()
	subjectMappings := []*policy.SubjectMapping{
		createSimpleSubjectMapping(testDeactivatedProjectAlphaActive, "alpha",
			[]*policy.Action{testActionRead}, ".properties.project[]", []string{"alpha"}, nil),
		createSimpleSubjectMapping(testDeactivatedProjectBetaInactive, "beta",
			[]*policy.Action{testActionRead}, ".properties.project[]", []string{"beta"}, nil),
	}

	pdp, err := NewPolicyDecisionPoint(ctx, s.logger, []*policy.Attribute{attr}, subjectMappings, nil, false, false)
	s.Require().NoError(err)

	entity := s.createEntityWithProps("entity-both-projects", map[string]interface{}{
		"project": []interface{}{"alpha", "beta"},
	})

	entitlements, err := pdp.GetEntitlements(ctx, []*entityresolutionV2.EntityRepresentation{entity}, nil, false)
	s.Require().NoError(err)
	s.Require().Len(entitlements, 1)
	s.Contains(entitlements[0].GetActionsPerAttributeValueFqn(), testDeactivatedProjectAlphaActive)
	s.NotContains(entitlements[0].GetActionsPerAttributeValueFqn(), testDeactivatedProjectBetaInactive)
}
