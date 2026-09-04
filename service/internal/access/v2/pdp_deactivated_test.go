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
	testDeactivatedProjectFQN      = createAttrFQN(deactivatedTestNamespace, "project")
	testDeactivatedProjectActive   = createAttrValueFQN(deactivatedTestNamespace, "project", "active")
	testDeactivatedProjectInactive = createAttrValueFQN(deactivatedTestNamespace, "project", "inactive")

	testDeactivatedClearanceFQN          = createAttrFQN(deactivatedTestNamespace, "clearance")
	testDeactivatedClearanceHighInactive = createAttrValueFQN(deactivatedTestNamespace, "clearance", "high")
	testDeactivatedClearanceLowActive    = createAttrValueFQN(deactivatedTestNamespace, "clearance", "low")

	testDeactivatedArchivedFQN      = createAttrFQN(deactivatedTestNamespace, "archived")
	testDeactivatedArchivedValue    = createAttrValueFQN(deactivatedTestNamespace, "archived", "value1")
	testDeactivatedArchivedAdHocVal = createAttrValueFQN(deactivatedTestNamespace, "archived", "adhoc")
)

// deactivationProjectAttr is an ANY_OF definition with one active and one deactivated value.
func deactivationProjectAttr() *policy.Attribute {
	return &policy.Attribute{
		Fqn:       testDeactivatedProjectFQN,
		Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Namespace: &policy.Namespace{Name: deactivatedTestNamespace, Fqn: "https://" + deactivatedTestNamespace},
		Values: []*policy.Value{
			{Fqn: testDeactivatedProjectActive, Value: "active", Active: wrapperspb.Bool(true)},
			{Fqn: testDeactivatedProjectInactive, Value: "inactive", Active: wrapperspb.Bool(false)},
		},
	}
}

// deactivationClearanceAttr is a HIERARCHY definition whose highest value is deactivated.
func deactivationClearanceAttr() *policy.Attribute {
	return &policy.Attribute{
		Fqn:       testDeactivatedClearanceFQN,
		Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
		Namespace: &policy.Namespace{Name: deactivatedTestNamespace, Fqn: "https://" + deactivatedTestNamespace},
		Values: []*policy.Value{
			{Fqn: testDeactivatedClearanceHighInactive, Value: "high", Active: wrapperspb.Bool(false)},
			{Fqn: testDeactivatedClearanceLowActive, Value: "low", Active: wrapperspb.Bool(true)},
		},
	}
}

// deactivationArchivedAttr is a deactivated ANY_OF definition whose values are all still active.
// Deactivating a definition must deny its values even though each value is individually active.
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
		createSimpleSubjectMapping(testDeactivatedProjectActive, "active",
			[]*policy.Action{testActionRead}, ".properties.project[]", []string{"active"}, nil),
		createSimpleSubjectMapping(testDeactivatedProjectInactive, "inactive",
			[]*policy.Action{testActionRead}, ".properties.project[]", []string{"inactive"}, nil),
	}

	pdp, err := NewPolicyDecisionPoint(ctx, s.logger, []*policy.Attribute{attr}, subjectMappings, nil, false, false)
	s.Require().NoError(err)

	entity := s.createEntityWithProps("entity-both-projects", map[string]interface{}{
		"project": []interface{}{"active", "inactive"},
	})

	s.Run("resource tagged with the deactivated value is denied", func() {
		decision, entitlements, err := pdp.GetDecision(ctx, entity, testActionRead, []*authz.Resource{
			createAttributeValueResource(testDeactivatedProjectInactive, testDeactivatedProjectInactive),
		})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted, "subject mapping must not entitle a deactivated value")
		s.NotContains(entitlements, testDeactivatedProjectInactive)
	})

	s.Run("ANY_OF resource carrying the deactivated value alongside an active one is denied", func() {
		decision, _, err := pdp.GetDecision(ctx, entity, testActionRead, []*authz.Resource{
			createAttributeValueResource("mixed-state-resource", testDeactivatedProjectActive, testDeactivatedProjectInactive),
		})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted, "a resource carrying a deactivated value must fail closed even under ANY_OF")
	})

	s.Run("active sibling value is unaffected", func() {
		decision, entitlements, err := pdp.GetDecision(ctx, entity, testActionRead, []*authz.Resource{
			createAttributeValueResource(testDeactivatedProjectActive, testDeactivatedProjectActive),
		})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.AllPermitted)
		s.Contains(entitlements, testDeactivatedProjectActive)
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
		"project": []interface{}{"active", "inactive"},
	})

	s.Run("dynamic mapping does not entitle the deactivated value", func() {
		decision, entitlements, err := pdp.GetDecision(ctx, entity, testActionRead, []*authz.Resource{
			createAttributeValueResource(testDeactivatedProjectInactive, testDeactivatedProjectInactive),
		})
		s.Require().NoError(err)
		s.False(decision.AllPermitted)
		s.NotContains(entitlements, testDeactivatedProjectInactive)
	})

	s.Run("dynamic mapping still entitles the active value", func() {
		decision, _, err := pdp.GetDecision(ctx, entity, testActionRead, []*authz.Resource{
			createAttributeValueResource(testDeactivatedProjectActive, testDeactivatedProjectActive),
		})
		s.Require().NoError(err)
		s.True(decision.AllPermitted)
	})
}

// Test_GetDecision_DeactivatedValue_DirectEntitlements covers the direct-entitlement path where
// the entitled value FQN is carried on the entity representation rather than in policy.
func (s *PDPTestSuite) Test_GetDecision_DeactivatedValue_DirectEntitlements() {
	ctx := s.T().Context()

	attr := deactivationProjectAttr()
	pdp, err := NewPolicyDecisionPoint(ctx, s.logger, []*policy.Attribute{attr}, []*policy.SubjectMapping{}, nil, true, false)
	s.Require().NoError(err)

	entity := &entityresolutionV2.EntityRepresentation{
		OriginalId: "entity-direct",
		DirectEntitlements: []*entityresolutionV2.DirectEntitlement{
			{AttributeValueFqn: testDeactivatedProjectActive, Actions: []string{testActionRead.GetName()}},
			{AttributeValueFqn: testDeactivatedProjectInactive, Actions: []string{testActionRead.GetName()}},
		},
	}

	s.Run("direct entitlement does not entitle the deactivated value", func() {
		decision, entitlements, err := pdp.GetDecision(ctx, entity, testActionRead, []*authz.Resource{
			createAttributeValueResource(testDeactivatedProjectInactive, testDeactivatedProjectInactive),
		})
		s.Require().NoError(err)
		s.False(decision.AllPermitted)
		s.NotContains(entitlements, testDeactivatedProjectInactive)
	})

	s.Run("direct entitlement still entitles the active value", func() {
		decision, _, err := pdp.GetDecision(ctx, entity, testActionRead, []*authz.Resource{
			createAttributeValueResource(testDeactivatedProjectActive, testDeactivatedProjectActive),
		})
		s.Require().NoError(err)
		s.True(decision.AllPermitted)
	})
}

// Test_GetDecision_DeactivatedValue_RegisteredResources covers registered resources on both sides
// of a decision: as the entity being entitled, and as the resource being accessed.
func (s *PDPTestSuite) Test_GetDecision_DeactivatedValue_RegisteredResources() {
	ctx := s.T().Context()

	attr := deactivationProjectAttr()
	regResName := "deactivation_service"
	entityRegResValueFQN := createRegisteredResourceValueFQN("", regResName, "entity")
	inactiveRegResValueFQN := createRegisteredResourceValueFQN("", regResName, "tagged_inactive")
	activeRegResValueFQN := createRegisteredResourceValueFQN("", regResName, "tagged_active")

	actionAttributeValue := func(fqn, value string) *policy.RegisteredResourceValue_ActionAttributeValue {
		return &policy.RegisteredResourceValue_ActionAttributeValue{
			Action:         testActionRead,
			AttributeValue: &policy.Value{Fqn: fqn, Value: value},
		}
	}

	regRes := &policy.RegisteredResource{
		Name: regResName,
		Values: []*policy.RegisteredResourceValue{
			{
				Value: "entity",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
					actionAttributeValue(testDeactivatedProjectActive, "active"),
					actionAttributeValue(testDeactivatedProjectInactive, "inactive"),
				},
			},
			{
				Value:                 "tagged_inactive",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{actionAttributeValue(testDeactivatedProjectInactive, "inactive")},
			},
			{
				Value:                 "tagged_active",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{actionAttributeValue(testDeactivatedProjectActive, "active")},
			},
		},
	}

	pdp, err := NewPolicyDecisionPoint(ctx, s.logger, []*policy.Attribute{attr}, []*policy.SubjectMapping{},
		[]*policy.RegisteredResource{regRes}, false, false)
	s.Require().NoError(err)

	s.Run("registered resource entity is not entitled to the deactivated value", func() {
		decision, entitlements, err := pdp.GetDecisionRegisteredResource(ctx, entityRegResValueFQN, testActionRead, []*authz.Resource{
			createAttributeValueResource(testDeactivatedProjectInactive, testDeactivatedProjectInactive),
		})
		s.Require().NoError(err)
		s.False(decision.AllPermitted)
		s.NotContains(entitlements, testDeactivatedProjectInactive)
	})

	s.Run("registered resource entity remains entitled to the active value", func() {
		decision, _, err := pdp.GetDecisionRegisteredResource(ctx, entityRegResValueFQN, testActionRead, []*authz.Resource{
			createAttributeValueResource(testDeactivatedProjectActive, testDeactivatedProjectActive),
		})
		s.Require().NoError(err)
		s.True(decision.AllPermitted)
	})

	s.Run("registered resource tagged with the deactivated value is denied as a resource", func() {
		decision, _, err := pdp.GetDecisionRegisteredResource(ctx, entityRegResValueFQN, testActionRead, []*authz.Resource{
			createRegisteredResource("reg-res-inactive", inactiveRegResValueFQN),
		})
		s.Require().NoError(err)
		s.False(decision.AllPermitted, "a registered resource tagged with a deactivated value must fail closed")
	})

	s.Run("registered resource tagged with the active value is still permitted", func() {
		decision, _, err := pdp.GetDecisionRegisteredResource(ctx, entityRegResValueFQN, testActionRead, []*authz.Resource{
			createRegisteredResource("reg-res-active", activeRegResValueFQN),
		})
		s.Require().NoError(err)
		s.True(decision.AllPermitted)
	})

	s.Run("registered resource entitlements omit the deactivated value", func() {
		entitlements, err := pdp.GetEntitlementsRegisteredResource(ctx, entityRegResValueFQN, false)
		s.Require().NoError(err)
		s.Require().Len(entitlements, 1)
		s.Contains(entitlements[0].GetActionsPerAttributeValueFqn(), testDeactivatedProjectActive)
		s.NotContains(entitlements[0].GetActionsPerAttributeValueFqn(), testDeactivatedProjectInactive)
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
			createSimpleSubjectMapping(testDeactivatedProjectActive, "active",
				[]*policy.Action{testActionRead}, ".properties.project[]", []string{"active"}, nil),
		}
		pdp, err := NewPolicyDecisionPoint(ctx, s.logger, allAttrs, subjectMappings, nil, false, false)
		s.Require().NoError(err)

		entity := s.createEntityWithProps("entity-archived", map[string]interface{}{
			"archived": []interface{}{"value1"},
			"project":  []interface{}{"active"},
		})

		decision, entitlements, err := pdp.GetDecision(ctx, entity, testActionRead, []*authz.Resource{
			createAttributeValueResource(testDeactivatedArchivedValue, testDeactivatedArchivedValue),
		})
		s.Require().NoError(err)
		s.False(decision.AllPermitted, "a value under a deactivated definition must not be satisfiable")
		s.NotContains(entitlements, testDeactivatedArchivedValue)

		// A value under an active definition is unaffected.
		decision, _, err = pdp.GetDecision(ctx, entity, testActionRead, []*authz.Resource{
			createAttributeValueResource(testDeactivatedProjectActive, testDeactivatedProjectActive),
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
			createSimpleSubjectMapping(testDeactivatedProjectActive, "active",
				[]*policy.Action{testActionRead}, ".properties.project[]", []string{"active"}, nil),
		}
		pdp, err := NewPolicyDecisionPoint(ctx, s.logger, allAttrs, subjectMappings, nil, false, false)
		s.Require().NoError(err)

		entity := s.createEntityWithProps("entity-archived-entitlements", map[string]interface{}{
			"archived": []interface{}{"value1"},
			"project":  []interface{}{"active"},
		})

		entitlements, err := pdp.GetEntitlements(ctx, []*entityresolutionV2.EntityRepresentation{entity}, nil, false)
		s.Require().NoError(err)
		s.Require().Len(entitlements, 1)
		s.Contains(entitlements[0].GetActionsPerAttributeValueFqn(), testDeactivatedProjectActive)
		s.NotContains(entitlements[0].GetActionsPerAttributeValueFqn(), testDeactivatedArchivedValue)
	})
}

// Test_GetEntitlements_DeactivatedValue asserts deactivated values never surface as entitlements.
func (s *PDPTestSuite) Test_GetEntitlements_DeactivatedValue() {
	ctx := s.T().Context()

	attr := deactivationProjectAttr()
	subjectMappings := []*policy.SubjectMapping{
		createSimpleSubjectMapping(testDeactivatedProjectActive, "active",
			[]*policy.Action{testActionRead}, ".properties.project[]", []string{"active"}, nil),
		createSimpleSubjectMapping(testDeactivatedProjectInactive, "inactive",
			[]*policy.Action{testActionRead}, ".properties.project[]", []string{"inactive"}, nil),
	}

	pdp, err := NewPolicyDecisionPoint(ctx, s.logger, []*policy.Attribute{attr}, subjectMappings, nil, false, false)
	s.Require().NoError(err)

	entity := s.createEntityWithProps("entity-both-projects", map[string]interface{}{
		"project": []interface{}{"active", "inactive"},
	})

	entitlements, err := pdp.GetEntitlements(ctx, []*entityresolutionV2.EntityRepresentation{entity}, nil, false)
	s.Require().NoError(err)
	s.Require().Len(entitlements, 1)
	s.Contains(entitlements[0].GetActionsPerAttributeValueFqn(), testDeactivatedProjectActive)
	s.NotContains(entitlements[0].GetActionsPerAttributeValueFqn(), testDeactivatedProjectInactive)
}
