package namespacedpolicy

import (
	"context"
	"testing"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPrunePlannerRejectsMultipleScopes(t *testing.T) {
	t.Parallel()

	_, err := NewPrunePlanner(&plannerTestHandler{}, "actions,subject-mappings")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMultiplePruneScopes)
}

// Scope: actions.
func TestPrunePlannerPlanBlocksActionWhenInUse(t *testing.T) {
	t.Parallel()

	targetNamespace := &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"}
	legacyAction := &policy.Action{Id: "action-1", Name: "decrypt"}
	attributeValue := testAttributeValue("https://example.com/attr/classification/value/secret", targetNamespace)
	subjectSets := testSubjectSets()
	legacySCS := &policy.SubjectConditionSet{Id: "scs-1", SubjectSets: subjectSets}
	legacyMapping := &policy.SubjectMapping{
		Id:             "mapping-1",
		AttributeValue: attributeValue,
		Actions: []*policy.Action{
			{Id: legacyAction.GetId(), Name: legacyAction.GetName()},
		},
		SubjectConditionSet: legacySCS,
	}
	legacyValue := testRegisteredResourceValue(
		"value-1",
		testActionAttributeValue(
			legacyAction.GetId(),
			legacyAction.GetName(),
			attributeValue,
		),
	)
	legacyValue.Id = "value-1"
	legacyResource := testRegisteredResource("resource-1", "documents", legacyValue)
	obligationValue := &policy.ObligationValue{
		Id:  "ov-1",
		Fqn: "https://example.com/obl/notify/value/email",
		Obligation: &policy.Obligation{
			Namespace: targetNamespace,
		},
	}
	legacyTrigger := &policy.ObligationTrigger{
		Id:              "trigger-1",
		Action:          &policy.Action{Id: legacyAction.GetId(), Name: legacyAction.GetName()},
		AttributeValue:  attributeValue,
		ObligationValue: obligationValue,
	}

	targetResourceValue := &policy.RegisteredResourceValue{
		Id:       "target-value-1",
		Value:    legacyValue.GetValue(),
		Metadata: migratedMetadata(legacyValue.GetId()),
		ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
			testActionAttributeValue("target-action-1", legacyAction.GetName(), attributeValue),
		},
	}
	targetResource := &policy.RegisteredResource{
		Id:       "target-resource-1",
		Name:     legacyResource.GetName(),
		Metadata: migratedMetadata(legacyResource.GetId()),
		Values:   []*policy.RegisteredResourceValue{targetResourceValue},
	}
	handler := &plannerTestHandler{
		actionsByNamespace: map[string]*actions.ListActionsResponse{
			"": {
				ActionsCustom: []*policy.Action{legacyAction},
				Pagination:    emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				ActionsCustom: []*policy.Action{
					{
						Id:        "target-action-1",
						Name:      legacyAction.GetName(),
						Namespace: targetNamespace,
						Metadata:  migratedMetadata(legacyAction.GetId()),
					},
				},
				Pagination: emptyPageResponse(),
			},
		},
		subjectConditionSetsByNamespace: map[string]*subjectmapping.ListSubjectConditionSetsResponse{
			"": {
				SubjectConditionSets: []*policy.SubjectConditionSet{legacySCS},
				Pagination:           emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				SubjectConditionSets: []*policy.SubjectConditionSet{
					{
						Id:          "target-scs-1",
						SubjectSets: subjectSets,
						Metadata:    migratedMetadata(legacySCS.GetId()),
					},
				},
				Pagination: emptyPageResponse(),
			},
		},
		subjectMappingsByNamespace: map[string]*subjectmapping.ListSubjectMappingsResponse{
			"": {
				SubjectMappings: []*policy.SubjectMapping{legacyMapping},
				Pagination:      emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				SubjectMappings: []*policy.SubjectMapping{
					{
						Id:             "target-mapping-1",
						AttributeValue: attributeValue,
						Actions: []*policy.Action{
							{Id: "target-action-1", Name: legacyAction.GetName()},
						},
						SubjectConditionSet: &policy.SubjectConditionSet{
							Id:          "target-scs-1",
							SubjectSets: subjectSets,
						},
						Metadata: migratedMetadata(legacyMapping.GetId()),
					},
				},
				Pagination: emptyPageResponse(),
			},
		},
		registeredResourcesByNamespace: map[string]*registeredresources.ListRegisteredResourcesResponse{
			"": {
				Resources:  []*policy.RegisteredResource{legacyResource},
				Pagination: emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				Resources:  []*policy.RegisteredResource{targetResource},
				Pagination: emptyPageResponse(),
			},
		},
		obligationTriggersByNamespace: map[string]*obligations.ListObligationTriggersResponse{
			"": {
				Triggers:   []*policy.ObligationTrigger{legacyTrigger},
				Pagination: emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				Triggers: []*policy.ObligationTrigger{
					{
						Id:              "target-trigger-1",
						Action:          &policy.Action{Id: "target-action-1", Name: legacyAction.GetName()},
						AttributeValue:  attributeValue,
						ObligationValue: obligationValue,
						Metadata:        migratedMetadata(legacyTrigger.GetId()),
					},
				},
				Pagination: emptyPageResponse(),
			},
		},
		namespacesResponse: &namespaces.ListNamespacesResponse{
			Namespaces: []*policy.Namespace{targetNamespace},
			Pagination: emptyPageResponse(),
		},
	}

	planner, err := NewPrunePlanner(handler, "actions")
	require.NoError(t, err)

	plan, err := planner.Plan(t.Context())
	require.NoError(t, err)

	require.Len(t, plan.Actions, 1)
	assert.Equal(t, PruneStatusBlocked, plan.Actions[0].Status)
	assertPruneMigratedTargets(t, plan.Actions[0].MigratedTargets, targetNamespace, "target-action-1")
	assert.Equal(t, PruneStatusReasonTypeInUse, plan.Actions[0].Reason.Type)
	assert.Equal(t, pruneStatusReasonMessageInUse, plan.Actions[0].Reason.Message)
	assert.Empty(t, plan.SubjectConditionSets)
	assert.Empty(t, plan.SubjectMappings)
	assert.Empty(t, plan.RegisteredResources)
	assert.Empty(t, plan.ObligationTriggers)
}

func TestPrunePlannerPlanDeletesUnusedActionWhenCanonicalMigratedTargetExists(t *testing.T) {
	t.Parallel()

	targetNamespace := &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"}
	legacyAction := &policy.Action{Id: "action-1", Name: "decrypt"}
	targetAction := &policy.Action{
		Id:        "target-action-1",
		Name:      legacyAction.GetName(),
		Namespace: targetNamespace,
		Metadata:  migratedMetadata(legacyAction.GetId()),
	}
	handler := &plannerTestHandler{
		actionsByNamespace: map[string]*actions.ListActionsResponse{
			"": {
				ActionsCustom: []*policy.Action{legacyAction},
				Pagination:    emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				ActionsCustom: []*policy.Action{targetAction},
				Pagination:    emptyPageResponse(),
			},
		},
		namespacesResponse: &namespaces.ListNamespacesResponse{
			Namespaces: []*policy.Namespace{targetNamespace},
			Pagination: emptyPageResponse(),
		},
	}

	planner, err := NewPrunePlanner(handler, "actions")
	require.NoError(t, err)

	plan, err := planner.Plan(t.Context())
	require.NoError(t, err)

	require.Len(t, plan.Actions, 1)
	assert.Equal(t, PruneStatusDelete, plan.Actions[0].Status)
	assertPruneMigratedTargets(t, plan.Actions[0].MigratedTargets, targetNamespace, targetAction.GetId())
	assert.True(t, plan.Actions[0].Reason.IsZero())
}

func TestPrunePlannerPlanMarksUnusedActionWithNoMatchingMigrationLabelsAsUnresolved(t *testing.T) {
	t.Parallel()

	targetNamespace := &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"}
	legacyAction := &policy.Action{Id: "action-1", Name: "decrypt"}
	targetAction := &policy.Action{
		Id:        "target-action-1",
		Name:      legacyAction.GetName(),
		Namespace: targetNamespace,
	}
	handler := &plannerTestHandler{
		actionsByNamespace: map[string]*actions.ListActionsResponse{
			"": {
				ActionsCustom: []*policy.Action{legacyAction},
				Pagination:    emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				ActionsCustom: []*policy.Action{targetAction},
				Pagination:    emptyPageResponse(),
			},
		},
		namespacesResponse: &namespaces.ListNamespacesResponse{
			Namespaces: []*policy.Namespace{targetNamespace},
			Pagination: emptyPageResponse(),
		},
	}

	planner, err := NewPrunePlanner(handler, "actions")
	require.NoError(t, err)

	plan, err := planner.Plan(t.Context())
	require.NoError(t, err)

	require.Len(t, plan.Actions, 1)
	assert.Equal(t, PruneStatusUnresolved, plan.Actions[0].Status)
	assertPruneMigratedTargets(t, plan.Actions[0].MigratedTargets, targetNamespace, targetAction.GetId())
	assert.Equal(t, PruneStatusReasonTypeNoMatchingLabelsFound, plan.Actions[0].Reason.Type)
	assert.Equal(t, pruneStatusReasonMessageNoMatchingLabelsFound, plan.Actions[0].Reason.Message)
}

func TestPrunePlannerPlanBlocksUnusedActionWhenMigratedTargetIsNotFound(t *testing.T) {
	t.Parallel()

	targetNamespace := &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"}
	legacyAction := &policy.Action{Id: "action-1", Name: "decrypt"}
	handler := &plannerTestHandler{
		actionsByNamespace: map[string]*actions.ListActionsResponse{
			"": {
				ActionsCustom: []*policy.Action{legacyAction},
				Pagination:    emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				ActionsCustom: []*policy.Action{
					{
						Id:        "target-action-1",
						Name:      "different",
						Namespace: targetNamespace,
					},
				},
				Pagination: emptyPageResponse(),
			},
		},
		namespacesResponse: &namespaces.ListNamespacesResponse{
			Namespaces: []*policy.Namespace{targetNamespace},
			Pagination: emptyPageResponse(),
		},
	}

	planner, err := NewPrunePlanner(handler, "actions")
	require.NoError(t, err)

	plan, err := planner.Plan(t.Context())
	require.NoError(t, err)

	require.Len(t, plan.Actions, 1)
	assert.Equal(t, PruneStatusBlocked, plan.Actions[0].Status)
	assert.Empty(t, plan.Actions[0].MigratedTargets)
	assert.Equal(t, PruneStatusReasonTypeMigratedTargetNotFound, plan.Actions[0].Reason.Type)
	assert.Equal(t, pruneStatusReasonMessageMigratedTargetNotFound, plan.Actions[0].Reason.Message)
}

// Scope: subject condition sets.
func TestPrunePlannerPlanBlocksSubjectConditionSetWhenInUse(t *testing.T) {
	t.Parallel()

	targetNamespace := &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"}
	legacyAction := &policy.Action{Id: "action-1", Name: "decrypt"}
	attributeValue := testAttributeValue("https://example.com/attr/classification/value/secret", targetNamespace)
	subjectSets := testSubjectSets()
	legacySCS := &policy.SubjectConditionSet{Id: "scs-1", SubjectSets: subjectSets}
	legacyMapping := &policy.SubjectMapping{
		Id:             "mapping-1",
		AttributeValue: attributeValue,
		Actions: []*policy.Action{
			{Id: legacyAction.GetId(), Name: legacyAction.GetName()},
		},
		SubjectConditionSet: legacySCS,
	}
	legacyResource := testRegisteredResource(
		"resource-1",
		"documents",
		testRegisteredResourceValue(
			"prod",
			testActionAttributeValue(
				legacyAction.GetId(),
				legacyAction.GetName(),
				attributeValue,
			),
		),
	)
	obligationValue := &policy.ObligationValue{
		Id:  "ov-1",
		Fqn: "https://example.com/obl/notify/value/email",
		Obligation: &policy.Obligation{
			Namespace: targetNamespace,
		},
	}
	legacyTrigger := &policy.ObligationTrigger{
		Id:              "trigger-1",
		Action:          &policy.Action{Id: legacyAction.GetId(), Name: legacyAction.GetName()},
		AttributeValue:  attributeValue,
		ObligationValue: obligationValue,
	}
	handler := &plannerTestHandler{
		actionsByNamespace: map[string]*actions.ListActionsResponse{
			"": {
				ActionsCustom: []*policy.Action{legacyAction},
				Pagination:    emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				ActionsCustom: []*policy.Action{
					{
						Id:        "target-action-1",
						Name:      legacyAction.GetName(),
						Namespace: targetNamespace,
						Metadata:  migratedMetadata(legacyAction.GetId()),
					},
				},
				Pagination: emptyPageResponse(),
			},
		},
		subjectConditionSetsByNamespace: map[string]*subjectmapping.ListSubjectConditionSetsResponse{
			"": {
				SubjectConditionSets: []*policy.SubjectConditionSet{legacySCS},
				Pagination:           emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				SubjectConditionSets: []*policy.SubjectConditionSet{
					{
						Id:          "target-scs-1",
						SubjectSets: subjectSets,
						Metadata:    migratedMetadata(legacySCS.GetId()),
					},
				},
				Pagination: emptyPageResponse(),
			},
		},
		subjectMappingsByNamespace: map[string]*subjectmapping.ListSubjectMappingsResponse{
			"": {
				SubjectMappings: []*policy.SubjectMapping{legacyMapping},
				Pagination:      emptyPageResponse(),
			},
		},
		registeredResourcesByNamespace: map[string]*registeredresources.ListRegisteredResourcesResponse{
			"": {
				Resources:  []*policy.RegisteredResource{legacyResource},
				Pagination: emptyPageResponse(),
			},
		},
		obligationTriggersByNamespace: map[string]*obligations.ListObligationTriggersResponse{
			"": {
				Triggers:   []*policy.ObligationTrigger{legacyTrigger},
				Pagination: emptyPageResponse(),
			},
		},
		namespacesResponse: &namespaces.ListNamespacesResponse{
			Namespaces: []*policy.Namespace{targetNamespace},
			Pagination: emptyPageResponse(),
		},
	}

	planner, err := NewPrunePlanner(handler, "subject-condition-sets")
	require.NoError(t, err)

	plan, err := planner.Plan(t.Context())
	require.NoError(t, err)

	require.Len(t, plan.SubjectConditionSets, 1)
	assert.Equal(t, PruneStatusBlocked, plan.SubjectConditionSets[0].Status)
	assertPruneMigratedTargets(t, plan.SubjectConditionSets[0].MigratedTargets, targetNamespace, "target-scs-1")
	assert.Equal(t, PruneStatusReasonTypeInUse, plan.SubjectConditionSets[0].Reason.Type)
	assert.Equal(t, pruneStatusReasonMessageInUse, plan.SubjectConditionSets[0].Reason.Message)
	assert.Empty(t, plan.Actions)
	assert.Empty(t, plan.SubjectMappings)
	assert.Empty(t, plan.RegisteredResources)
	assert.Empty(t, plan.ObligationTriggers)
}

func TestPrunePlannerPlanDeletesUnusedSubjectConditionSetWhenCanonicalMigratedTargetExists(t *testing.T) {
	t.Parallel()

	targetNamespace := &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"}
	subjectSets := testSubjectSets()
	legacySCS := &policy.SubjectConditionSet{Id: "scs-1", SubjectSets: subjectSets}
	targetSCS := &policy.SubjectConditionSet{
		Id:          "target-scs-1",
		SubjectSets: subjectSets,
		Metadata:    migratedMetadata(legacySCS.GetId()),
	}
	handler := &plannerTestHandler{
		subjectConditionSetsByNamespace: map[string]*subjectmapping.ListSubjectConditionSetsResponse{
			"": {
				SubjectConditionSets: []*policy.SubjectConditionSet{legacySCS},
				Pagination:           emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				SubjectConditionSets: []*policy.SubjectConditionSet{targetSCS},
				Pagination:           emptyPageResponse(),
			},
		},
		namespacesResponse: &namespaces.ListNamespacesResponse{
			Namespaces: []*policy.Namespace{targetNamespace},
			Pagination: emptyPageResponse(),
		},
	}

	planner, err := NewPrunePlanner(handler, "subject-condition-sets")
	require.NoError(t, err)

	plan, err := planner.Plan(t.Context())
	require.NoError(t, err)

	require.Len(t, plan.SubjectConditionSets, 1)
	assert.Equal(t, PruneStatusDelete, plan.SubjectConditionSets[0].Status)
	assertPruneMigratedTargets(t, plan.SubjectConditionSets[0].MigratedTargets, targetNamespace, targetSCS.GetId())
	assert.True(t, plan.SubjectConditionSets[0].Reason.IsZero())
}

func TestPrunePlannerPlanMarksUnusedSubjectConditionSetWithNoMatchingMigrationLabelsAsUnresolved(t *testing.T) {
	t.Parallel()

	targetNamespace := &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"}
	subjectSets := testSubjectSets()
	legacySCS := &policy.SubjectConditionSet{Id: "scs-1", SubjectSets: subjectSets}
	targetSCS := &policy.SubjectConditionSet{
		Id:          "target-scs-1",
		SubjectSets: subjectSets,
	}
	handler := &plannerTestHandler{
		subjectConditionSetsByNamespace: map[string]*subjectmapping.ListSubjectConditionSetsResponse{
			"": {
				SubjectConditionSets: []*policy.SubjectConditionSet{legacySCS},
				Pagination:           emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				SubjectConditionSets: []*policy.SubjectConditionSet{targetSCS},
				Pagination:           emptyPageResponse(),
			},
		},
		namespacesResponse: &namespaces.ListNamespacesResponse{
			Namespaces: []*policy.Namespace{targetNamespace},
			Pagination: emptyPageResponse(),
		},
	}

	planner, err := NewPrunePlanner(handler, "subject-condition-sets")
	require.NoError(t, err)

	plan, err := planner.Plan(t.Context())
	require.NoError(t, err)

	require.Len(t, plan.SubjectConditionSets, 1)
	assert.Equal(t, PruneStatusUnresolved, plan.SubjectConditionSets[0].Status)
	assertPruneMigratedTargets(t, plan.SubjectConditionSets[0].MigratedTargets, targetNamespace, targetSCS.GetId())
	assert.Equal(t, PruneStatusReasonTypeNoMatchingLabelsFound, plan.SubjectConditionSets[0].Reason.Type)
	assert.Equal(t, pruneStatusReasonMessageNoMatchingLabelsFound, plan.SubjectConditionSets[0].Reason.Message)
}

func TestPrunePlannerPlanBlocksUnusedSubjectConditionSetWhenMigratedTargetIsNotFound(t *testing.T) {
	t.Parallel()

	targetNamespace := &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"}
	legacySCS := &policy.SubjectConditionSet{Id: "scs-1", SubjectSets: testSubjectSets()}
	targetSCS := &policy.SubjectConditionSet{
		Id:          "target-scs-1",
		SubjectSets: []*policy.SubjectSet{},
	}
	handler := &plannerTestHandler{
		subjectConditionSetsByNamespace: map[string]*subjectmapping.ListSubjectConditionSetsResponse{
			"": {
				SubjectConditionSets: []*policy.SubjectConditionSet{legacySCS},
				Pagination:           emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				SubjectConditionSets: []*policy.SubjectConditionSet{targetSCS},
				Pagination:           emptyPageResponse(),
			},
		},
		namespacesResponse: &namespaces.ListNamespacesResponse{
			Namespaces: []*policy.Namespace{targetNamespace},
			Pagination: emptyPageResponse(),
		},
	}

	planner, err := NewPrunePlanner(handler, "subject-condition-sets")
	require.NoError(t, err)

	plan, err := planner.Plan(t.Context())
	require.NoError(t, err)

	require.Len(t, plan.SubjectConditionSets, 1)
	assert.Equal(t, PruneStatusBlocked, plan.SubjectConditionSets[0].Status)
	assert.Empty(t, plan.SubjectConditionSets[0].MigratedTargets)
	assert.Equal(t, PruneStatusReasonTypeMigratedTargetNotFound, plan.SubjectConditionSets[0].Reason.Type)
	assert.Equal(t, pruneStatusReasonMessageMigratedTargetNotFound, plan.SubjectConditionSets[0].Reason.Message)
}

// Scope: subject mappings.
func TestPrunePlannerPlanClassifiesUnmigratedSubjectMappingAsNeedsMigration(t *testing.T) {
	t.Parallel()

	targetNamespace := &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"}
	legacyAction := &policy.Action{Id: "action-1", Name: "decrypt"}
	subjectSets := testSubjectSets()
	legacySCS := &policy.SubjectConditionSet{Id: "scs-1", SubjectSets: subjectSets}
	legacyMapping := &policy.SubjectMapping{
		Id:             "mapping-1",
		AttributeValue: testAttributeValue("https://example.com/attr/classification/value/secret", targetNamespace),
		Actions: []*policy.Action{
			{Id: legacyAction.GetId(), Name: legacyAction.GetName()},
		},
		SubjectConditionSet: legacySCS,
	}
	handler := &plannerTestHandler{
		actionsByNamespace: map[string]*actions.ListActionsResponse{
			"": {
				ActionsCustom: []*policy.Action{legacyAction},
				Pagination:    emptyPageResponse(),
			},
		},
		subjectConditionSetsByNamespace: map[string]*subjectmapping.ListSubjectConditionSetsResponse{
			"": {
				SubjectConditionSets: []*policy.SubjectConditionSet{legacySCS},
				Pagination:           emptyPageResponse(),
			},
		},
		subjectMappingsByNamespace: map[string]*subjectmapping.ListSubjectMappingsResponse{
			"": {
				SubjectMappings: []*policy.SubjectMapping{legacyMapping},
				Pagination:      emptyPageResponse(),
			},
		},
		namespacesResponse: &namespaces.ListNamespacesResponse{
			Namespaces: []*policy.Namespace{targetNamespace},
			Pagination: emptyPageResponse(),
		},
	}

	planner, err := NewPrunePlanner(handler, "subject-mappings")
	require.NoError(t, err)

	plan, err := planner.Plan(t.Context())
	require.NoError(t, err)

	require.Len(t, plan.SubjectMappings, 1)
	assert.Equal(t, PruneStatusBlocked, plan.SubjectMappings[0].Status)
	assert.Equal(t, PruneStatusReasonTypeNeedsMigration, plan.SubjectMappings[0].Reason.Type)
	assert.Equal(t, pruneStatusReasonMessageNeedsMigration, plan.SubjectMappings[0].Reason.Message)
	assert.True(t, plan.SubjectMappings[0].MigratedTarget.IsZero())
}

func TestPrunePlannerPlanClassifiesMissingMigrationLabelAsUnresolved(t *testing.T) {
	t.Parallel()

	targetNamespace := &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"}
	legacyAction := &policy.Action{Id: "action-1", Name: "decrypt"}
	targetAction := &policy.Action{
		Id:        "target-action-1",
		Name:      legacyAction.GetName(),
		Namespace: targetNamespace,
		Metadata:  migratedMetadata(legacyAction.GetId()),
	}
	subjectSets := testSubjectSets()
	legacySCS := &policy.SubjectConditionSet{Id: "scs-1", SubjectSets: subjectSets}
	targetSCS := &policy.SubjectConditionSet{
		Id:          "target-scs-1",
		SubjectSets: subjectSets,
		Metadata:    migratedMetadata(legacySCS.GetId()),
	}
	attributeValue := testAttributeValue("https://example.com/attr/classification/value/secret", targetNamespace)
	legacyMapping := &policy.SubjectMapping{
		Id:             "mapping-1",
		AttributeValue: attributeValue,
		Actions: []*policy.Action{
			{Id: legacyAction.GetId(), Name: legacyAction.GetName()},
		},
		SubjectConditionSet: legacySCS,
	}
	targetMapping := &policy.SubjectMapping{
		Id:             "target-mapping-1",
		AttributeValue: attributeValue,
		Actions: []*policy.Action{
			{Id: targetAction.GetId(), Name: targetAction.GetName()},
		},
		SubjectConditionSet: targetSCS,
	}
	handler := &plannerTestHandler{
		actionsByNamespace: map[string]*actions.ListActionsResponse{
			"": {
				ActionsCustom: []*policy.Action{legacyAction},
				Pagination:    emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				ActionsCustom: []*policy.Action{targetAction},
				Pagination:    emptyPageResponse(),
			},
		},
		subjectConditionSetsByNamespace: map[string]*subjectmapping.ListSubjectConditionSetsResponse{
			"": {
				SubjectConditionSets: []*policy.SubjectConditionSet{legacySCS},
				Pagination:           emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				SubjectConditionSets: []*policy.SubjectConditionSet{targetSCS},
				Pagination:           emptyPageResponse(),
			},
		},
		subjectMappingsByNamespace: map[string]*subjectmapping.ListSubjectMappingsResponse{
			"": {
				SubjectMappings: []*policy.SubjectMapping{legacyMapping},
				Pagination:      emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				SubjectMappings: []*policy.SubjectMapping{targetMapping},
				Pagination:      emptyPageResponse(),
			},
		},
		namespacesResponse: &namespaces.ListNamespacesResponse{
			Namespaces: []*policy.Namespace{targetNamespace},
			Pagination: emptyPageResponse(),
		},
	}

	planner, err := NewPrunePlanner(handler, "subject-mappings")
	require.NoError(t, err)

	plan, err := planner.Plan(t.Context())
	require.NoError(t, err)

	require.Len(t, plan.SubjectMappings, 1)
	assert.Equal(t, PruneStatusUnresolved, plan.SubjectMappings[0].Status)
	assertPruneMigratedTarget(t, plan.SubjectMappings[0].MigratedTarget, targetNamespace, targetMapping.GetId())
	assert.Equal(t, PruneStatusReasonTypeMissingMigrationLabel, plan.SubjectMappings[0].Reason.Type)
	assert.Equal(t, pruneStatusReasonMessageMissingMigrationLabel, plan.SubjectMappings[0].Reason.Message)
}

func TestPrunePlannerPlanFailsWhenMigratedTargetIDIsEmpty(t *testing.T) {
	t.Parallel()

	targetNamespace := &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"}
	legacyMapping := &policy.SubjectMapping{Id: "mapping-1"}
	resolved := &ResolvedTargets{
		SubjectMappings: []*ResolvedSubjectMapping{
			{
				Source:    legacyMapping,
				Namespace: targetNamespace,
				AlreadyMigrated: &policy.SubjectMapping{
					Metadata: migratedMetadata(legacyMapping.GetId()),
				},
			},
		},
	}

	_, err := buildPrunePlanFromResolved(scopesFromSlice([]Scope{ScopeSubjectMappings}), resolved, nil)

	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidPruneResolvedTarget)
	assert.Contains(t, err.Error(), `subject mapping "mapping-1"`)
}

func TestPrunePlannerPlanClassifiesMismatchedMigrationLabelAsUnresolved(t *testing.T) {
	t.Parallel()

	targetNamespace := &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"}
	legacyMapping := &policy.SubjectMapping{Id: "mapping-1"}
	resolved := &ResolvedTargets{
		SubjectMappings: []*ResolvedSubjectMapping{
			{
				Source:    legacyMapping,
				Namespace: targetNamespace,
				AlreadyMigrated: &policy.SubjectMapping{
					Id: "target-mapping-1",
					Metadata: &common.Metadata{
						Labels: map[string]string{
							migrationLabelMigratedFrom: "different-source-id",
						},
					},
				},
			},
		},
	}

	plan, err := buildPrunePlanFromResolved(scopesFromSlice([]Scope{ScopeSubjectMappings}), resolved, nil)

	require.NoError(t, err)
	require.Len(t, plan.SubjectMappings, 1)
	assert.Equal(t, PruneStatusUnresolved, plan.SubjectMappings[0].Status)
	assert.Equal(t, PruneStatusReasonTypeMismatchedMigrationLabel, plan.SubjectMappings[0].Reason.Type)
	assert.Equal(t, pruneStatusReasonMessageMismatchedMigrationLabel, plan.SubjectMappings[0].Reason.Message)
}

// Scope: registered resources.
func TestPrunePlannerPlanSkipsRegisteredResourceWhenResolvedSourceIsMissing(t *testing.T) {
	t.Parallel()

	resolved := &ResolvedTargets{
		RegisteredResources: []*ResolvedRegisteredResource{{}},
	}

	plan, err := buildPrunePlanFromResolved(
		scopesFromSlice([]Scope{ScopeRegisteredResources}),
		resolved,
		map[string]*policy.RegisteredResource{},
	)

	require.NoError(t, err)
	require.NotNil(t, plan)
	assert.Empty(t, plan.RegisteredResources)
}

func TestPrunePlannerPlanFailsWhenRegisteredResourceSourceIsNotReloaded(t *testing.T) {
	t.Parallel()

	source := testRegisteredResource("resource-1", "documents")
	resolved := &ResolvedTargets{
		RegisteredResources: []*ResolvedRegisteredResource{
			{Source: source},
		},
	}

	_, err := buildPrunePlanFromResolved(
		scopesFromSlice([]Scope{ScopeRegisteredResources}),
		resolved,
		map[string]*policy.RegisteredResource{},
	)

	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidPruneResolvedSource)
	assert.Contains(t, err.Error(), `registered resource source "resource-1" not found`)
}

func TestPrunePlannerPlanClassifiesUnmigratedRegisteredResourceAsNeedsMigration(t *testing.T) {
	t.Parallel()

	targetNamespace := &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"}
	legacyAction := &policy.Action{Id: "action-1", Name: "decrypt"}
	attributeValue := testAttributeValue("https://example.com/attr/classification/value/secret", targetNamespace)
	legacyResource := testRegisteredResource(
		"resource-1",
		"documents",
		testRegisteredResourceValue(
			"prod",
			testActionAttributeValue(legacyAction.GetId(), legacyAction.GetName(), attributeValue),
		),
	)
	handler := &plannerTestHandler{
		actionsByNamespace: map[string]*actions.ListActionsResponse{
			"": {
				ActionsCustom: []*policy.Action{legacyAction},
				Pagination:    emptyPageResponse(),
			},
		},
		registeredResourcesByNamespace: map[string]*registeredresources.ListRegisteredResourcesResponse{
			"": {
				Resources:  []*policy.RegisteredResource{legacyResource},
				Pagination: emptyPageResponse(),
			},
		},
		namespacesResponse: &namespaces.ListNamespacesResponse{
			Namespaces: []*policy.Namespace{targetNamespace},
			Pagination: emptyPageResponse(),
		},
	}

	planner, err := NewPrunePlanner(handler, "registered-resources")
	require.NoError(t, err)

	plan, err := planner.Plan(t.Context())
	require.NoError(t, err)

	require.Len(t, plan.RegisteredResources, 1)
	assert.Equal(t, PruneStatusBlocked, plan.RegisteredResources[0].Status)
	assert.Equal(t, PruneStatusReasonTypeNeedsMigration, plan.RegisteredResources[0].Reason.Type)
	assert.Equal(t, pruneStatusReasonMessageNeedsMigration, plan.RegisteredResources[0].Reason.Message)
	assert.True(t, plan.RegisteredResources[0].MigratedTarget.IsZero())
}

func TestPrunePlannerPlanMarksFilteredRegisteredResourceSourceAsUnresolved(t *testing.T) {
	t.Parallel()

	leftNamespace := &policy.Namespace{Id: "ns-1", Fqn: "https://left.example.com"}
	rightNamespace := &policy.Namespace{Id: "ns-2", Fqn: "https://right.example.com"}
	legacyAction := &policy.Action{Id: "action-1", Name: "decrypt"}
	leftValue := testRegisteredResourceValue(
		"left",
		testActionAttributeValue(
			legacyAction.GetId(),
			legacyAction.GetName(),
			testAttributeValue("https://left.example.com/attr/classification/value/secret", leftNamespace),
		),
	)
	rightValue := testRegisteredResourceValue(
		"right",
		testActionAttributeValue(
			legacyAction.GetId(),
			legacyAction.GetName(),
			testAttributeValue("https://right.example.com/attr/classification/value/secret", rightNamespace),
		),
	)
	legacyResource := testRegisteredResource("resource-1", "documents", leftValue, rightValue)
	targetResource := &policy.RegisteredResource{
		Id:       "target-resource-1",
		Name:     legacyResource.GetName(),
		Metadata: migratedMetadata(legacyResource.GetId()),
	}
	handler := &plannerTestHandler{
		actionsByNamespace: map[string]*actions.ListActionsResponse{
			"": {
				ActionsCustom: []*policy.Action{legacyAction},
				Pagination:    emptyPageResponse(),
			},
		},
		registeredResourcesByNamespace: map[string]*registeredresources.ListRegisteredResourcesResponse{
			"": {
				Resources:  []*policy.RegisteredResource{legacyResource},
				Pagination: emptyPageResponse(),
			},
		},
		namespacesResponse: &namespaces.ListNamespacesResponse{
			Namespaces: []*policy.Namespace{leftNamespace, rightNamespace},
			Pagination: emptyPageResponse(),
		},
	}
	reviewer := registeredResourceFilterReviewer{
		namespace: leftNamespace,
		target:    targetResource,
	}

	planner, err := NewPrunePlanner(handler, "registered-resources", WithPruneInteractiveReviewer(reviewer))
	require.NoError(t, err)

	plan, err := planner.Plan(t.Context())
	require.NoError(t, err)

	require.Len(t, plan.RegisteredResources, 1)
	assert.Equal(t, PruneStatusUnresolved, plan.RegisteredResources[0].Status)
	assertPruneMigratedTarget(t, plan.RegisteredResources[0].MigratedTarget, leftNamespace, targetResource.GetId())
	assert.Equal(t, PruneStatusReasonTypeRegisteredResourceSourceMismatch, plan.RegisteredResources[0].Reason.Type)
	assert.Contains(t, plan.RegisteredResources[0].Reason.Message, "manual review required before source deletion")
	assert.Contains(t, plan.RegisteredResources[0].Reason.Message, leftNamespace.GetFqn())
	require.Len(t, plan.RegisteredResources[0].Source.GetValues(), 1)
	require.Len(t, plan.RegisteredResources[0].FullSource.GetValues(), 2)
}

func TestPrunePlannerPlanDeletesRegisteredResourceWhenFullSourceMatchesMigratedTarget(t *testing.T) {
	t.Parallel()

	targetNamespace := &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"}
	legacyAction := &policy.Action{Id: "action-1", Name: "decrypt"}
	targetAction := &policy.Action{
		Id:        "target-action-1",
		Name:      legacyAction.GetName(),
		Namespace: targetNamespace,
		Metadata:  migratedMetadata(legacyAction.GetId()),
	}
	attributeValue := testAttributeValue("https://example.com/attr/classification/value/secret", targetNamespace)
	legacyValue := testRegisteredResourceValue(
		"prod",
		testActionAttributeValue(legacyAction.GetId(), legacyAction.GetName(), attributeValue),
	)
	legacyResource := testRegisteredResource("resource-1", "documents", legacyValue)
	targetValue := testRegisteredResourceValue(
		"prod",
		testActionAttributeValue(targetAction.GetId(), targetAction.GetName(), attributeValue),
	)
	targetResource := testRegisteredResource("target-resource-1", legacyResource.GetName(), targetValue)
	targetResource.Metadata = migratedMetadata(legacyResource.GetId())

	handler := &plannerTestHandler{
		actionsByNamespace: map[string]*actions.ListActionsResponse{
			"": {
				ActionsCustom: []*policy.Action{legacyAction},
				Pagination:    emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				ActionsCustom: []*policy.Action{targetAction},
				Pagination:    emptyPageResponse(),
			},
		},
		registeredResourcesByNamespace: map[string]*registeredresources.ListRegisteredResourcesResponse{
			"": {
				Resources:  []*policy.RegisteredResource{legacyResource},
				Pagination: emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				Resources:  []*policy.RegisteredResource{targetResource},
				Pagination: emptyPageResponse(),
			},
		},
		namespacesResponse: &namespaces.ListNamespacesResponse{
			Namespaces: []*policy.Namespace{targetNamespace},
			Pagination: emptyPageResponse(),
		},
	}

	planner, err := NewPrunePlanner(handler, "registered-resources")
	require.NoError(t, err)

	plan, err := planner.Plan(t.Context())
	require.NoError(t, err)

	require.Len(t, plan.RegisteredResources, 1)
	assert.Equal(t, PruneStatusDelete, plan.RegisteredResources[0].Status)
	assertPruneMigratedTarget(t, plan.RegisteredResources[0].MigratedTarget, targetNamespace, targetResource.GetId())
	assert.True(t, plan.RegisteredResources[0].Reason.IsZero())
	require.NotNil(t, plan.RegisteredResources[0].Source)
	require.NotNil(t, plan.RegisteredResources[0].FullSource)
	assert.True(t, registeredResourceCanonicalEqual(plan.RegisteredResources[0].Source, plan.RegisteredResources[0].FullSource))
}

// Scope: obligation triggers.
func TestPrunePlannerPlanClassifiesUnmigratedObligationTriggerAsNeedsMigration(t *testing.T) {
	t.Parallel()

	targetNamespace := &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"}
	legacyAction := &policy.Action{Id: "action-1", Name: "decrypt"}
	attributeValue := testAttributeValue("https://example.com/attr/classification/value/secret", targetNamespace)
	obligationValue := &policy.ObligationValue{
		Id:  "ov-1",
		Fqn: "https://example.com/obl/notify/value/email",
		Obligation: &policy.Obligation{
			Namespace: targetNamespace,
		},
	}
	legacyTrigger := &policy.ObligationTrigger{
		Id:              "trigger-1",
		Action:          &policy.Action{Id: legacyAction.GetId(), Name: legacyAction.GetName()},
		AttributeValue:  attributeValue,
		ObligationValue: obligationValue,
	}
	handler := &plannerTestHandler{
		actionsByNamespace: map[string]*actions.ListActionsResponse{
			"": {
				ActionsCustom: []*policy.Action{legacyAction},
				Pagination:    emptyPageResponse(),
			},
		},
		obligationTriggersByNamespace: map[string]*obligations.ListObligationTriggersResponse{
			"": {
				Triggers:   []*policy.ObligationTrigger{legacyTrigger},
				Pagination: emptyPageResponse(),
			},
		},
		namespacesResponse: &namespaces.ListNamespacesResponse{
			Namespaces: []*policy.Namespace{targetNamespace},
			Pagination: emptyPageResponse(),
		},
	}

	planner, err := NewPrunePlanner(handler, "obligation-triggers")
	require.NoError(t, err)

	plan, err := planner.Plan(t.Context())
	require.NoError(t, err)

	require.Len(t, plan.ObligationTriggers, 1)
	assert.Equal(t, PruneStatusBlocked, plan.ObligationTriggers[0].Status)
	assert.Equal(t, PruneStatusReasonTypeNeedsMigration, plan.ObligationTriggers[0].Reason.Type)
	assert.Equal(t, pruneStatusReasonMessageNeedsMigration, plan.ObligationTriggers[0].Reason.Message)
	assert.True(t, plan.ObligationTriggers[0].MigratedTarget.IsZero())
}

func TestPrunePlannerPlanDeletesObligationTriggerWhenMigratedTargetExists(t *testing.T) {
	t.Parallel()

	targetNamespace := &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"}
	legacyAction := &policy.Action{Id: "action-1", Name: "decrypt"}
	targetAction := &policy.Action{
		Id:        "target-action-1",
		Name:      legacyAction.GetName(),
		Namespace: targetNamespace,
		Metadata:  migratedMetadata(legacyAction.GetId()),
	}
	attributeValue := testAttributeValue("https://example.com/attr/classification/value/secret", targetNamespace)
	obligationValue := &policy.ObligationValue{
		Id:  "ov-1",
		Fqn: "https://example.com/obl/notify/value/email",
		Obligation: &policy.Obligation{
			Namespace: targetNamespace,
		},
	}
	legacyTrigger := &policy.ObligationTrigger{
		Id:              "trigger-1",
		Action:          &policy.Action{Id: legacyAction.GetId(), Name: legacyAction.GetName()},
		AttributeValue:  attributeValue,
		ObligationValue: obligationValue,
	}
	targetTrigger := &policy.ObligationTrigger{
		Id:              "target-trigger-1",
		Action:          &policy.Action{Id: targetAction.GetId(), Name: targetAction.GetName()},
		AttributeValue:  attributeValue,
		ObligationValue: obligationValue,
		Metadata:        migratedMetadata(legacyTrigger.GetId()),
	}
	handler := &plannerTestHandler{
		actionsByNamespace: map[string]*actions.ListActionsResponse{
			"": {
				ActionsCustom: []*policy.Action{legacyAction},
				Pagination:    emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				ActionsCustom: []*policy.Action{targetAction},
				Pagination:    emptyPageResponse(),
			},
		},
		obligationTriggersByNamespace: map[string]*obligations.ListObligationTriggersResponse{
			"": {
				Triggers:   []*policy.ObligationTrigger{legacyTrigger},
				Pagination: emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				Triggers:   []*policy.ObligationTrigger{targetTrigger},
				Pagination: emptyPageResponse(),
			},
		},
		namespacesResponse: &namespaces.ListNamespacesResponse{
			Namespaces: []*policy.Namespace{targetNamespace},
			Pagination: emptyPageResponse(),
		},
	}

	planner, err := NewPrunePlanner(handler, "obligation-triggers")
	require.NoError(t, err)

	plan, err := planner.Plan(t.Context())
	require.NoError(t, err)

	require.Len(t, plan.ObligationTriggers, 1)
	assert.Equal(t, PruneStatusDelete, plan.ObligationTriggers[0].Status)
	assertPruneMigratedTarget(t, plan.ObligationTriggers[0].MigratedTarget, targetNamespace, targetTrigger.GetId())
	assert.True(t, plan.ObligationTriggers[0].Reason.IsZero())
}

func TestPrunePlannerPlanMarksObligationTriggerWithMissingMigrationLabelAsUnresolved(t *testing.T) {
	t.Parallel()

	targetNamespace := &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"}
	legacyAction := &policy.Action{Id: "action-1", Name: "decrypt"}
	targetAction := &policy.Action{
		Id:        "target-action-1",
		Name:      legacyAction.GetName(),
		Namespace: targetNamespace,
		Metadata:  migratedMetadata(legacyAction.GetId()),
	}
	attributeValue := testAttributeValue("https://example.com/attr/classification/value/secret", targetNamespace)
	obligationValue := &policy.ObligationValue{
		Id:  "ov-1",
		Fqn: "https://example.com/obl/notify/value/email",
		Obligation: &policy.Obligation{
			Namespace: targetNamespace,
		},
	}
	legacyTrigger := &policy.ObligationTrigger{
		Id:              "trigger-1",
		Action:          &policy.Action{Id: legacyAction.GetId(), Name: legacyAction.GetName()},
		AttributeValue:  attributeValue,
		ObligationValue: obligationValue,
	}
	targetTrigger := &policy.ObligationTrigger{
		Id:              "target-trigger-1",
		Action:          &policy.Action{Id: targetAction.GetId(), Name: targetAction.GetName()},
		AttributeValue:  attributeValue,
		ObligationValue: obligationValue,
	}
	handler := &plannerTestHandler{
		actionsByNamespace: map[string]*actions.ListActionsResponse{
			"": {
				ActionsCustom: []*policy.Action{legacyAction},
				Pagination:    emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				ActionsCustom: []*policy.Action{targetAction},
				Pagination:    emptyPageResponse(),
			},
		},
		obligationTriggersByNamespace: map[string]*obligations.ListObligationTriggersResponse{
			"": {
				Triggers:   []*policy.ObligationTrigger{legacyTrigger},
				Pagination: emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				Triggers:   []*policy.ObligationTrigger{targetTrigger},
				Pagination: emptyPageResponse(),
			},
		},
		namespacesResponse: &namespaces.ListNamespacesResponse{
			Namespaces: []*policy.Namespace{targetNamespace},
			Pagination: emptyPageResponse(),
		},
	}

	planner, err := NewPrunePlanner(handler, "obligation-triggers")
	require.NoError(t, err)

	plan, err := planner.Plan(t.Context())
	require.NoError(t, err)

	require.Len(t, plan.ObligationTriggers, 1)
	assert.Equal(t, PruneStatusUnresolved, plan.ObligationTriggers[0].Status)
	assertPruneMigratedTarget(t, plan.ObligationTriggers[0].MigratedTarget, targetNamespace, targetTrigger.GetId())
	assert.Equal(t, PruneStatusReasonTypeMissingMigrationLabel, plan.ObligationTriggers[0].Reason.Type)
	assert.Equal(t, pruneStatusReasonMessageMissingMigrationLabel, plan.ObligationTriggers[0].Reason.Message)
}

func migratedMetadata(sourceID string) *common.Metadata {
	return &common.Metadata{
		Labels: map[string]string{
			migrationLabelMigratedFrom: sourceID,
		},
	}
}

func testSubjectSets() []*policy.SubjectSet {
	return []*policy.SubjectSet{
		{
			ConditionGroups: []*policy.ConditionGroup{
				{
					Conditions: []*policy.Condition{
						{
							SubjectExternalSelectorValue: "email",
							Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
							SubjectExternalValues:        []string{"user@example.com"},
						},
					},
				},
			},
		},
	}
}

func assertPruneMigratedTargets(t *testing.T, actual []TargetRef, namespace *policy.Namespace, ids ...string) {
	t.Helper()

	require.Len(t, actual, len(ids))
	for i, id := range ids {
		assertPruneMigratedTarget(t, actual[i], namespace, id)
	}
}

func assertPruneMigratedTarget(t *testing.T, actual TargetRef, namespace *policy.Namespace, id string) {
	t.Helper()

	assert.Equal(t, id, actual.ID)
	assert.Equal(t, namespace.GetId(), actual.NamespaceID)
	assert.Equal(t, namespace.GetFqn(), actual.NamespaceFQN)
}

type registeredResourceFilterReviewer struct {
	namespace *policy.Namespace
	target    *policy.RegisteredResource
}

func (r registeredResourceFilterReviewer) Review(_ context.Context, resolved *ResolvedTargets, _ []*policy.Namespace) error {
	for _, resource := range resolved.RegisteredResources {
		if resource == nil || resource.Source == nil {
			continue
		}

		filtered, err := filterRegisteredResourceToNamespace(resource.Source, r.namespace)
		if err != nil {
			return err
		}
		resource.Source = filtered
		resource.Namespace = r.namespace
		resource.Unresolved = nil
		resource.AlreadyMigrated = r.target
		resource.NeedsCreate = false
	}

	return nil
}
