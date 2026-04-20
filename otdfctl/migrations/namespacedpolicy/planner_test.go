package namespacedpolicy

import (
	"context"
	"errors"
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

func TestPlannerPlanMarksActionAlreadyMigratedWithoutMetadata(t *testing.T) {
	t.Parallel()

	targetNamespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	legacyAction := &policy.Action{
		Id:   "action-legacy",
		Name: "decrypt",
	}
	targetAction := &policy.Action{
		Id:        "action-target",
		Name:      "decrypt",
		Namespace: targetNamespace,
	}
	legacyMapping := &policy.SubjectMapping{
		Id: "mapping-legacy",
		Actions: []*policy.Action{
			{
				Id:   legacyAction.GetId(),
				Name: legacyAction.GetName(),
			},
		},
		AttributeValue: &policy.Value{
			Fqn: "https://example.com/attr/classification/value/secret",
		},
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

	planner, err := NewPlanner(handler, "actions")
	require.NoError(t, err)

	plan, err := planner.Plan(t.Context())
	require.NoError(t, err)
	require.Len(t, plan.Actions, 1)
	require.Len(t, plan.Actions[0].Targets, 1)

	assert.Equal(t, TargetStatusAlreadyMigrated, plan.Actions[0].Targets[0].Status)
	require.NotNil(t, plan.Actions[0].Targets[0].Existing)
	assert.Equal(t, targetAction.GetId(), plan.Actions[0].Targets[0].Existing.GetId())
	assert.Equal(t, []string{"", targetNamespace.GetId()}, handler.actionCalls)
	assert.Equal(t, []string{""}, handler.subjectMappingCalls)
}

func TestPlannerPlanDoesNotLeakSupportSubjectMappingsIntoActionScope(t *testing.T) {
	t.Parallel()

	targetNamespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	legacyCreate := &policy.Action{
		Id:   "action-create",
		Name: "create",
	}
	legacyRead := &policy.Action{
		Id:   "action-read",
		Name: "read",
	}
	legacyCustom := &policy.Action{
		Id:   "action-custom-1",
		Name: "custom_action_1",
	}
	legacySCS := &policy.SubjectConditionSet{
		Id: "scs-1",
	}
	resourceValue := &policy.RegisteredResourceValue{
		Id:       "resource-value-1",
		Resource: &policy.RegisteredResource{Id: "resource-1"},
		ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
			{
				Id: "aav-create",
				Action: &policy.Action{
					Id:   legacyCreate.GetId(),
					Name: legacyCreate.GetName(),
				},
				AttributeValue: &policy.Value{
					Attribute: &policy.Attribute{
						Namespace: targetNamespace,
					},
				},
			},
			{
				Id: "aav-custom",
				Action: &policy.Action{
					Id:   legacyCustom.GetId(),
					Name: legacyCustom.GetName(),
				},
				AttributeValue: &policy.Value{
					Attribute: &policy.Attribute{
						Namespace: targetNamespace,
					},
				},
			},
		},
	}
	legacyResource := &policy.RegisteredResource{
		Id:     "resource-1",
		Name:   "resource-1",
		Values: []*policy.RegisteredResourceValue{resourceValue},
	}
	legacyMapping := &policy.SubjectMapping{
		Id: "mapping-1",
		AttributeValue: &policy.Value{
			Attribute: &policy.Attribute{
				Namespace: targetNamespace,
			},
		},
		SubjectConditionSet: &policy.SubjectConditionSet{
			Id: legacySCS.GetId(),
		},
		Actions: []*policy.Action{
			{
				Id:   legacyRead.GetId(),
				Name: legacyRead.GetName(),
			},
		},
	}
	handler := &plannerTestHandler{
		actionsByNamespace: map[string]*actions.ListActionsResponse{
			"": {
				ActionsStandard: []*policy.Action{legacyCreate, legacyRead},
				ActionsCustom:   []*policy.Action{legacyCustom},
				Pagination:      emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				ActionsStandard: []*policy.Action{
					{
						Id:        "target-create",
						Name:      legacyCreate.GetName(),
						Namespace: targetNamespace,
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
		namespacesResponse: &namespaces.ListNamespacesResponse{
			Namespaces: []*policy.Namespace{targetNamespace},
			Pagination: emptyPageResponse(),
		},
	}

	planner, err := NewPlanner(handler, "subject-condition-sets,registered-resources")
	require.NoError(t, err)

	plan, err := planner.Plan(t.Context())
	require.NoError(t, err)

	assert.Equal(t, []Scope{ScopeActions, ScopeSubjectConditionSets, ScopeRegisteredResources}, plan.Scopes)
	assert.ElementsMatch(t, []string{legacyCreate.GetId(), legacyCustom.GetId()}, actionSourceIDs(plan.Actions))
	assert.NotContains(t, actionSourceIDs(plan.Actions), legacyRead.GetId())
	require.Len(t, plan.SubjectConditionSets, 1)
	assert.Equal(t, legacySCS.GetId(), plan.SubjectConditionSets[0].Source.GetId())
	assert.Equal(t, []string{"", targetNamespace.GetId()}, handler.actionCalls)
	assert.Equal(t, []string{""}, handler.subjectMappingCalls)
}

func TestPlannerRetrieveUsesRequestedScopeBoundaries(t *testing.T) {
	t.Parallel()

	targetNamespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	legacyAction := &policy.Action{
		Id:   "action-1",
		Name: "decrypt",
	}
	legacySCS := &policy.SubjectConditionSet{
		Id: "scs-1",
	}
	legacyMapping := &policy.SubjectMapping{
		Id: "mapping-1",
		AttributeValue: testAttributeValue(
			"https://example.com/attr/classification/value/secret",
			targetNamespace,
		),
		SubjectConditionSet: &policy.SubjectConditionSet{
			Id: legacySCS.GetId(),
		},
		Actions: []*policy.Action{
			{
				Id:   legacyAction.GetId(),
				Name: legacyAction.GetName(),
			},
		},
	}
	legacyResource := testRegisteredResource(
		"resource-1",
		"documents",
		testRegisteredResourceValue(
			"prod",
			testActionAttributeValue(
				legacyAction.GetId(),
				legacyAction.GetName(),
				testAttributeValue("https://example.com/attr/classification/value/secret", targetNamespace),
			),
		),
	)
	legacyTrigger := &policy.ObligationTrigger{
		Id:     "trigger-1",
		Action: &policy.Action{Id: legacyAction.GetId(), Name: legacyAction.GetName()},
		ObligationValue: &policy.ObligationValue{
			Id:  "ov-1",
			Fqn: "https://example.com/obl/notify/value/email",
			Obligation: &policy.Obligation{
				Namespace: targetNamespace,
			},
		},
	}

	tests := []struct {
		name                           string
		scopeCSV                       string
		expectedScopes                 []Scope
		expectedActionCalls            []string
		expectedSubjectConditionCalls  []string
		expectedSubjectMappingCalls    []string
		expectedRegisteredResourceCall []string
		expectedObligationCalls        []string
		expectedCandidateCounts        Candidates
	}{
		{
			name:           "subject mappings pull dependencies without reverse lookup scopes",
			scopeCSV:       "subject-mappings",
			expectedScopes: []Scope{ScopeActions, ScopeSubjectConditionSets, ScopeSubjectMappings},
			expectedActionCalls: []string{
				"",
			},
			expectedSubjectConditionCalls: []string{
				"",
			},
			expectedSubjectMappingCalls: []string{
				"",
			},
			expectedCandidateCounts: Candidates{
				Actions:              []*policy.Action{legacyAction},
				SubjectConditionSets: []*policy.SubjectConditionSet{legacySCS},
				SubjectMappings:      []*policy.SubjectMapping{legacyMapping},
			},
		},
		{
			name:           "actions pull reverse lookup scopes without expanding artifact scopes",
			scopeCSV:       "actions",
			expectedScopes: []Scope{ScopeActions},
			expectedActionCalls: []string{
				"",
			},
			expectedSubjectMappingCalls: []string{
				"",
			},
			expectedRegisteredResourceCall: []string{
				"",
			},
			expectedObligationCalls: []string{
				"",
			},
			expectedCandidateCounts: Candidates{
				Actions:             []*policy.Action{legacyAction},
				SubjectMappings:     []*policy.SubjectMapping{legacyMapping},
				RegisteredResources: []*policy.RegisteredResource{legacyResource},
				ObligationTriggers:  []*policy.ObligationTrigger{legacyTrigger},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

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
			}

			planner, err := NewPlanner(handler, tt.scopeCSV)
			require.NoError(t, err)

			retrieved, err := planner.retrieve(t.Context())
			require.NoError(t, err)

			assert.Equal(t, tt.expectedScopes, retrieved.Scopes)
			assert.Equal(t, tt.expectedActionCalls, handler.actionCalls)
			assert.Equal(t, tt.expectedSubjectConditionCalls, handler.subjectConditionSetCalls)
			assert.Equal(t, tt.expectedSubjectMappingCalls, handler.subjectMappingCalls)
			assert.Equal(t, tt.expectedRegisteredResourceCall, handler.registeredResourceCalls)
			assert.Equal(t, tt.expectedObligationCalls, handler.obligationTriggerCalls)
			assert.Len(t, retrieved.Candidates.Actions, len(tt.expectedCandidateCounts.Actions))
			assert.Len(t, retrieved.Candidates.SubjectConditionSets, len(tt.expectedCandidateCounts.SubjectConditionSets))
			assert.Len(t, retrieved.Candidates.SubjectMappings, len(tt.expectedCandidateCounts.SubjectMappings))
			assert.Len(t, retrieved.Candidates.RegisteredResources, len(tt.expectedCandidateCounts.RegisteredResources))
			assert.Len(t, retrieved.Candidates.ObligationTriggers, len(tt.expectedCandidateCounts.ObligationTriggers))
		})
	}
}

func TestPlannerPlanAllScopesBuildsAllPlanSections(t *testing.T) {
	t.Parallel()

	targetNamespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	legacyAction := &policy.Action{
		Id:   "action-1",
		Name: "decrypt",
	}
	legacySCS := &policy.SubjectConditionSet{
		Id: "scs-1",
	}
	legacyMapping := &policy.SubjectMapping{
		Id: "mapping-1",
		AttributeValue: testAttributeValue(
			"https://example.com/attr/classification/value/secret",
			targetNamespace,
		),
		SubjectConditionSet: &policy.SubjectConditionSet{
			Id: legacySCS.GetId(),
		},
		Actions: []*policy.Action{
			{
				Id:   legacyAction.GetId(),
				Name: legacyAction.GetName(),
			},
		},
	}
	legacyResource := testRegisteredResource(
		"resource-1",
		"documents",
		testRegisteredResourceValue(
			"prod",
			testActionAttributeValue(
				legacyAction.GetId(),
				legacyAction.GetName(),
				testAttributeValue("https://example.com/attr/classification/value/secret", targetNamespace),
			),
		),
	)
	legacyTrigger := &policy.ObligationTrigger{
		Id:     "trigger-1",
		Action: &policy.Action{Id: legacyAction.GetId(), Name: legacyAction.GetName()},
		ObligationValue: &policy.ObligationValue{
			Id:  "ov-1",
			Fqn: "https://example.com/obl/notify/value/email",
			Obligation: &policy.Obligation{
				Namespace: targetNamespace,
			},
		},
	}

	handler := &plannerTestHandler{
		actionsByNamespace: map[string]*actions.ListActionsResponse{
			"": {
				ActionsCustom: []*policy.Action{legacyAction},
				Pagination:    emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				Pagination: emptyPageResponse(),
			},
		},
		subjectConditionSetsByNamespace: map[string]*subjectmapping.ListSubjectConditionSetsResponse{
			"": {
				SubjectConditionSets: []*policy.SubjectConditionSet{legacySCS},
				Pagination:           emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				Pagination: emptyPageResponse(),
			},
		},
		subjectMappingsByNamespace: map[string]*subjectmapping.ListSubjectMappingsResponse{
			"": {
				SubjectMappings: []*policy.SubjectMapping{legacyMapping},
				Pagination:      emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				Pagination: emptyPageResponse(),
			},
		},
		registeredResourcesByNamespace: map[string]*registeredresources.ListRegisteredResourcesResponse{
			"": {
				Resources:  []*policy.RegisteredResource{legacyResource},
				Pagination: emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				Pagination: emptyPageResponse(),
			},
		},
		obligationTriggersByNamespace: map[string]*obligations.ListObligationTriggersResponse{
			"": {
				Triggers:   []*policy.ObligationTrigger{legacyTrigger},
				Pagination: emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				Pagination: emptyPageResponse(),
			},
		},
		namespacesResponse: &namespaces.ListNamespacesResponse{
			Namespaces: []*policy.Namespace{targetNamespace},
			Pagination: emptyPageResponse(),
		},
	}

	planner, err := NewPlanner(handler, "actions,subject-condition-sets,subject-mappings,registered-resources,obligation-triggers")
	require.NoError(t, err)

	plan, err := planner.Plan(t.Context())
	require.NoError(t, err)

	assert.Equal(t, []Scope{
		ScopeActions,
		ScopeSubjectConditionSets,
		ScopeSubjectMappings,
		ScopeRegisteredResources,
		ScopeObligationTriggers,
	}, plan.Scopes)
	require.Len(t, plan.Actions, 1)
	require.Len(t, plan.Actions[0].Targets, 1)
	assert.Equal(t, TargetStatusCreate, plan.Actions[0].Targets[0].Status)
	assert.ElementsMatch(t, []string{
		"subject_mapping|mapping-1",
		"registered_resource|resource-1",
		"obligation_trigger|trigger-1",
	}, actionReferenceKindsAndIDs(plan.Actions[0].References))

	require.Len(t, plan.SubjectConditionSets, 1)
	require.Len(t, plan.SubjectConditionSets[0].Targets, 1)
	assert.Equal(t, TargetStatusCreate, plan.SubjectConditionSets[0].Targets[0].Status)

	require.Len(t, plan.SubjectMappings, 1)
	require.Len(t, plan.SubjectMappings[0].Targets, 1)
	assert.Equal(t, TargetStatusCreate, plan.SubjectMappings[0].Targets[0].Status)
	require.Len(t, plan.SubjectMappings[0].Targets[0].Actions, 1)
	assert.Equal(t, TargetStatusCreate, plan.SubjectMappings[0].Targets[0].Actions[0].Status)
	require.NotNil(t, plan.SubjectMappings[0].Targets[0].SubjectConditionSet)
	assert.Equal(t, TargetStatusCreate, plan.SubjectMappings[0].Targets[0].SubjectConditionSet.Status)

	require.Len(t, plan.RegisteredResources, 1)
	require.Len(t, plan.RegisteredResources[0].Targets, 1)
	require.Len(t, plan.RegisteredResources[0].Targets[0].Values, 1)
	require.Len(t, plan.RegisteredResources[0].Targets[0].Values[0].ActionBindings, 1)
	assert.Equal(t, TargetStatusCreate, plan.RegisteredResources[0].Targets[0].Values[0].ActionBindings[0].ActionTargetRef.Status)

	require.Len(t, plan.ObligationTriggers, 1)
	require.Len(t, plan.ObligationTriggers[0].Targets, 1)
	require.NotNil(t, plan.ObligationTriggers[0].Targets[0].Action)
	assert.Equal(t, TargetStatusCreate, plan.ObligationTriggers[0].Targets[0].Action.Status)

	require.Len(t, plan.Namespaces, 1)
	assert.Equal(t, []string{legacyAction.GetId()}, plan.Namespaces[0].Actions)
	assert.Equal(t, []string{legacySCS.GetId()}, plan.Namespaces[0].SubjectConditionSets)
	assert.Equal(t, []string{legacyMapping.GetId()}, plan.Namespaces[0].SubjectMappings)
	assert.Equal(t, []string{legacyResource.GetId()}, plan.Namespaces[0].RegisteredResources)
	assert.Equal(t, []string{legacyTrigger.GetId()}, plan.Namespaces[0].ObligationTriggers)

	assert.Equal(t, []string{"", targetNamespace.GetId()}, handler.actionCalls)
	assert.Equal(t, []string{"", targetNamespace.GetId()}, handler.subjectConditionSetCalls)
	assert.Equal(t, []string{"", targetNamespace.GetId()}, handler.subjectMappingCalls)
	assert.Equal(t, []string{"", targetNamespace.GetId()}, handler.registeredResourceCalls)
	assert.Equal(t, []string{"", targetNamespace.GetId()}, handler.obligationTriggerCalls)
}

func TestPlannerPlanInvokesInteractiveReviewerWhenConfigured(t *testing.T) {
	t.Parallel()

	targetNamespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	legacyAction := &policy.Action{
		Id:   "action-legacy",
		Name: "decrypt",
	}
	legacyMapping := &policy.SubjectMapping{
		Id: "mapping-legacy",
		Actions: []*policy.Action{
			{
				Id:   legacyAction.GetId(),
				Name: legacyAction.GetName(),
			},
		},
		AttributeValue: &policy.Value{
			Fqn: "https://example.com/attr/classification/value/secret",
		},
	}
	reviewer := &plannerTestReviewer{}

	handler := &plannerTestHandler{
		actionsByNamespace: map[string]*actions.ListActionsResponse{
			"": {
				ActionsCustom: []*policy.Action{legacyAction},
				Pagination:    emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				Pagination: emptyPageResponse(),
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

	planner, err := NewPlanner(handler, "actions", WithInteractiveReviewer(reviewer))
	require.NoError(t, err)

	plan, err := planner.Plan(t.Context())
	require.NoError(t, err)

	require.Len(t, plan.Actions, 1)
	assert.Equal(t, 1, reviewer.calls)
	assert.NotNil(t, reviewer.lastResolved)
}

func TestPlannerPlanPropagatesInteractiveReviewerError(t *testing.T) {
	t.Parallel()

	targetNamespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	legacyAction := &policy.Action{
		Id:   "action-legacy",
		Name: "decrypt",
	}
	legacyMapping := &policy.SubjectMapping{
		Id: "mapping-legacy",
		Actions: []*policy.Action{
			{
				Id:   legacyAction.GetId(),
				Name: legacyAction.GetName(),
			},
		},
		AttributeValue: &policy.Value{
			Fqn: "https://example.com/attr/classification/value/secret",
		},
	}
	reviewerErr := errors.New("review failed")
	reviewer := &plannerTestReviewer{err: reviewerErr}

	handler := &plannerTestHandler{
		actionsByNamespace: map[string]*actions.ListActionsResponse{
			"": {
				ActionsCustom: []*policy.Action{legacyAction},
				Pagination:    emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				Pagination: emptyPageResponse(),
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

	planner, err := NewPlanner(handler, "actions", WithInteractiveReviewer(reviewer))
	require.NoError(t, err)

	_, err = planner.Plan(t.Context())
	require.ErrorIs(t, err, reviewerErr)
	assert.Equal(t, 1, reviewer.calls)
}

func TestPlannerPlanInteractiveReviewerLeavesCurrentUnresolvedPlanShapeUntouched(t *testing.T) {
	t.Parallel()

	namespaceOne := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	namespaceTwo := &policy.Namespace{
		Id:  "ns-2",
		Fqn: "https://example.org",
	}
	legacyAction := &policy.Action{
		Id:   "action-legacy",
		Name: "decrypt",
	}
	legacyResource := testRegisteredResource(
		"resource-1",
		"documents",
		testRegisteredResourceValue(
			"prod",
			testActionAttributeValue(
				legacyAction.GetId(),
				legacyAction.GetName(),
				testAttributeValue("https://example.com/attr/classification/value/secret", namespaceOne),
			),
			testActionAttributeValue(
				legacyAction.GetId(),
				legacyAction.GetName(),
				testAttributeValue("https://example.org/attr/classification/value/restricted", namespaceTwo),
			),
		),
	)
	reviewer := &plannerTestReviewer{}

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
			Namespaces: []*policy.Namespace{namespaceOne, namespaceTwo},
			Pagination: emptyPageResponse(),
		},
	}

	planner, err := NewPlanner(handler, "registered-resources", WithInteractiveReviewer(reviewer))
	require.NoError(t, err)

	plan, err := planner.Plan(t.Context())
	require.NoError(t, err)

	assert.Equal(t, 1, reviewer.calls)
	require.Len(t, plan.RegisteredResources, 1)
	assert.Equal(t, ErrUndeterminedTargetMapping.Error()+": registered resource spans multiple target namespaces", plan.RegisteredResources[0].Unresolved)
	assert.Empty(t, plan.RegisteredResources[0].Targets)
	require.NotNil(t, plan.Unresolved)
	require.Len(t, plan.Unresolved.RegisteredResources, 1)
	assert.Equal(t, legacyResource.GetId(), plan.Unresolved.RegisteredResources[0].Resource.GetId())
	assert.Equal(t, plan.RegisteredResources[0].Unresolved, plan.Unresolved.RegisteredResources[0].Reason)
}

func TestPlannerPlanHuhInteractiveReviewerResolvesRegisteredResourceConflict(t *testing.T) {
	t.Parallel()

	namespaceOne := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	namespaceTwo := &policy.Namespace{
		Id:  "ns-2",
		Fqn: "https://example.org",
	}
	legacyAction := &policy.Action{
		Id:   "action-legacy",
		Name: "decrypt",
	}
	legacyResource := testRegisteredResource(
		"resource-1",
		"documents",
		testRegisteredResourceValue(
			"prod",
			testActionAttributeValue(
				legacyAction.GetId(),
				legacyAction.GetName(),
				testAttributeValue("https://example.com/attr/classification/value/secret", namespaceOne),
			),
			testActionAttributeValue(
				legacyAction.GetId(),
				legacyAction.GetName(),
				testAttributeValue("https://example.org/attr/classification/value/restricted", namespaceTwo),
			),
		),
	)
	prompter := &testInteractivePrompter{
		selectValue: namespaceSelectionValue(namespaceOne),
	}

	handler := &plannerTestHandler{
		actionsByNamespace: map[string]*actions.ListActionsResponse{
			"": {
				ActionsCustom: []*policy.Action{legacyAction},
				Pagination:    emptyPageResponse(),
			},
			namespaceOne.GetId(): {
				Pagination: emptyPageResponse(),
			},
		},
		registeredResourcesByNamespace: map[string]*registeredresources.ListRegisteredResourcesResponse{
			"": {
				Resources:  []*policy.RegisteredResource{legacyResource},
				Pagination: emptyPageResponse(),
			},
			namespaceOne.GetId(): {
				Pagination: emptyPageResponse(),
			},
		},
		namespacesResponse: &namespaces.ListNamespacesResponse{
			Namespaces: []*policy.Namespace{namespaceOne, namespaceTwo},
			Pagination: emptyPageResponse(),
		},
	}

	planner, err := NewPlanner(handler, "registered-resources", WithInteractiveReviewer(NewHuhInteractiveReviewer(handler, prompter)))
	require.NoError(t, err)

	plan, err := planner.Plan(t.Context())
	require.NoError(t, err)

	assert.Equal(t, 1, prompter.selectCalls)
	require.Len(t, plan.RegisteredResources, 1)
	assert.Empty(t, plan.RegisteredResources[0].Unresolved)
	require.Len(t, plan.RegisteredResources[0].Targets, 1)
	assert.Equal(t, TargetStatusCreate, plan.RegisteredResources[0].Targets[0].Status)
	assert.True(t, sameNamespace(namespaceOne, plan.RegisteredResources[0].Targets[0].Namespace))
	require.Len(t, plan.RegisteredResources[0].Targets[0].Values, 1)
	require.Len(t, plan.RegisteredResources[0].Targets[0].Values[0].ActionBindings, 1)
	assert.Equal(t, "action-legacy", plan.RegisteredResources[0].Targets[0].Values[0].ActionBindings[0].SourceActionID)
	require.NotNil(t, plan.RegisteredResources[0].Targets[0].Values[0].ActionBindings[0].ActionTargetRef)
	assert.Equal(t, TargetStatusCreate, plan.RegisteredResources[0].Targets[0].Values[0].ActionBindings[0].ActionTargetRef.Status)
	assert.Nil(t, plan.Unresolved)
	require.Len(t, plan.Actions, 1)
	require.Len(t, plan.Actions[0].Targets, 1)
	assert.Equal(t, TargetStatusCreate, plan.Actions[0].Targets[0].Status)
	assert.True(t, sameNamespace(namespaceOne, plan.Actions[0].Targets[0].Namespace))
}

type plannerTestHandler struct {
	actionsByNamespace              map[string]*actions.ListActionsResponse
	subjectConditionSetsByNamespace map[string]*subjectmapping.ListSubjectConditionSetsResponse
	subjectMappingsByNamespace      map[string]*subjectmapping.ListSubjectMappingsResponse
	registeredResourcesByNamespace  map[string]*registeredresources.ListRegisteredResourcesResponse
	obligationTriggersByNamespace   map[string]*obligations.ListObligationTriggersResponse
	namespacesResponse              *namespaces.ListNamespacesResponse
	actionCalls                     []string
	subjectConditionSetCalls        []string
	subjectMappingCalls             []string
	registeredResourceCalls         []string
	obligationTriggerCalls          []string
}

func (h *plannerTestHandler) ListActions(_ context.Context, limit, offset int32, namespace string) (*actions.ListActionsResponse, error) {
	h.actionCalls = append(h.actionCalls, namespace)
	if resp, ok := h.actionsByNamespace[namespace]; ok {
		return resp, nil
	}
	return &actions.ListActionsResponse{Pagination: emptyPageResponse()}, nil
}

func (h *plannerTestHandler) ListSubjectConditionSets(_ context.Context, limit, offset int32, namespace string) (*subjectmapping.ListSubjectConditionSetsResponse, error) {
	h.subjectConditionSetCalls = append(h.subjectConditionSetCalls, namespace)
	if resp, ok := h.subjectConditionSetsByNamespace[namespace]; ok {
		return resp, nil
	}
	return &subjectmapping.ListSubjectConditionSetsResponse{Pagination: emptyPageResponse()}, nil
}

func (h *plannerTestHandler) ListSubjectMappings(_ context.Context, limit, offset int32, namespace string) (*subjectmapping.ListSubjectMappingsResponse, error) {
	h.subjectMappingCalls = append(h.subjectMappingCalls, namespace)
	if resp, ok := h.subjectMappingsByNamespace[namespace]; ok {
		return resp, nil
	}
	return &subjectmapping.ListSubjectMappingsResponse{Pagination: emptyPageResponse()}, nil
}

func (h *plannerTestHandler) ListRegisteredResources(_ context.Context, limit, offset int32, namespace string) (*registeredresources.ListRegisteredResourcesResponse, error) {
	h.registeredResourceCalls = append(h.registeredResourceCalls, namespace)
	if resp, ok := h.registeredResourcesByNamespace[namespace]; ok {
		return resp, nil
	}
	return &registeredresources.ListRegisteredResourcesResponse{Pagination: emptyPageResponse()}, nil
}

func (h *plannerTestHandler) ListObligationTriggers(_ context.Context, namespace string, limit, offset int32) (*obligations.ListObligationTriggersResponse, error) {
	h.obligationTriggerCalls = append(h.obligationTriggerCalls, namespace)
	if resp, ok := h.obligationTriggersByNamespace[namespace]; ok {
		return resp, nil
	}
	return &obligations.ListObligationTriggersResponse{Pagination: emptyPageResponse()}, nil
}

func (h *plannerTestHandler) ListNamespaces(_ context.Context, state common.ActiveStateEnum, limit, offset int32) (*namespaces.ListNamespacesResponse, error) {
	if h.namespacesResponse != nil {
		return h.namespacesResponse, nil
	}
	return &namespaces.ListNamespacesResponse{Pagination: emptyPageResponse()}, nil
}

func emptyPageResponse() *policy.PageResponse {
	return &policy.PageResponse{}
}

func actionSourceIDs(actions []*ActionPlan) []string {
	ids := make([]string, 0, len(actions))
	for _, action := range actions {
		if action == nil || action.Source == nil {
			continue
		}
		ids = append(ids, action.Source.GetId())
	}

	return ids
}

type plannerTestReviewer struct {
	calls        int
	lastResolved *ResolvedTargets
	err          error
}

func (r *plannerTestReviewer) Review(_ context.Context, resolved *ResolvedTargets, _ []*policy.Namespace) error {
	r.calls++
	r.lastResolved = resolved
	return r.err
}
