package namespacedpolicy

import (
	"errors"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecutePruneDispatchesOnlyPlanScope(t *testing.T) {
	tests := []struct {
		name      string
		scope     Scope
		wantCalls []string
		verify    func(*testing.T, *PrunePlan)
	}{
		{
			name:      "actions",
			scope:     ScopeActions,
			wantCalls: []string{"action:action-delete-1", "action:action-delete-2"},
			verify:    verifyPruneActionsExecuted,
		},
		{
			name:      "subject condition sets",
			scope:     ScopeSubjectConditionSets,
			wantCalls: []string{"subject-condition-set:scs-delete-1", "subject-condition-set:scs-delete-2"},
			verify:    verifyPruneSubjectConditionSetsExecuted,
		},
		{
			name:      "subject mappings",
			scope:     ScopeSubjectMappings,
			wantCalls: []string{"subject-mapping:mapping-delete-1", "subject-mapping:mapping-delete-2"},
			verify:    verifyPruneSubjectMappingsExecuted,
		},
		{
			name:      "registered resources",
			scope:     ScopeRegisteredResources,
			wantCalls: []string{"registered-resource:resource-delete-1", "registered-resource:resource-delete-2"},
			verify:    verifyPruneRegisteredResourcesExecuted,
		},
		{
			name:      "obligation triggers",
			scope:     ScopeObligationTriggers,
			wantCalls: []string{"obligation-trigger:trigger-delete-1", "obligation-trigger:trigger-delete-2"},
			verify:    verifyPruneObligationTriggersExecuted,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &mockExecutorHandler{}
			plan := mixedPrunePlan(tt.scope)

			executor, err := NewExecutor(handler)
			require.NoError(t, err)

			err = executor.ExecutePrune(t.Context(), plan)
			require.NoError(t, err)

			assert.Equal(t, tt.wantCalls, handler.deleteCalls)
			tt.verify(t, plan)
		})
	}
}

func TestExecutePruneRecordsFailureAndStops(t *testing.T) {
	deleteErr := errors.New("delete denied")
	handler := &mockExecutorHandler{
		deleteActionErrs: map[string]error{
			"action-delete": deleteErr,
		},
	}
	plan := &PrunePlan{
		Scopes: []Scope{ScopeActions},
		Actions: []*PruneActionPlan{
			{Source: &policy.Action{Id: "action-delete"}, Status: PruneStatusDelete},
			{Source: &policy.Action{Id: "action-pending"}, Status: PruneStatusDelete},
		},
	}

	executor, err := NewExecutor(handler)
	require.NoError(t, err)

	err = executor.ExecutePrune(t.Context(), plan)
	require.ErrorIs(t, err, deleteErr)
	require.EqualError(t, err, `delete action "action-delete": delete denied`)

	require.NotNil(t, plan.Actions[0].Execution)
	assert.False(t, plan.Actions[0].Execution.Applied)
	assert.Equal(t, `delete action "action-delete": delete denied`, plan.Actions[0].Execution.Failure)
	assert.Nil(t, plan.Actions[1].Execution)
	assert.Equal(t, []string{"action:action-delete"}, handler.deleteCalls)
}

func TestExecutePruneRequiresSingleScope(t *testing.T) {
	handler := &mockExecutorHandler{}
	executor, err := NewExecutor(handler)
	require.NoError(t, err)

	err = executor.ExecutePrune(t.Context(), &PrunePlan{})
	require.ErrorIs(t, err, ErrEmptyPlannerScope)

	err = executor.ExecutePrune(t.Context(), &PrunePlan{
		Scopes: []Scope{ScopeActions, ScopeRegisteredResources},
	})
	require.ErrorIs(t, err, ErrMultiplePruneScopes)
}

func verifyPruneActionsExecuted(t *testing.T, plan *PrunePlan) {
	t.Helper()

	assert.True(t, plan.Actions[0].Execution.Applied)
	assert.True(t, plan.Actions[1].Execution.Applied)
	assert.Nil(t, plan.Actions[2].Execution)
	assert.Nil(t, plan.Actions[3].Execution)
}

func verifyPruneSubjectConditionSetsExecuted(t *testing.T, plan *PrunePlan) {
	t.Helper()

	assert.True(t, plan.SubjectConditionSets[0].Execution.Applied)
	assert.True(t, plan.SubjectConditionSets[1].Execution.Applied)
	assert.Nil(t, plan.SubjectConditionSets[2].Execution)
	assert.Nil(t, plan.SubjectConditionSets[3].Execution)
}

func verifyPruneSubjectMappingsExecuted(t *testing.T, plan *PrunePlan) {
	t.Helper()

	assert.True(t, plan.SubjectMappings[0].Execution.Applied)
	assert.True(t, plan.SubjectMappings[1].Execution.Applied)
	assert.Nil(t, plan.SubjectMappings[2].Execution)
}

func verifyPruneRegisteredResourcesExecuted(t *testing.T, plan *PrunePlan) {
	t.Helper()

	assert.True(t, plan.RegisteredResources[0].Execution.Applied)
	assert.True(t, plan.RegisteredResources[1].Execution.Applied)
	assert.Nil(t, plan.RegisteredResources[2].Execution)
}

func verifyPruneObligationTriggersExecuted(t *testing.T, plan *PrunePlan) {
	t.Helper()

	assert.True(t, plan.ObligationTriggers[0].Execution.Applied)
	assert.True(t, plan.ObligationTriggers[1].Execution.Applied)
	assert.Nil(t, plan.ObligationTriggers[2].Execution)
}

func mixedPrunePlan(scope Scope) *PrunePlan {
	return &PrunePlan{
		Scopes: []Scope{scope},
		Actions: []*PruneActionPlan{
			{Source: &policy.Action{Id: "action-delete-1"}, Status: PruneStatusDelete},
			{Source: &policy.Action{Id: "action-delete-2"}, Status: PruneStatusDelete},
			{Source: &policy.Action{Id: "action-blocked"}, Status: PruneStatusBlocked},
			{Source: &policy.Action{Id: "action-skipped"}, Status: PruneStatusSkipped},
		},
		SubjectConditionSets: []*PruneSubjectConditionSetPlan{
			{Source: &policy.SubjectConditionSet{Id: "scs-delete-1"}, Status: PruneStatusDelete},
			{Source: &policy.SubjectConditionSet{Id: "scs-delete-2"}, Status: PruneStatusDelete},
			{Source: &policy.SubjectConditionSet{Id: "scs-unresolved"}, Status: PruneStatusUnresolved},
			{Source: &policy.SubjectConditionSet{Id: "scs-skipped"}, Status: PruneStatusSkipped},
		},
		SubjectMappings: []*PruneSubjectMappingPlan{
			{Source: &policy.SubjectMapping{Id: "mapping-delete-1"}, Status: PruneStatusDelete},
			{Source: &policy.SubjectMapping{Id: "mapping-delete-2"}, Status: PruneStatusDelete},
			{Source: &policy.SubjectMapping{Id: "mapping-skipped"}, Status: PruneStatusSkipped},
		},
		RegisteredResources: []*PruneRegisteredResourcePlan{
			{
				Source: &policy.RegisteredResource{Id: "resource-delete-1"},
				FullSource: &policy.RegisteredResource{
					Id: "resource-delete-1",
					Values: []*policy.RegisteredResourceValue{
						{Id: "value-1"},
						{Id: "value-2"},
					},
				},
				Status: PruneStatusDelete,
			},
			{
				Source: &policy.RegisteredResource{Id: "resource-delete-2"},
				FullSource: &policy.RegisteredResource{
					Id: "resource-delete-2",
					Values: []*policy.RegisteredResourceValue{
						{Id: "value-3"},
						{Id: "value-4"},
					},
				},
				Status: PruneStatusDelete,
			},
			{
				Source: &policy.RegisteredResource{Id: "resource-skipped"},
				Status: PruneStatusSkipped,
			},
		},
		ObligationTriggers: []*PruneObligationTriggerPlan{
			{Source: &policy.ObligationTrigger{Id: "trigger-delete-1"}, Status: PruneStatusDelete},
			{Source: &policy.ObligationTrigger{Id: "trigger-delete-2"}, Status: PruneStatusDelete},
			{Source: &policy.ObligationTrigger{Id: "trigger-skipped"}, Status: PruneStatusSkipped},
		},
	}
}
