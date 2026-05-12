package namespacedpolicy

import (
	"errors"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfirmPrunePlanDeletesConfirmsDeleteItems(t *testing.T) {
	t.Parallel()

	plan := &PrunePlan{
		Actions: []*PruneActionPlan{
			{
				Source: &policy.Action{Id: "action-1", Name: "archive"},
				Status: PruneStatusDelete,
				MigratedTargets: []TargetRef{
					{ID: "target-action-1", NamespaceFQN: "https://example.com"},
				},
			},
		},
	}
	prompter := &queuedSelectPrompter{
		selectValues: []string{namespacedPolicyCommitConfirm},
	}

	err := ConfirmPrunePlanDeletes(t.Context(), plan, prompter)
	require.NoError(t, err)

	require.Equal(t, 1, prompter.selectCalls)
	assert.Equal(t, PruneStatusDelete, plan.Actions[0].Status)
	assert.True(t, plan.Actions[0].Reason.IsZero())
}

func TestConfirmPrunePlanDeletesSkipsDeleteItems(t *testing.T) {
	t.Parallel()

	plan := &PrunePlan{
		Actions: []*PruneActionPlan{
			{
				Source:          &policy.Action{Id: "action-1", Name: "archive"},
				Status:          PruneStatusDelete,
				MigratedTargets: []TargetRef{{ID: "target-action-1", NamespaceFQN: "https://example.com"}},
			},
			{
				Source:          &policy.Action{Id: "action-2", Name: "export"},
				Status:          PruneStatusDelete,
				MigratedTargets: []TargetRef{{ID: "target-action-2", NamespaceFQN: "https://example.com"}},
			},
		},
	}
	prompter := &queuedSelectPrompter{
		selectValues: []string{
			namespacedPolicyCommitSkip,
			namespacedPolicyCommitConfirm,
		},
	}

	err := ConfirmPrunePlanDeletes(t.Context(), plan, prompter)
	require.NoError(t, err)

	require.Equal(t, 2, prompter.selectCalls)
	assert.Equal(t, PruneStatusSkipped, plan.Actions[0].Status)
	assert.Equal(t, PruneStatusReasonTypeSkippedByUser, plan.Actions[0].Reason.Type)
	assert.Equal(t, skippedByUserReason, plan.Actions[0].Reason.Message)
	assert.Equal(t, PruneStatusDelete, plan.Actions[1].Status)
}

func TestConfirmPrunePlanDeletesAbortStopsWithoutMutatingCurrentItem(t *testing.T) {
	t.Parallel()

	plan := &PrunePlan{
		Actions: []*PruneActionPlan{
			{
				Source: &policy.Action{Id: "action-1", Name: "archive"},
				Status: PruneStatusDelete,
			},
			{
				Source: &policy.Action{Id: "action-2", Name: "export"},
				Status: PruneStatusDelete,
			},
		},
	}
	prompter := &queuedSelectPrompter{
		selectValues: []string{namespacedPolicyCommitAbort},
	}

	err := ConfirmPrunePlanDeletes(t.Context(), plan, prompter)
	require.ErrorIs(t, err, ErrInteractiveReviewAborted)

	require.Equal(t, 1, prompter.selectCalls)
	assert.Equal(t, PruneStatusDelete, plan.Actions[0].Status)
	assert.Equal(t, PruneStatusDelete, plan.Actions[1].Status)
}

func TestConfirmPrunePlanDeletesSkipsNilSourceAndNonDeleteItems(t *testing.T) {
	t.Parallel()

	plan := &PrunePlan{
		Actions: []*PruneActionPlan{
			nil,
			{Status: PruneStatusDelete},
			{
				Source: &policy.Action{Id: "action-blocked", Name: "archive"},
				Status: PruneStatusBlocked,
			},
			{
				Source: &policy.Action{Id: "action-unresolved", Name: "export"},
				Status: PruneStatusUnresolved,
			},
			{
				Source: &policy.Action{Id: "action-skipped", Name: "share"},
				Status: PruneStatusSkipped,
			},
		},
	}
	prompter := &queuedSelectPrompter{
		selectValues: []string{namespacedPolicyCommitSkip},
	}

	err := ConfirmPrunePlanDeletes(t.Context(), plan, prompter)
	require.NoError(t, err)

	assert.Equal(t, 0, prompter.selectCalls)
	assert.Equal(t, PruneStatusDelete, plan.Actions[1].Status)
	assert.Equal(t, PruneStatusBlocked, plan.Actions[2].Status)
	assert.Equal(t, PruneStatusUnresolved, plan.Actions[3].Status)
	assert.Equal(t, PruneStatusSkipped, plan.Actions[4].Status)
}

func TestConfirmPrunePlanDeletesPromptsAllConstructs(t *testing.T) {
	t.Parallel()

	plan := &PrunePlan{
		Actions: []*PruneActionPlan{
			{Source: &policy.Action{Id: "action-1", Name: "archive"}, Status: PruneStatusDelete},
		},
		SubjectConditionSets: []*PruneSubjectConditionSetPlan{
			{Source: &policy.SubjectConditionSet{Id: "scs-1"}, Status: PruneStatusDelete},
		},
		SubjectMappings: []*PruneSubjectMappingPlan{
			{Source: &policy.SubjectMapping{Id: "mapping-1"}, Status: PruneStatusDelete},
		},
		RegisteredResources: []*PruneRegisteredResourcePlan{
			{Source: testRegisteredResource("resource-1", "dataset"), Status: PruneStatusDelete},
		},
		ObligationTriggers: []*PruneObligationTriggerPlan{
			{Source: &policy.ObligationTrigger{Id: "trigger-1"}, Status: PruneStatusDelete},
		},
	}
	prompter := &queuedSelectPrompter{
		selectValues: []string{
			namespacedPolicyCommitConfirm,
			namespacedPolicyCommitConfirm,
			namespacedPolicyCommitConfirm,
			namespacedPolicyCommitConfirm,
			namespacedPolicyCommitConfirm,
		},
	}

	err := ConfirmPrunePlanDeletes(t.Context(), plan, prompter)
	require.NoError(t, err)

	assert.Equal(t, 5, prompter.selectCalls)
}

func TestApplyPruneDeleteConfirmationDecisionHandlesChoices(t *testing.T) {
	t.Parallel()

	promptErr := errors.New("boom")
	tests := []struct {
		name        string
		selectValue string
		selectErr   error
		wantSkipped bool
		wantErr     error
	}{
		{
			name:        "confirm",
			selectValue: namespacedPolicyCommitConfirm,
		},
		{
			name:        "skip",
			selectValue: namespacedPolicyCommitSkip,
			wantSkipped: true,
		},
		{
			name:        "abort",
			selectValue: namespacedPolicyCommitAbort,
			wantErr:     ErrInteractiveReviewAborted,
		},
		{
			name:      "prompt error",
			selectErr: promptErr,
			wantErr:   promptErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prompter := &queuedSelectPrompter{
				selectValues: []string{tt.selectValue},
				selectErr:    tt.selectErr,
			}
			skipped := false

			err := applyPruneDeleteConfirmationDecision(t.Context(), prompter, SelectPrompt{Title: "test prompt"}, func() {
				skipped = true
			})
			if tt.wantErr == nil {
				require.NoError(t, err)
				assert.Equal(t, tt.wantSkipped, skipped)
				return
			}
			require.ErrorIs(t, err, tt.wantErr)
			assert.False(t, skipped)
		})
	}
}
