package namespacedpolicy

import (
	"context"
	"errors"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfirmNamespacedPolicyBackupMapsAbortToBackupError(t *testing.T) {
	t.Parallel()

	prompter := &testInteractivePrompter{
		confirmErr: ErrInteractiveReviewAborted,
	}

	err := ConfirmNamespacedPolicyBackup(t.Context(), prompter)
	require.ErrorIs(t, err, ErrNamespacedPolicyBackupNotConfirmed)

	require.Equal(t, 1, prompter.confirmCalls)
	require.NotNil(t, prompter.lastConfirmPrompt)
	assert.Equal(t, backupConfirmTitle, prompter.lastConfirmPrompt.Title)
	assert.Equal(t, []string{backupConfirmDetail, backupAbortDetail}, prompter.lastConfirmPrompt.Description)
	assert.Equal(t, backupConfirmLabel, prompter.lastConfirmPrompt.ConfirmLabel)
	assert.Equal(t, backupCancelLabel, prompter.lastConfirmPrompt.CancelLabel)
}

func TestReviewNamespacedPolicyInteractiveCommitSkipsDependentsOfSkippedAction(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	attributeValue := testAttributeValue("https://example.com/attr/classification/value/secret", namespace)
	plan := &Plan{
		Scopes: []Scope{
			ScopeActions,
			ScopeSubjectConditionSets,
			ScopeSubjectMappings,
			ScopeRegisteredResources,
			ScopeObligationTriggers,
		},
		Actions: []*ActionPlan{
			{
				Source: &policy.Action{Id: "action-1", Name: "decrypt"},
				Targets: []*ActionTargetPlan{
					{
						Namespace: namespace,
						Status:    TargetStatusCreate,
					},
				},
			},
		},
		SubjectConditionSets: []*SubjectConditionSetPlan{
			{
				Source: &policy.SubjectConditionSet{Id: "scs-1"},
				Targets: []*SubjectConditionSetTargetPlan{
					{
						Namespace: namespace,
						Status:    TargetStatusCreate,
					},
				},
			},
		},
		SubjectMappings: []*SubjectMappingPlan{
			{
				Source: &policy.SubjectMapping{
					Id:             "mapping-1",
					AttributeValue: attributeValue,
				},
				Target: &SubjectMappingTargetPlan{
					Namespace:                   namespace,
					Status:                      TargetStatusCreate,
					ActionSourceIDs:             []string{"action-1"},
					SubjectConditionSetSourceID: "scs-1",
				},
			},
		},
		RegisteredResources: []*RegisteredResourcePlan{
			{
				Source: testRegisteredResource("resource-1", "documents"),
				Target: &RegisteredResourceTargetPlan{
					Namespace: namespace,
					Status:    TargetStatusCreate,
					Values: []*RegisteredResourceValuePlan{
						{
							ActionBindings: []*RegisteredResourceActionBinding{
								{
									SourceActionID: "action-1",
									AttributeValue: attributeValue,
								},
							},
						},
					},
				},
			},
		},
		ObligationTriggers: []*ObligationTriggerPlan{
			{
				Source: &policy.ObligationTrigger{
					Id:             "trigger-1",
					Action:         &policy.Action{Id: "action-1", Name: "decrypt"},
					AttributeValue: attributeValue,
					ObligationValue: &policy.ObligationValue{
						Id: "obligation-value-1",
					},
				},
				Target: &ObligationTriggerTargetPlan{
					Namespace:      namespace,
					Status:         TargetStatusCreate,
					ActionSourceID: "action-1",
				},
			},
		},
	}

	prompter := &queuedSelectPrompter{
		selectValues: []string{
			namespacedPolicyCommitSkip,
			namespacedPolicyCommitConfirm,
		},
	}

	err := ReviewNamespacedPolicyInteractiveCommit(t.Context(), plan, prompter)
	require.NoError(t, err)

	require.Equal(t, 2, prompter.selectCalls)

	actionTarget := plan.Actions[0].Targets[0]
	assert.Equal(t, TargetStatusSkipped, actionTarget.Status)
	assert.Equal(t, skippedByUserReason, actionTarget.Reason)
	assert.Nil(t, actionTarget.Execution)

	scsTarget := plan.SubjectConditionSets[0].Targets[0]
	assert.Equal(t, TargetStatusCreate, scsTarget.Status)
	assert.Empty(t, scsTarget.Reason)

	mappingTarget := plan.SubjectMappings[0].Target
	assert.Equal(t, TargetStatusSkipped, mappingTarget.Status)
	assert.Contains(t, mappingTarget.Reason, `depends on skipped action "decrypt" in https://example.com`)
	assert.Nil(t, mappingTarget.Execution)

	resourceTarget := plan.RegisteredResources[0].Target
	assert.Equal(t, TargetStatusSkipped, resourceTarget.Status)
	assert.Contains(t, resourceTarget.Reason, `depends on skipped action "decrypt" in https://example.com`)
	assert.Nil(t, resourceTarget.Execution)
	require.Len(t, resourceTarget.Values, 1)
	assert.Nil(t, resourceTarget.Values[0].Execution)

	triggerTarget := plan.ObligationTriggers[0].Target
	assert.Equal(t, TargetStatusSkipped, triggerTarget.Status)
	assert.Contains(t, triggerTarget.Reason, `depends on skipped action "decrypt" in https://example.com`)
	assert.Nil(t, triggerTarget.Execution)
}

func TestReviewNamespacedPolicyInteractiveCommitSkipsMappingsDependentOnSkippedSCS(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	attributeValue := testAttributeValue("https://example.com/attr/classification/value/secret", namespace)
	plan := &Plan{
		Scopes: []Scope{
			ScopeActions,
			ScopeSubjectConditionSets,
			ScopeSubjectMappings,
		},
		Actions: []*ActionPlan{
			{
				Source: &policy.Action{Id: "action-1", Name: "decrypt"},
				Targets: []*ActionTargetPlan{
					{
						Namespace: namespace,
						Status:    TargetStatusCreate,
					},
				},
			},
		},
		SubjectConditionSets: []*SubjectConditionSetPlan{
			{
				Source: &policy.SubjectConditionSet{Id: "scs-1"},
				Targets: []*SubjectConditionSetTargetPlan{
					{
						Namespace: namespace,
						Status:    TargetStatusCreate,
					},
				},
			},
		},
		SubjectMappings: []*SubjectMappingPlan{
			{
				Source: &policy.SubjectMapping{
					Id:             "mapping-1",
					AttributeValue: attributeValue,
				},
				Target: &SubjectMappingTargetPlan{
					Namespace:                   namespace,
					Status:                      TargetStatusCreate,
					ActionSourceIDs:             []string{"action-1"},
					SubjectConditionSetSourceID: "scs-1",
				},
			},
		},
	}

	prompter := &queuedSelectPrompter{
		selectValues: []string{
			namespacedPolicyCommitConfirm,
			namespacedPolicyCommitSkip,
		},
	}

	err := ReviewNamespacedPolicyInteractiveCommit(t.Context(), plan, prompter)
	require.NoError(t, err)

	require.Equal(t, 2, prompter.selectCalls)

	actionTarget := plan.Actions[0].Targets[0]
	assert.Equal(t, TargetStatusCreate, actionTarget.Status)
	assert.Empty(t, actionTarget.Reason)
	assert.Nil(t, actionTarget.Execution)

	scsTarget := plan.SubjectConditionSets[0].Targets[0]
	assert.Equal(t, TargetStatusSkipped, scsTarget.Status)
	assert.Equal(t, skippedByUserReason, scsTarget.Reason)
	assert.Nil(t, scsTarget.Execution)

	mappingTarget := plan.SubjectMappings[0].Target
	assert.Equal(t, TargetStatusSkipped, mappingTarget.Status)
	assert.Contains(t, mappingTarget.Reason, `depends on skipped subject condition set "scs-1" in https://example.com`)
	assert.Nil(t, mappingTarget.Execution)
}

func TestReviewNamespacedPolicyInteractiveCommitPropagatesAbort(t *testing.T) {
	t.Parallel()

	// The user aborts on the first action prompt. The reviewer must (a) return
	// ErrInteractiveReviewAborted so the caller stops, and (b) not prompt for
	// any later action or downstream object, so no half-applied migration is
	// committed.
	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	attributeValue := testAttributeValue("https://example.com/attr/classification/value/secret", namespace)
	plan := &Plan{
		Scopes: []Scope{
			ScopeActions,
			ScopeSubjectConditionSets,
			ScopeSubjectMappings,
		},
		Actions: []*ActionPlan{
			{
				Source: &policy.Action{Id: "action-1", Name: "decrypt"},
				Targets: []*ActionTargetPlan{
					{Namespace: namespace, Status: TargetStatusCreate},
				},
			},
			{
				Source: &policy.Action{Id: "action-2", Name: "read"},
				Targets: []*ActionTargetPlan{
					{Namespace: namespace, Status: TargetStatusCreate},
				},
			},
		},
		SubjectConditionSets: []*SubjectConditionSetPlan{
			{
				Source: &policy.SubjectConditionSet{Id: "scs-1"},
				Targets: []*SubjectConditionSetTargetPlan{
					{Namespace: namespace, Status: TargetStatusCreate},
				},
			},
		},
		SubjectMappings: []*SubjectMappingPlan{
			{
				Source: &policy.SubjectMapping{
					Id:             "mapping-1",
					AttributeValue: attributeValue,
				},
				Target: &SubjectMappingTargetPlan{
					Namespace:                   namespace,
					Status:                      TargetStatusCreate,
					ActionSourceIDs:             []string{"action-1"},
					SubjectConditionSetSourceID: "scs-1",
				},
			},
		},
	}

	prompter := &queuedSelectPrompter{
		selectValues: []string{namespacedPolicyCommitAbort},
	}

	err := ReviewNamespacedPolicyInteractiveCommit(t.Context(), plan, prompter)
	require.ErrorIs(t, err, ErrInteractiveReviewAborted)

	// Only the first prompt should have fired; abort must halt the walkthrough.
	require.Equal(t, 1, prompter.selectCalls)

	// Abort must not mutate target state — subsequent execution should be able
	// to run or the user should be able to retry.
	assert.Equal(t, TargetStatusCreate, plan.Actions[0].Targets[0].Status)
	assert.Empty(t, plan.Actions[0].Targets[0].Reason)
	assert.Equal(t, TargetStatusCreate, plan.Actions[1].Targets[0].Status)
	assert.Equal(t, TargetStatusCreate, plan.SubjectConditionSets[0].Targets[0].Status)
	assert.Equal(t, TargetStatusCreate, plan.SubjectMappings[0].Target.Status)
}

func TestApplyInteractiveDecisionHandlesChoices(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		selectValue string
		selectErr   error
		wantErr     error
	}{
		{
			name:        "confirm",
			selectValue: namespacedPolicyCommitConfirm,
		},
		{
			name:        "skip",
			selectValue: namespacedPolicyCommitSkip,
			wantErr:     errInteractiveSkipSelected,
		},
		{
			name:        "abort",
			selectValue: namespacedPolicyCommitAbort,
			wantErr:     ErrInteractiveReviewAborted,
		},
		{
			name:      "prompt error",
			selectErr: errors.New("boom"),
			wantErr:   errors.New("boom"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prompter := &queuedSelectPrompter{
				selectValues: []string{tt.selectValue},
				selectErr:    tt.selectErr,
			}

			err := applyInteractiveDecision(t.Context(), prompter, SelectPrompt{
				Title: "test prompt",
			})
			if tt.wantErr == nil {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, tt.wantErr.Error())
		})
	}
}

type queuedSelectPrompter struct {
	selectCalls  int
	selectValues []string
	selectErr    error
}

func (p *queuedSelectPrompter) Confirm(_ context.Context, _ ConfirmPrompt) error {
	return nil
}

func (p *queuedSelectPrompter) Select(_ context.Context, _ SelectPrompt) (string, error) {
	p.selectCalls++
	if p.selectErr != nil {
		return "", p.selectErr
	}
	if len(p.selectValues) == 0 {
		return "", nil
	}

	value := p.selectValues[0]
	p.selectValues = p.selectValues[1:]
	return value, nil
}
