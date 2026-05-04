package namespacedpolicy

import (
	"fmt"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReviewPrunePlanMarksUnresolvedActionForDeletion(t *testing.T) {
	t.Parallel()

	reason := newPruneReason(PruneStatusReasonTypeNoMatchingLabelsFound, pruneStatusReasonMessageNoMatchingLabelsFound)
	plan := &PrunePlan{
		Actions: []*PruneActionPlan{
			{
				Source: &policy.Action{
					Id:   "action-1",
					Name: "archive",
				},
				Status: PruneStatusUnresolved,
				MigratedTargets: []TargetRef{
					{
						ID:           "target-action-1",
						NamespaceID:  "namespace-1",
						NamespaceFQN: "https://example.com",
					},
				},
				Reason: reason,
			},
		},
	}
	prompter := &testInteractivePrompter{selectValue: pruneReviewDelete}

	err := ReviewPrunePlan(t.Context(), plan, prompter)
	require.NoError(t, err)

	require.Equal(t, 1, prompter.selectCalls)
	require.NotNil(t, prompter.lastSelectPrompt)
	assert.Equal(t, `Delete unresolved action "archive"?`, prompter.lastSelectPrompt.Title)
	assert.Equal(t, []string{
		"Source ID: action-1",
		"Action: archive",
		`Migrated targets: id="target-action-1" (namespace="https://example.com")`,
		"Reason: NoMatchingLabelsFound: canonical migrated targets were found, but none carry migrated_from for this source",
	}, prompter.lastSelectPrompt.Description)
	require.Len(t, prompter.lastSelectPrompt.Options, 3)
	assert.Equal(t, PruneStatusDelete, plan.Actions[0].Status)
	assert.True(t, plan.Actions[0].Reason.IsZero())
}

func TestReviewPrunePlanSkipLeavesUnresolvedSubjectMappingUntouched(t *testing.T) {
	t.Parallel()

	reason := newPruneReason(PruneStatusReasonTypeMissingMigrationLabel, pruneStatusReasonMessageMissingMigrationLabel)
	target := TargetRef{
		ID:           "target-mapping-1",
		NamespaceID:  "namespace-1",
		NamespaceFQN: "https://example.com",
	}
	plan := &PrunePlan{
		SubjectMappings: []*PruneSubjectMappingPlan{
			{
				Source: &policy.SubjectMapping{
					Id: "mapping-1",
					AttributeValue: &policy.Value{
						Fqn: "https://example.com/attr/classification/value/secret",
					},
				},
				Status:         PruneStatusUnresolved,
				MigratedTarget: target,
				Reason:         reason,
			},
		},
	}
	prompter := &testInteractivePrompter{selectValue: pruneReviewSkip}

	err := ReviewPrunePlan(t.Context(), plan, prompter)
	require.NoError(t, err)

	assert.Equal(t, 1, prompter.selectCalls)
	assert.Equal(t, PruneStatusUnresolved, plan.SubjectMappings[0].Status)
	assert.Equal(t, target, plan.SubjectMappings[0].MigratedTarget)
	assert.Equal(t, reason, plan.SubjectMappings[0].Reason)
}

func TestReviewPrunePlanSubjectConditionSetPromptIncludesTargetsAndReason(t *testing.T) {
	t.Parallel()

	plan := &PrunePlan{
		SubjectConditionSets: []*PruneSubjectConditionSetPlan{
			{
				Source: &policy.SubjectConditionSet{
					Id: "scs-1",
				},
				Status: PruneStatusUnresolved,
				MigratedTargets: []TargetRef{
					{
						ID:           "target-scs-1",
						NamespaceFQN: "https://example.com",
					},
				},
				Reason: newPruneReason(PruneStatusReasonTypeNoMatchingLabelsFound, pruneStatusReasonMessageNoMatchingLabelsFound),
			},
		},
	}
	prompter := &testInteractivePrompter{selectValue: pruneReviewSkip}

	err := ReviewPrunePlan(t.Context(), plan, prompter)
	require.NoError(t, err)

	require.Equal(t, 1, prompter.selectCalls)
	require.NotNil(t, prompter.lastSelectPrompt)
	assert.Equal(t, `Delete unresolved subject condition set "scs-1"?`, prompter.lastSelectPrompt.Title)
	assert.Equal(t, []string{
		"Source ID: scs-1",
		`Migrated targets: id="target-scs-1" (namespace="https://example.com")`,
		"Reason: NoMatchingLabelsFound: canonical migrated targets were found, but none carry migrated_from for this source",
	}, prompter.lastSelectPrompt.Description)
}

func TestReviewPrunePlanSubjectMappingPromptIncludesActionNames(t *testing.T) {
	t.Parallel()

	plan := &PrunePlan{
		SubjectMappings: []*PruneSubjectMappingPlan{
			{
				Source: &policy.SubjectMapping{
					Id: "mapping-1",
					AttributeValue: &policy.Value{
						Fqn: "https://example.com/attr/classification/value/secret",
					},
					SubjectConditionSet: &policy.SubjectConditionSet{Id: "scs-1"},
					Actions: []*policy.Action{
						{Id: "action-1", Name: "archive"},
						{Id: "action-2", Name: "export"},
					},
				},
				Status: PruneStatusUnresolved,
				MigratedTarget: TargetRef{
					ID:           "target-mapping-1",
					NamespaceFQN: "https://example.com",
				},
				Reason: newPruneReason(PruneStatusReasonTypeMissingMigrationLabel, pruneStatusReasonMessageMissingMigrationLabel),
			},
		},
	}
	prompter := &testInteractivePrompter{selectValue: pruneReviewSkip}

	err := ReviewPrunePlan(t.Context(), plan, prompter)
	require.NoError(t, err)

	require.Equal(t, 1, prompter.selectCalls)
	require.NotNil(t, prompter.lastSelectPrompt)
	assert.Equal(t, `Delete unresolved subject mapping "mapping-1"?`, prompter.lastSelectPrompt.Title)
	assert.Equal(t, []string{
		"Source ID: mapping-1",
		"Attribute value: https://example.com/attr/classification/value/secret",
		"Subject condition set source: scs-1",
		`Actions: "archive", "export"`,
		`Migrated target: id="target-mapping-1" (namespace="https://example.com")`,
		"Reason: MissingMigrationLabel: migrated target is missing migrated_from metadata for this source",
	}, prompter.lastSelectPrompt.Description)
}

func TestReviewPrunePlanRegisteredResourceMismatchPromptShowsFilteredAndFullSource(t *testing.T) {
	t.Parallel()

	secretValue := testAttributeValue("https://example.com/attr/classification/value/secret", testNamespace("https://example.com"))
	filteredSource := testRegisteredResource(
		"resource-1",
		"dataset",
		testRegisteredResourceValue("prod", testActionAttributeValue("action-1", "read", secretValue)),
	)
	fullSource := testRegisteredResource(
		"resource-1",
		"dataset",
		testRegisteredResourceValue("prod", testActionAttributeValue("action-1", "read", secretValue)),
		testRegisteredResourceValue("dev", testActionAttributeValue("action-2", "write", secretValue)),
	)
	plan := &PrunePlan{
		RegisteredResources: []*PruneRegisteredResourcePlan{
			{
				Source:     filteredSource,
				FullSource: fullSource,
				Status:     PruneStatusUnresolved,
				MigratedTarget: TargetRef{
					ID:           "target-resource-1",
					NamespaceFQN: "https://example.com",
				},
				Reason: newPruneReason(
					PruneStatusReasonTypeRegisteredResourceSourceMismatch,
					fmt.Sprintf(pruneStatusReasonMessageRegisteredResourceSourceMismatchFmt, "https://example.com"),
				),
			},
		},
	}
	prompter := &testInteractivePrompter{selectValue: pruneReviewSkip}

	err := ReviewPrunePlan(t.Context(), plan, prompter)
	require.NoError(t, err)

	require.Equal(t, 1, prompter.selectCalls)
	require.NotNil(t, prompter.lastSelectPrompt)
	assert.Equal(t, `Delete unresolved registered resource "dataset"?`, prompter.lastSelectPrompt.Title)
	assert.Equal(t, []string{
		"Source ID: resource-1",
		"Resource: dataset",
		`Migrated target: id="target-resource-1" (namespace="https://example.com")`,
		`Filtered source: values="prod" (action_bindings="read" -> https://example.com/attr/classification/value/secret)`,
		`Full source: values="prod", "dev" (action_bindings="read" -> https://example.com/attr/classification/value/secret, "write" -> https://example.com/attr/classification/value/secret)`,
		`Reason: RegisteredResourceSourceMismatch: resolved registered resource view does not match the full source object for target namespace "https://example.com"; source contains values outside the resolved migration view`,
	}, prompter.lastSelectPrompt.Description)
}

func TestReviewPrunePlanObligationTriggerPromptIncludesTriggerContext(t *testing.T) {
	t.Parallel()

	plan := &PrunePlan{
		ObligationTriggers: []*PruneObligationTriggerPlan{
			{
				Source: &policy.ObligationTrigger{
					Id:             "trigger-1",
					AttributeValue: testAttributeValue("https://example.com/attr/classification/value/secret", testNamespace("https://example.com")),
					Action:         &policy.Action{Id: "action-1", Name: "read"},
					ObligationValue: &policy.ObligationValue{
						Id:    "obligation-value-1",
						Fqn:   "https://example.com/obl/watermark/value/footer",
						Value: "footer",
						Obligation: &policy.Obligation{
							Id:   "obligation-1",
							Fqn:  "https://example.com/obl/watermark",
							Name: "watermark",
						},
					},
					Context: []*policy.RequestContext{
						{Pep: &policy.PolicyEnforcementPoint{ClientId: "tdf-client"}},
					},
				},
				Status: PruneStatusUnresolved,
				MigratedTarget: TargetRef{
					ID:           "target-trigger-1",
					NamespaceFQN: "https://example.com",
				},
				Reason: newPruneReason(PruneStatusReasonTypeMissingMigrationLabel, pruneStatusReasonMessageMissingMigrationLabel),
			},
		},
	}
	prompter := &testInteractivePrompter{selectValue: pruneReviewSkip}

	err := ReviewPrunePlan(t.Context(), plan, prompter)
	require.NoError(t, err)

	require.Equal(t, 1, prompter.selectCalls)
	require.NotNil(t, prompter.lastSelectPrompt)
	assert.Equal(t, `Delete unresolved obligation trigger "trigger-1"?`, prompter.lastSelectPrompt.Title)
	assert.Equal(t, []string{
		"Source ID: trigger-1",
		"Attribute value: https://example.com/attr/classification/value/secret",
		"Action: read",
		"Obligation: https://example.com/obl/watermark",
		"Obligation value: https://example.com/obl/watermark/value/footer",
		`Context: client_id="tdf-client"`,
		`Migrated target: id="target-trigger-1" (namespace="https://example.com")`,
		"Reason: MissingMigrationLabel: migrated target is missing migrated_from metadata for this source",
	}, prompter.lastSelectPrompt.Description)
}

func TestReviewPrunePlanAbortReturnsAbortedAndStops(t *testing.T) {
	t.Parallel()

	plan := &PrunePlan{
		Actions: []*PruneActionPlan{
			{
				Source: &policy.Action{
					Id:   "action-1",
					Name: "archive",
				},
				Status: PruneStatusUnresolved,
				Reason: newPruneReason(PruneStatusReasonTypeNoMatchingLabelsFound, pruneStatusReasonMessageNoMatchingLabelsFound),
			},
			{
				Source: &policy.Action{
					Id:   "action-2",
					Name: "export",
				},
				Status: PruneStatusUnresolved,
				Reason: newPruneReason(PruneStatusReasonTypeNoMatchingLabelsFound, pruneStatusReasonMessageNoMatchingLabelsFound),
			},
		},
	}
	prompter := &testInteractivePrompter{selectValue: pruneReviewAbort}

	err := ReviewPrunePlan(t.Context(), plan, prompter)
	require.ErrorIs(t, err, ErrInteractiveReviewAborted)

	assert.Equal(t, 1, prompter.selectCalls)
	assert.Equal(t, PruneStatusUnresolved, plan.Actions[0].Status)
	assert.Equal(t, PruneStatusUnresolved, plan.Actions[1].Status)
}

func TestReviewPrunePlanIgnoresBlockedPruneItems(t *testing.T) {
	t.Parallel()

	plan := &PrunePlan{
		Actions: []*PruneActionPlan{
			{
				Source: &policy.Action{
					Id:   "action-1",
					Name: "archive",
				},
				Status: PruneStatusBlocked,
				Reason: newPruneReason(PruneStatusReasonTypeInUse, pruneStatusReasonMessageInUse),
			},
		},
	}
	prompter := &testInteractivePrompter{selectValue: pruneReviewDelete}

	err := ReviewPrunePlan(t.Context(), plan, prompter)
	require.NoError(t, err)

	assert.Equal(t, 0, prompter.selectCalls)
	assert.Equal(t, PruneStatusBlocked, plan.Actions[0].Status)
}

func TestReviewPrunePlanSkipsNilSourceAndNonUnresolvedItems(t *testing.T) {
	t.Parallel()

	plan := &PrunePlan{
		Actions: []*PruneActionPlan{
			nil,
			{
				Status: PruneStatusUnresolved,
				Reason: newPruneReason(
					PruneStatusReasonTypeNoMatchingLabelsFound,
					pruneStatusReasonMessageNoMatchingLabelsFound,
				),
			},
			{
				Source: &policy.Action{
					Id:   "action-1",
					Name: "archive",
				},
				Status: PruneStatusDelete,
			},
		},
	}
	prompter := &testInteractivePrompter{selectValue: pruneReviewDelete}

	err := ReviewPrunePlan(t.Context(), plan, prompter)
	require.NoError(t, err)

	assert.Equal(t, 0, prompter.selectCalls)
	assert.Equal(t, PruneStatusUnresolved, plan.Actions[1].Status)
	assert.Equal(t, PruneStatusDelete, plan.Actions[2].Status)
}
