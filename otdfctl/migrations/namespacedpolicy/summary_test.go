package namespacedpolicy

import (
	"regexp"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
)

func TestRenderNamespacedPolicySummaryCommitIncludesCountsAndCreatedDetails(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"}
	otherNamespace := &policy.Namespace{Id: "ns-2", Fqn: "https://example.org"}
	classificationValue := testAttributeValue("https://example.com/attr/classification/value/secret", namespace)

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
				Source: &policy.Action{Id: "action-create", Name: "decrypt"},
				Targets: []*ActionTargetPlan{
					{
						Namespace: namespace,
						Status:    TargetStatusCreate,
						Execution: &ExecutionResult{CreatedTargetID: "created-action-1"},
					},
				},
			},
			{
				Source: &policy.Action{Id: "action-skip", Name: "download"},
				Targets: []*ActionTargetPlan{
					{
						Namespace: otherNamespace,
						Status:    TargetStatusSkipped,
						Reason:    skippedByUserReason,
					},
				},
			},
		},
		SubjectConditionSets: []*SubjectConditionSetPlan{
			{
				Source: &policy.SubjectConditionSet{
					Id: "scs-1",
					SubjectSets: []*policy.SubjectSet{
						{},
						{},
					},
				},
				Targets: []*SubjectConditionSetTargetPlan{
					{
						Namespace: namespace,
						Status:    TargetStatusCreate,
						Execution: &ExecutionResult{CreatedTargetID: "created-scs-1"},
					},
				},
			},
		},
		SubjectMappings: []*SubjectMappingPlan{
			{
				Source: &policy.SubjectMapping{
					Id:             "mapping-1",
					AttributeValue: classificationValue,
				},
				Target: &SubjectMappingTargetPlan{
					Namespace:                   namespace,
					Status:                      TargetStatusCreate,
					Execution:                   &ExecutionResult{CreatedTargetID: "created-mapping-1"},
					ActionSourceIDs:             []string{"action-create"},
					SubjectConditionSetSourceID: "scs-1",
				},
			},
		},
		RegisteredResources: []*RegisteredResourcePlan{
			{
				Source: testRegisteredResource(
					"resource-1",
					"documents",
					testRegisteredResourceValue(
						"prod",
						testActionAttributeValue("action-create", "decrypt", classificationValue),
					),
				),
				Target: &RegisteredResourceTargetPlan{
					Namespace: namespace,
					Status:    TargetStatusCreate,
					Execution: &ExecutionResult{CreatedTargetID: "created-resource-1"},
					Values: []*RegisteredResourceValuePlan{
						{
							Source: &policy.RegisteredResourceValue{
								Value: "prod",
								Resource: &policy.RegisteredResource{
									Name:      "documents",
									Namespace: namespace,
								},
							},
							Execution: &ExecutionResult{CreatedTargetID: "created-resource-value-1"},
							ActionBindings: []*RegisteredResourceActionBinding{
								{
									SourceActionID: "action-create",
									AttributeValue: classificationValue,
								},
							},
						},
					},
				},
			},
			{
				Source:     testRegisteredResource("resource-2", "finance"),
				Unresolved: "conflicting namespaces",
			},
		},
		ObligationTriggers: []*ObligationTriggerPlan{
			{
				Source: &policy.ObligationTrigger{
					Id:             "trigger-1",
					Action:         &policy.Action{Id: "action-create", Name: "decrypt"},
					AttributeValue: classificationValue,
					ObligationValue: &policy.ObligationValue{
						Fqn: "https://example.com/obligation/log/value/default",
					},
				},
				Target: &ObligationTriggerTargetPlan{
					Namespace:      namespace,
					Status:         TargetStatusCreate,
					Execution:      &ExecutionResult{CreatedTargetID: "created-trigger-1"},
					ActionSourceID: "action-create",
				},
			},
		},
	}

	summary := stripANSI(RenderNamespacedPolicySummaryWithResult(plan, true, "success"))

	assert.Contains(t, summary, "Namespaced Policy Migration Committed")
	assert.Contains(t, summary, "Scopes: actions, subject-condition-sets, subject-mappings, registered-resources, obligation-triggers")
	assert.Contains(t, summary, "Commit: true")
	assert.Contains(t, summary, "Result: success")
	assert.Contains(t, summary, "Actions")
	assert.Contains(t, summary, "Counts: created=1 existing_standard=0 already_migrated=0 skipped=1 failed=0 unresolved=0")
	assert.Contains(t, summary, `action "decrypt" -> https://example.com (id: created-action-1)`)
	assert.Contains(t, summary, `action "download" -> https://example.org: skipped by user`)
	assert.Contains(t, summary, "Subject Condition Sets")
	assert.Contains(t, summary, `subject condition set "scs-1" -> https://example.com (id: created-scs-1) (subject_sets=2)`)
	assert.Contains(t, summary, "Subject Mappings")
	assert.Contains(t, summary, `subject mapping "mapping-1" -> https://example.com (id: created-mapping-1) (attribute_value=https://example.com/attr/classification/value/secret, actions="decrypt", scs_source=scs-1)`)
	assert.Contains(t, summary, "Registered Resources")
	assert.Contains(t, summary, `registered resource "documents" -> https://example.com (id: created-resource-1) (values=https://example.com/reg_res/documents/value/prod, action_bindings="decrypt" -> https://example.com/attr/classification/value/secret)`)
	assert.Contains(t, summary, `registered resource "finance": conflicting namespaces`)
	assert.Contains(t, summary, "Obligation Triggers")
	assert.Contains(t, summary, `obligation trigger "trigger-1" -> https://example.com (id: created-trigger-1) (action="decrypt", attribute_value=https://example.com/attr/classification/value/secret, obligation_value=https://example.com/obligation/log/value/default)`)
	assert.Contains(t, summary, "Created")
	assert.Contains(t, summary, "Skipped")
	assert.Contains(t, summary, "Unresolved")
}

func TestRenderNamespacedPolicySummaryDryRunUsesToCreateLabel(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"}
	plan := &Plan{
		Scopes: []Scope{ScopeActions},
		Actions: []*ActionPlan{
			{
				Source: &policy.Action{Id: "action-1", Name: "decrypt"},
				Targets: []*ActionTargetPlan{
					{
						Namespace: namespace,
						Status:    TargetStatusCreate,
						Execution: &ExecutionResult{CreatedTargetID: "created-action-1"},
					},
				},
			},
		},
	}

	summary := stripANSI(RenderNamespacedPolicySummary(plan, false))

	assert.Contains(t, summary, "Namespaced Policy Migration Plan")
	assert.Contains(t, summary, "Commit: false")
	assert.Contains(t, summary, "Result: success")
	assert.Contains(t, summary, "Counts: to_create=1 existing_standard=0 already_migrated=0 skipped=0 failed=0 unresolved=0")
	assert.Contains(t, summary, "Will Create")
	assert.NotContains(t, summary, "\nCreated\n")
	assert.Contains(t, summary, `action "decrypt" -> https://example.com`)
	assert.NotContains(t, summary, "(id: created-action-1)")
}

func TestRenderNamespacedPolicySummaryIncludesTargetlessUnresolvedEntries(t *testing.T) {
	t.Parallel()

	plan := &Plan{
		Scopes: []Scope{
			ScopeActions,
			ScopeSubjectConditionSets,
			ScopeSubjectMappings,
			ScopeObligationTriggers,
		},
		Actions: []*ActionPlan{
			{
				Source: &policy.Action{Id: "action-1", Name: "decrypt"},
				Targets: []*ActionTargetPlan{
					nil,
				},
			},
		},
		SubjectConditionSets: []*SubjectConditionSetPlan{
			{
				Source: &policy.SubjectConditionSet{Id: "scs-1"},
				Targets: []*SubjectConditionSetTargetPlan{
					nil,
				},
			},
		},
		SubjectMappings: []*SubjectMappingPlan{
			{
				Source: &policy.SubjectMapping{Id: "mapping-1"},
			},
		},
		ObligationTriggers: []*ObligationTriggerPlan{
			{
				Source: &policy.ObligationTrigger{Id: "trigger-1"},
			},
		},
	}

	summary := stripANSI(RenderNamespacedPolicySummaryWithResult(plan, true, "success"))

	assert.Contains(t, summary, "Actions")
	assert.Contains(t, summary, "Counts: created=0 existing_standard=0 already_migrated=0 skipped=0 failed=0 unresolved=1")
	assert.Contains(t, summary, `action "decrypt": received unexpected nil target for action`)
	assert.Contains(t, summary, "Subject Condition Sets")
	assert.Contains(t, summary, "Counts: created=0 existing_standard=0 already_migrated=0 skipped=0 failed=0 unresolved=1")
	assert.Contains(t, summary, `subject condition set "scs-1": received unexpected nil target for subject condition set`)
	assert.Contains(t, summary, "Subject Mappings")
	assert.Contains(t, summary, "Counts: created=0 existing_standard=0 already_migrated=0 skipped=0 failed=0 unresolved=1")
	assert.Contains(t, summary, `subject mapping "mapping-1": received unexpected nil target for subject mapping`)
	assert.Contains(t, summary, "Obligation Triggers")
	assert.Contains(t, summary, "Counts: created=0 existing_standard=0 already_migrated=0 skipped=0 failed=0 unresolved=1")
	assert.Contains(t, summary, `obligation trigger "trigger-1": received unexpected nil target for obligation trigger`)
}

func TestRenderNamespacedPolicySummaryCommitFailureShowsFailedAndPendingCreates(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"}

	plan := &Plan{
		Scopes: []Scope{
			ScopeActions,
			ScopeSubjectConditionSets,
			ScopeRegisteredResources,
		},
		Actions: []*ActionPlan{
			{
				Source: &policy.Action{Id: "action-created", Name: "decrypt"},
				Targets: []*ActionTargetPlan{
					{
						Namespace: namespace,
						Status:    TargetStatusCreate,
						Execution: &ExecutionResult{Applied: true, CreatedTargetID: "created-action-1"},
					},
				},
			},
			{
				Source: &policy.Action{Id: "action-failed", Name: "download"},
				Targets: []*ActionTargetPlan{
					{
						Namespace: namespace,
						Status:    TargetStatusCreate,
						Execution: &ExecutionResult{Failure: "boom"},
					},
				},
			},
		},
		SubjectConditionSets: []*SubjectConditionSetPlan{
			{
				Source: &policy.SubjectConditionSet{Id: "scs-pending"},
				Targets: []*SubjectConditionSetTargetPlan{
					{
						Namespace: namespace,
						Status:    TargetStatusCreate,
					},
				},
			},
		},
		RegisteredResources: []*RegisteredResourcePlan{
			{
				Source: testRegisteredResource(
					"resource-1",
					"documents",
					testRegisteredResourceValue("prod"),
				),
				Target: &RegisteredResourceTargetPlan{
					Namespace: namespace,
					Status:    TargetStatusCreate,
					Execution: &ExecutionResult{Applied: true, CreatedTargetID: "created-resource-1"},
					Values: []*RegisteredResourceValuePlan{
						{
							Source: &policy.RegisteredResourceValue{
								Id:    "rrv-1",
								Value: "prod",
								Resource: &policy.RegisteredResource{
									Name:      "documents",
									Namespace: namespace,
								},
							},
							Execution: &ExecutionResult{Failure: "value boom"},
						},
					},
				},
			},
		},
	}

	summary := stripANSI(RenderNamespacedPolicySummaryWithResult(plan, true, "failure"))

	assert.Contains(t, summary, "Result: failure")
	assert.Contains(t, summary, "Actions")
	assert.Contains(t, summary, "Counts: created=1 existing_standard=0 already_migrated=0 skipped=0 failed=1 unresolved=0")
	assert.Contains(t, summary, "Created")
	assert.Contains(t, summary, `action "decrypt" -> https://example.com (id: created-action-1)`)
	assert.Contains(t, summary, "Failed")
	assert.Contains(t, summary, `action "download" -> https://example.com: boom`)
	assert.Contains(t, summary, "Subject Condition Sets")
	assert.Contains(t, summary, "Counts: created=0 to_create=1 existing_standard=0 already_migrated=0 skipped=0 failed=0 unresolved=0")
	assert.Contains(t, summary, "Will Create")
	assert.Contains(t, summary, `subject condition set "scs-pending" -> https://example.com (subject_sets=0)`)
	assert.Contains(t, summary, "Registered Resources")
	assert.Contains(t, summary, "Counts: created=0 existing_standard=0 already_migrated=0 skipped=0 failed=1 unresolved=0")
	assert.Contains(t, summary, `registered resource "documents" -> https://example.com: value boom (value=https://example.com/reg_res/documents/value/prod)`)
}

func TestFormatSummaryCounts(t *testing.T) {
	t.Parallel()

	assert.Equal(t,
		"created=0 existing_standard=0 already_migrated=0 skipped=0 failed=0 unresolved=1",
		formatSummaryCounts(migrationStatusCounts{
			unresolved: 1,
		}, true),
	)

	assert.Equal(t,
		"created=0 to_create=1 existing_standard=0 already_migrated=0 skipped=0 failed=0 unresolved=0",
		formatSummaryCounts(migrationStatusCounts{
			toCreate: 1,
		}, true),
	)

	assert.Equal(t,
		"created=1 existing_standard=0 already_migrated=0 skipped=0 failed=1 unresolved=0",
		formatSummaryCounts(migrationStatusCounts{
			created: 1,
			failed:  1,
		}, true),
	)

	assert.Equal(t,
		"to_create=0 existing_standard=0 already_migrated=0 skipped=0 failed=0 unresolved=1",
		formatSummaryCounts(migrationStatusCounts{
			unresolved: 1,
		}, false),
	)

	assert.Equal(t,
		"to_create=1 existing_standard=0 already_migrated=0 skipped=0 failed=0 unresolved=0",
		formatSummaryCounts(migrationStatusCounts{
			toCreate: 1,
		}, false),
	)
}

func stripANSI(value string) string {
	tidyWhitespace := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return tidyWhitespace.ReplaceAllString(value, "")
}

func TestRecordTargetStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status TargetStatus
		want   migrationStatusCounts
	}{
		{
			name:   "existing standard",
			status: TargetStatusExistingStandard,
			want:   migrationStatusCounts{existingStandard: 1},
		},
		{
			name:   "already migrated",
			status: TargetStatusAlreadyMigrated,
			want:   migrationStatusCounts{alreadyMigrated: 1},
		},
		{
			name:   "skipped",
			status: TargetStatusSkipped,
			want:   migrationStatusCounts{skipped: 1},
		},
		{
			name:   "unresolved",
			status: TargetStatusUnresolved,
			want:   migrationStatusCounts{unresolved: 1},
		},
		{
			name:   "create is a no-op (tracked elsewhere)",
			status: TargetStatusCreate,
			want:   migrationStatusCounts{},
		},
		{
			name:   "unknown status is a no-op",
			status: TargetStatus("wat"),
			want:   migrationStatusCounts{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var counts migrationStatusCounts
			recordTargetStatus(&counts, tc.status)
			assert.Equal(t, tc.want, counts)
		})
	}
}

func TestRecordTargetStatusAccumulates(t *testing.T) {
	t.Parallel()

	// recordTargetStatus is called once per target during summary assembly, so
	// counters must accumulate rather than overwrite prior calls.
	var counts migrationStatusCounts
	recordTargetStatus(&counts, TargetStatusSkipped)
	recordTargetStatus(&counts, TargetStatusSkipped)
	recordTargetStatus(&counts, TargetStatusAlreadyMigrated)
	recordTargetStatus(&counts, TargetStatusUnresolved)

	assert.Equal(t, migrationStatusCounts{
		skipped:         2,
		alreadyMigrated: 1,
		unresolved:      1,
	}, counts)
}
