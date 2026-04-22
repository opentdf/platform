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
				Source: testRegisteredResource("resource-2", "finance"),
				Target: &RegisteredResourceTargetPlan{
					Namespace: otherNamespace,
					Status:    TargetStatusUnresolved,
					Reason:    "conflicting namespaces",
				},
			},
		},
		ObligationTriggers: []*ObligationTriggerPlan{
			{
				Source: &policy.ObligationTrigger{
					Id:             "trigger-1",
					Action:         &policy.Action{Id: "action-create", Name: "decrypt"},
					AttributeValue: classificationValue,
					ObligationValue: &policy.ObligationValue{
						Id: "obligation-value-1",
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
	assert.Contains(t, summary, "Counts: created=1 existing_standard=0 already_migrated=0 skipped=1 unresolved=0")
	assert.Contains(t, summary, `action "decrypt" -> https://example.com (id: created-action-1)`)
	assert.Contains(t, summary, `action "download" -> https://example.org: skipped by user`)
	assert.Contains(t, summary, "Subject Condition Sets")
	assert.Contains(t, summary, `subject condition set "scs-1" -> https://example.com (id: created-scs-1) (subject_sets=2)`)
	assert.Contains(t, summary, "Subject Mappings")
	assert.Contains(t, summary, `subject mapping "mapping-1" -> https://example.com (id: created-mapping-1) (attribute_value=https://example.com/attr/classification/value/secret, actions="decrypt", scs_source=scs-1)`)
	assert.Contains(t, summary, "Registered Resources")
	assert.Contains(t, summary, `registered resource "documents" -> https://example.com (id: created-resource-1) (values=https://example.com/reg_res/documents/value/prod, action_bindings="decrypt" -> https://example.com/attr/classification/value/secret)`)
	assert.Contains(t, summary, `registered resource "finance" -> https://example.org: conflicting namespaces`)
	assert.Contains(t, summary, "Obligation Triggers")
	assert.Contains(t, summary, `obligation trigger "trigger-1" -> https://example.com (id: created-trigger-1) (action="decrypt", attribute_value=https://example.com/attr/classification/value/secret, obligation_value=obligation-value-1)`)
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
	assert.Contains(t, summary, "Counts: to_create=1 existing_standard=0 already_migrated=0 skipped=0 unresolved=0")
	assert.Contains(t, summary, "Will Create")
	assert.Contains(t, summary, `action "decrypt" -> https://example.com`)
	assert.NotContains(t, summary, "(id: created-action-1)")
}

func stripANSI(value string) string {
	tidyWhitespace := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return tidyWhitespace.ReplaceAllString(value, "")
}
