package namespacedpolicy

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
)

type pruneSummaryStatusLines struct {
	deleted    string
	pending    string
	failed     string
	blocked    string
	unresolved string
}

func TestRenderNamespacedPolicyPruneSummaryDryRunShowsWillDelete(t *testing.T) {
	t.Parallel()

	plan := &PrunePlan{
		Scopes: []Scope{ScopeActions},
		Actions: []*PruneActionPlan{
			{
				Source: &policy.Action{Id: "action-delete", Name: "archive"},
				Status: PruneStatusDelete,
				MigratedTargets: []TargetRef{
					{ID: "migrated-action-1", NamespaceID: "ns-1", NamespaceFQN: "https://example.com"},
				},
			},
			{
				Source: &policy.Action{Id: "action-blocked", Name: "share"},
				Status: PruneStatusBlocked,
				Reason: newPruneReason(
					PruneStatusReasonTypeInUse,
					pruneStatusReasonMessageInUse,
				),
			},
			{
				Source: &policy.Action{Id: "action-unresolved", Name: "preview"},
				Status: PruneStatusUnresolved,
				Reason: newPruneReason(
					PruneStatusReasonTypeNoMatchingLabelsFound,
					pruneStatusReasonMessageNoMatchingLabelsFound,
				),
			},
		},
	}

	summary := stripANSI(RenderNamespacedPolicyPruneSummary(plan, false, PruneSummaryResultSuccess))

	assert.Contains(t, summary, "Namespaced Policy Prune Plan")
	assert.Contains(t, summary, "Scopes: actions")
	assert.Contains(t, summary, "Commit: false")
	assert.Contains(t, summary, "Result: success")
	assert.Contains(t, summary, "Counts: to_delete=1 skipped=0 blocked=1 failed=0 unresolved=1")
	assert.Contains(t, summary, "Will Delete")
	assert.NotContains(t, summary, "\nDeleted\n")
	assert.Contains(t, summary, `action "archive" (source_id=action-delete, found_migrated_targets=[id: "migrated-action-1" namespace: "https://example.com"])`)
	assert.Contains(t, summary, "Blocked")
	assert.Contains(t, summary, `action "share" (source_id=action-blocked, found_migrated_targets=(none)): reason=InUse: source object is still referenced by legacy policy`)
	assert.Contains(t, summary, "Unresolved")
	assert.Contains(t, summary, `action "preview" (source_id=action-unresolved, found_migrated_targets=(none)): reason=NoMatchingLabelsFound: canonical migrated targets were found, but none carry migrated_from for this source`)
}

func TestRenderNamespacedPolicyPruneSummaryCommitSeparatesDeletedPendingAndFailed(t *testing.T) {
	t.Parallel()

	plan := &PrunePlan{
		Scopes: []Scope{ScopeActions},
		Actions: []*PruneActionPlan{
			{
				Source:    &policy.Action{Id: "action-deleted", Name: "archive"},
				Status:    PruneStatusDelete,
				Execution: &ExecutionResult{Applied: true},
			},
			{
				Source: &policy.Action{Id: "action-pending", Name: "preview"},
				Status: PruneStatusDelete,
			},
			{
				Source:    &policy.Action{Id: "action-failed", Name: "share"},
				Status:    PruneStatusDelete,
				Execution: &ExecutionResult{Failure: "boom"},
			},
		},
	}

	summary := stripANSI(RenderNamespacedPolicyPruneSummary(plan, true, PruneSummaryResultFailure))

	assert.Contains(t, summary, "Namespaced Policy Prune Committed")
	assert.Contains(t, summary, "Result: failure")
	assert.Contains(t, summary, "Counts: deleted=1 to_delete=1 skipped=0 blocked=0 failed=1 unresolved=0")
	assert.Contains(t, summary, "Deleted")
	assert.Contains(t, summary, `action "archive" (source_id=action-deleted, found_migrated_targets=(none))`)
	assert.Contains(t, summary, "Will Delete")
	assert.Contains(t, summary, `action "preview" (source_id=action-pending, found_migrated_targets=(none))`)
	assert.Contains(t, summary, "Failed")
	assert.Contains(t, summary, `action "share" (source_id=action-failed, found_migrated_targets=(none)): execution_failure=boom`)
}

func TestRenderNamespacedPolicyPruneSummaryCommitShowsSkippedDeletes(t *testing.T) {
	t.Parallel()

	plan := &PrunePlan{
		Scopes: []Scope{ScopeActions},
		Actions: []*PruneActionPlan{
			{
				Source: &policy.Action{Id: "action-skipped", Name: "archive"},
				Status: PruneStatusSkipped,
				Reason: newPruneReason(
					PruneStatusReasonTypeSkippedByUser,
					pruneStatusReasonMessageSkippedByUser,
				),
			},
		},
	}

	summary := stripANSI(RenderNamespacedPolicyPruneSummary(plan, true, PruneSummaryResultSuccess))

	assert.Contains(t, summary, "Counts: deleted=0 skipped=1 blocked=0 failed=0 unresolved=0")
	assert.Contains(t, summary, "Skipped")
	assert.Contains(t, summary, `action "archive" (source_id=action-skipped, found_migrated_targets=(none)): reason=SkippedByUser: skipped by user`)
	assert.NotContains(t, summary, "Will Delete")
	assert.NotContains(t, summary, "\nDeleted\n")
}

func TestRenderNamespacedPolicyPruneSummaryActionsCoversEveryStatus(t *testing.T) {
	t.Parallel()

	plan := &PrunePlan{
		Scopes: []Scope{ScopeActions},
		Actions: []*PruneActionPlan{
			{
				Source:    &policy.Action{Id: "action-deleted", Name: "archive"},
				Status:    PruneStatusDelete,
				Execution: &ExecutionResult{Applied: true},
			},
			{
				Source: &policy.Action{Id: "action-pending", Name: "preview"},
				Status: PruneStatusDelete,
			},
			{
				Source:    &policy.Action{Id: "action-failed", Name: "share"},
				Status:    PruneStatusDelete,
				Execution: &ExecutionResult{Failure: "action boom"},
			},
			{
				Source: &policy.Action{Id: "action-blocked", Name: "download"},
				Status: PruneStatusBlocked,
				Reason: pruneSummaryBlockedReason(),
			},
			{
				Source: &policy.Action{Id: "action-unresolved", Name: "export"},
				Status: PruneStatusUnresolved,
				Reason: pruneSummaryUnresolvedReason(),
			},
		},
	}

	summary := stripANSI(RenderNamespacedPolicyPruneSummary(plan, true, PruneSummaryResultFailure))

	assertPruneSummaryCoversEveryStatus(t, summary, "Actions", pruneSummaryStatusLines{
		deleted:    `action "archive" (source_id=action-deleted, found_migrated_targets=(none))`,
		pending:    `action "preview" (source_id=action-pending, found_migrated_targets=(none))`,
		failed:     `action "share" (source_id=action-failed, found_migrated_targets=(none)): execution_failure=action boom`,
		blocked:    `action "download" (source_id=action-blocked, found_migrated_targets=(none)): reason=InUse: source object is still referenced by legacy policy`,
		unresolved: `action "export" (source_id=action-unresolved, found_migrated_targets=(none)): reason=NoMatchingLabelsFound: canonical migrated targets were found, but none carry migrated_from for this source`,
	})
}

func TestRenderNamespacedPolicyPruneSummarySubjectConditionSetsCoversEveryStatus(t *testing.T) {
	t.Parallel()

	plan := &PrunePlan{
		Scopes: []Scope{ScopeSubjectConditionSets},
		SubjectConditionSets: []*PruneSubjectConditionSetPlan{
			{
				Source:    pruneSummarySubjectConditionSet("scs-deleted"),
				Status:    PruneStatusDelete,
				Execution: &ExecutionResult{Applied: true},
			},
			{
				Source: pruneSummarySubjectConditionSet("scs-pending"),
				Status: PruneStatusDelete,
			},
			{
				Source:    pruneSummarySubjectConditionSet("scs-failed"),
				Status:    PruneStatusDelete,
				Execution: &ExecutionResult{Failure: "subject condition set boom"},
			},
			{
				Source: pruneSummarySubjectConditionSet("scs-blocked"),
				Status: PruneStatusBlocked,
				Reason: pruneSummaryBlockedReason(),
			},
			{
				Source: pruneSummarySubjectConditionSet("scs-unresolved"),
				Status: PruneStatusUnresolved,
				Reason: pruneSummaryUnresolvedReason(),
			},
		},
	}

	summary := stripANSI(RenderNamespacedPolicyPruneSummary(plan, true, PruneSummaryResultFailure))

	assertPruneSummaryCoversEveryStatus(t, summary, "Subject Condition Sets", pruneSummaryStatusLines{
		deleted:    `subject condition set "scs-deleted" (subject_sets=1, found_migrated_targets=(none))`,
		pending:    `subject condition set "scs-pending" (subject_sets=1, found_migrated_targets=(none))`,
		failed:     `subject condition set "scs-failed" (subject_sets=1, found_migrated_targets=(none)): execution_failure=subject condition set boom`,
		blocked:    `subject condition set "scs-blocked" (subject_sets=1, found_migrated_targets=(none)): reason=InUse: source object is still referenced by legacy policy`,
		unresolved: `subject condition set "scs-unresolved" (subject_sets=1, found_migrated_targets=(none)): reason=NoMatchingLabelsFound: canonical migrated targets were found, but none carry migrated_from for this source`,
	})
}

func TestRenderNamespacedPolicyPruneSummarySubjectMappingsCoversEveryStatus(t *testing.T) {
	t.Parallel()

	plan := &PrunePlan{
		Scopes: []Scope{ScopeSubjectMappings},
		SubjectMappings: []*PruneSubjectMappingPlan{
			{
				Source:         pruneSummarySubjectMapping("mapping-deleted", "read"),
				Status:         PruneStatusDelete,
				MigratedTarget: pruneSummaryTarget("target-mapping-deleted"),
				Execution:      &ExecutionResult{Applied: true},
			},
			{
				Source:         pruneSummarySubjectMapping("mapping-pending", "write"),
				Status:         PruneStatusDelete,
				MigratedTarget: pruneSummaryTarget("target-mapping-pending"),
			},
			{
				Source:         pruneSummarySubjectMapping("mapping-failed", "share"),
				Status:         PruneStatusDelete,
				MigratedTarget: pruneSummaryTarget("target-mapping-failed"),
				Execution:      &ExecutionResult{Failure: "subject mapping boom"},
			},
			{
				Source:         pruneSummarySubjectMapping("mapping-blocked", "download"),
				Status:         PruneStatusBlocked,
				MigratedTarget: pruneSummaryTarget("target-mapping-blocked"),
				Reason:         pruneSummaryBlockedReason(),
			},
			{
				Source:         pruneSummarySubjectMapping("mapping-unresolved", "export"),
				Status:         PruneStatusUnresolved,
				MigratedTarget: pruneSummaryTarget("target-mapping-unresolved"),
				Reason:         pruneSummaryUnresolvedReason(),
			},
		},
	}

	summary := stripANSI(RenderNamespacedPolicyPruneSummary(plan, true, PruneSummaryResultFailure))

	assertPruneSummaryCoversEveryStatus(t, summary, "Subject Mappings", pruneSummaryStatusLines{
		deleted:    `subject mapping "mapping-deleted" (attribute_value=https://example.com/attr/classification/value/secret, actions="read", scs_source=scs-source, found_migrated_target=id: "target-mapping-deleted" namespace: "https://example.com")`,
		pending:    `subject mapping "mapping-pending" (attribute_value=https://example.com/attr/classification/value/secret, actions="write", scs_source=scs-source, found_migrated_target=id: "target-mapping-pending" namespace: "https://example.com")`,
		failed:     `subject mapping "mapping-failed" (attribute_value=https://example.com/attr/classification/value/secret, actions="share", scs_source=scs-source, found_migrated_target=id: "target-mapping-failed" namespace: "https://example.com"): execution_failure=subject mapping boom`,
		blocked:    `subject mapping "mapping-blocked" (attribute_value=https://example.com/attr/classification/value/secret, actions="download", scs_source=scs-source, found_migrated_target=id: "target-mapping-blocked" namespace: "https://example.com"): reason=InUse: source object is still referenced by legacy policy`,
		unresolved: `subject mapping "mapping-unresolved" (attribute_value=https://example.com/attr/classification/value/secret, actions="export", scs_source=scs-source, found_migrated_target=id: "target-mapping-unresolved" namespace: "https://example.com"): reason=NoMatchingLabelsFound: canonical migrated targets were found, but none carry migrated_from for this source`,
	})
}

func TestRenderNamespacedPolicyPruneSummaryRegisteredResourcesCoversEveryStatus(t *testing.T) {
	t.Parallel()

	plan := &PrunePlan{
		Scopes: []Scope{ScopeRegisteredResources},
		RegisteredResources: []*PruneRegisteredResourcePlan{
			{
				Source:         pruneSummaryRegisteredResource("resource-deleted", "dataset-deleted", "read"),
				Status:         PruneStatusDelete,
				MigratedTarget: pruneSummaryTarget("target-resource-deleted"),
				Execution:      &ExecutionResult{Applied: true},
			},
			{
				Source:         pruneSummaryRegisteredResource("resource-pending", "dataset-pending", "write"),
				Status:         PruneStatusDelete,
				MigratedTarget: pruneSummaryTarget("target-resource-pending"),
			},
			{
				Source:         pruneSummaryRegisteredResource("resource-failed", "dataset-failed", "share"),
				Status:         PruneStatusDelete,
				MigratedTarget: pruneSummaryTarget("target-resource-failed"),
				Execution:      &ExecutionResult{Failure: "registered resource boom"},
			},
			{
				Source:         pruneSummaryRegisteredResource("resource-blocked", "dataset-blocked", "download"),
				Status:         PruneStatusBlocked,
				MigratedTarget: pruneSummaryTarget("target-resource-blocked"),
				Reason:         pruneSummaryBlockedReason(),
			},
			{
				Source:         pruneSummaryRegisteredResource("resource-unresolved", "dataset-unresolved", "export"),
				Status:         PruneStatusUnresolved,
				MigratedTarget: pruneSummaryTarget("target-resource-unresolved"),
				Reason:         pruneSummaryUnresolvedReason(),
			},
		},
	}

	summary := stripANSI(RenderNamespacedPolicyPruneSummary(plan, true, PruneSummaryResultFailure))

	assertPruneSummaryCoversEveryStatus(t, summary, "Registered Resources", pruneSummaryStatusLines{
		deleted:    `registered resource "dataset-deleted" (source_id=resource-deleted, source=values="prod" (action_bindings="read" -> https://example.com/attr/classification/value/secret), found_migrated_target=id: "target-resource-deleted" namespace: "https://example.com")`,
		pending:    `registered resource "dataset-pending" (source_id=resource-pending, source=values="prod" (action_bindings="write" -> https://example.com/attr/classification/value/secret), found_migrated_target=id: "target-resource-pending" namespace: "https://example.com")`,
		failed:     `registered resource "dataset-failed" (source_id=resource-failed, source=values="prod" (action_bindings="share" -> https://example.com/attr/classification/value/secret), found_migrated_target=id: "target-resource-failed" namespace: "https://example.com"): execution_failure=registered resource boom`,
		blocked:    `registered resource "dataset-blocked" (source_id=resource-blocked, source=values="prod" (action_bindings="download" -> https://example.com/attr/classification/value/secret), found_migrated_target=id: "target-resource-blocked" namespace: "https://example.com"): reason=InUse: source object is still referenced by legacy policy`,
		unresolved: `registered resource "dataset-unresolved" (source_id=resource-unresolved, source=values="prod" (action_bindings="export" -> https://example.com/attr/classification/value/secret), found_migrated_target=id: "target-resource-unresolved" namespace: "https://example.com"): reason=NoMatchingLabelsFound: canonical migrated targets were found, but none carry migrated_from for this source`,
	})
}

func TestRenderNamespacedPolicyPruneSummaryRegisteredResourceMismatchShowsSourceOnly(t *testing.T) {
	t.Parallel()

	filteredSource := pruneSummaryRegisteredResource("resource-1", "dataset", "read")
	fullSource := testRegisteredResource(
		"resource-1",
		"dataset",
		testRegisteredResourceValue("prod", testActionAttributeValue("action-read", "read", pruneSummaryAttributeValue())),
		testRegisteredResourceValue("dev", testActionAttributeValue("action-write", "write", pruneSummaryAttributeValue())),
	)
	plan := &PrunePlan{
		Scopes: []Scope{ScopeRegisteredResources},
		RegisteredResources: []*PruneRegisteredResourcePlan{
			{
				Source:         filteredSource,
				FullSource:     fullSource,
				Status:         PruneStatusUnresolved,
				MigratedTarget: pruneSummaryTarget("target-resource-1"),
				Reason: newPruneReason(
					PruneStatusReasonTypeRegisteredResourceSourceMismatch,
					"source mismatch",
				),
			},
		},
	}

	summary := stripANSI(RenderNamespacedPolicyPruneSummary(plan, false, PruneSummaryResultSuccess))

	assert.Contains(t, summary, `registered resource "dataset" (source_id=resource-1, source=values="prod" (action_bindings="read" -> https://example.com/attr/classification/value/secret), found_migrated_target=id: "target-resource-1" namespace: "https://example.com"): reason=RegisteredResourceSourceMismatch: source mismatch`)
	assert.NotContains(t, summary, "filtered_source=")
	assert.NotContains(t, summary, "full_source=")
	assert.NotContains(t, summary, `"dev"`)
}

func TestRenderNamespacedPolicyPruneSummaryObligationTriggersCoversEveryStatus(t *testing.T) {
	t.Parallel()

	plan := &PrunePlan{
		Scopes: []Scope{ScopeObligationTriggers},
		ObligationTriggers: []*PruneObligationTriggerPlan{
			{
				Source:         pruneSummaryObligationTrigger("trigger-deleted", "read"),
				Status:         PruneStatusDelete,
				MigratedTarget: pruneSummaryTarget("target-trigger-deleted"),
				Execution:      &ExecutionResult{Applied: true},
			},
			{
				Source:         pruneSummaryObligationTrigger("trigger-pending", "write"),
				Status:         PruneStatusDelete,
				MigratedTarget: pruneSummaryTarget("target-trigger-pending"),
			},
			{
				Source:         pruneSummaryObligationTrigger("trigger-failed", "share"),
				Status:         PruneStatusDelete,
				MigratedTarget: pruneSummaryTarget("target-trigger-failed"),
				Execution:      &ExecutionResult{Failure: "obligation trigger boom"},
			},
			{
				Source:         pruneSummaryObligationTrigger("trigger-blocked", "download"),
				Status:         PruneStatusBlocked,
				MigratedTarget: pruneSummaryTarget("target-trigger-blocked"),
				Reason:         pruneSummaryBlockedReason(),
			},
			{
				Source:         pruneSummaryObligationTrigger("trigger-unresolved", "export"),
				Status:         PruneStatusUnresolved,
				MigratedTarget: pruneSummaryTarget("target-trigger-unresolved"),
				Reason:         pruneSummaryUnresolvedReason(),
			},
		},
	}

	summary := stripANSI(RenderNamespacedPolicyPruneSummary(plan, true, PruneSummaryResultFailure))

	assertPruneSummaryCoversEveryStatus(t, summary, "Obligation Triggers", pruneSummaryStatusLines{
		deleted:    `obligation trigger "trigger-deleted" (attribute_value=https://example.com/attr/classification/value/secret, action="read", obligation_value=https://example.com/obligation/log/value/default, context=client_id: "tdf-client", found_migrated_target=id: "target-trigger-deleted" namespace: "https://example.com")`,
		pending:    `obligation trigger "trigger-pending" (attribute_value=https://example.com/attr/classification/value/secret, action="write", obligation_value=https://example.com/obligation/log/value/default, context=client_id: "tdf-client", found_migrated_target=id: "target-trigger-pending" namespace: "https://example.com")`,
		failed:     `obligation trigger "trigger-failed" (attribute_value=https://example.com/attr/classification/value/secret, action="share", obligation_value=https://example.com/obligation/log/value/default, context=client_id: "tdf-client", found_migrated_target=id: "target-trigger-failed" namespace: "https://example.com"): execution_failure=obligation trigger boom`,
		blocked:    `obligation trigger "trigger-blocked" (attribute_value=https://example.com/attr/classification/value/secret, action="download", obligation_value=https://example.com/obligation/log/value/default, context=client_id: "tdf-client", found_migrated_target=id: "target-trigger-blocked" namespace: "https://example.com"): reason=InUse: source object is still referenced by legacy policy`,
		unresolved: `obligation trigger "trigger-unresolved" (attribute_value=https://example.com/attr/classification/value/secret, action="export", obligation_value=https://example.com/obligation/log/value/default, context=client_id: "tdf-client", found_migrated_target=id: "target-trigger-unresolved" namespace: "https://example.com"): reason=NoMatchingLabelsFound: canonical migrated targets were found, but none carry migrated_from for this source`,
	})
}

func assertPruneSummaryCoversEveryStatus(t *testing.T, summary, constructTitle string, lines pruneSummaryStatusLines) {
	t.Helper()

	assert.Contains(t, summary, constructTitle)
	assert.Contains(t, summary, "Counts: deleted=1 to_delete=1 skipped=0 blocked=1 failed=1 unresolved=1")
	assert.Contains(t, summary, "Deleted")
	assert.Contains(t, summary, lines.deleted)
	assert.Contains(t, summary, "Will Delete")
	assert.Contains(t, summary, lines.pending)
	assert.Contains(t, summary, "Failed")
	assert.Contains(t, summary, lines.failed)
	assert.Contains(t, summary, "Blocked")
	assert.Contains(t, summary, lines.blocked)
	assert.Contains(t, summary, "Unresolved")
	assert.Contains(t, summary, lines.unresolved)
}

func pruneSummaryBlockedReason() PruneStatusReason {
	return newPruneReason(PruneStatusReasonTypeInUse, pruneStatusReasonMessageInUse)
}

func pruneSummaryUnresolvedReason() PruneStatusReason {
	return newPruneReason(PruneStatusReasonTypeNoMatchingLabelsFound, pruneStatusReasonMessageNoMatchingLabelsFound)
}

func pruneSummaryTarget(id string) TargetRef {
	return TargetRef{
		ID:           id,
		NamespaceFQN: "https://example.com",
	}
}

func pruneSummaryAttributeValue() *policy.Value {
	return testAttributeValue("https://example.com/attr/classification/value/secret", testNamespace("https://example.com"))
}

func pruneSummarySubjectConditionSet(id string) *policy.SubjectConditionSet {
	return &policy.SubjectConditionSet{
		Id: id,
		SubjectSets: []*policy.SubjectSet{
			{},
		},
	}
}

func pruneSummarySubjectMapping(id, actionName string) *policy.SubjectMapping {
	return &policy.SubjectMapping{
		Id:             id,
		AttributeValue: pruneSummaryAttributeValue(),
		SubjectConditionSet: &policy.SubjectConditionSet{
			Id: "scs-source",
		},
		Actions: []*policy.Action{
			{Id: "action-" + actionName, Name: actionName},
		},
	}
}

func pruneSummaryRegisteredResource(id, name, actionName string) *policy.RegisteredResource {
	return testRegisteredResource(
		id,
		name,
		testRegisteredResourceValue("prod", testActionAttributeValue("action-"+actionName, actionName, pruneSummaryAttributeValue())),
	)
}

func pruneSummaryObligationTrigger(id, actionName string) *policy.ObligationTrigger {
	return &policy.ObligationTrigger{
		Id:             id,
		AttributeValue: pruneSummaryAttributeValue(),
		Action: &policy.Action{
			Id:   "action-" + actionName,
			Name: actionName,
		},
		ObligationValue: &policy.ObligationValue{
			Fqn: "https://example.com/obligation/log/value/default",
		},
		Context: []*policy.RequestContext{
			{Pep: &policy.PolicyEnforcementPoint{ClientId: "tdf-client"}},
		},
	}
}
