package namespacedpolicy

import "github.com/opentdf/platform/protocol/go/policy"

type PruneStatus string

const (
	PruneStatusDelete     PruneStatus = "delete"
	PruneStatusBlocked    PruneStatus = "blocked"
	PruneStatusUnresolved PruneStatus = "unresolved"
)

type PruneStatusReasonType string

const (
	PruneStatusReasonTypeMigratedTargetNotFound           PruneStatusReasonType = "MigratedTargetNotFound"
	PruneStatusReasonTypeMigrationLabelsNotFound          PruneStatusReasonType = "MigrationLabelsNotFound"
	PruneStatusReasonTypeInUse                            PruneStatusReasonType = "InUse"
	PruneStatusReasonTypeNeedsMigration                   PruneStatusReasonType = "NeedsMigration"
	PruneStatusReasonTypeRegisteredResourceSourceMismatch PruneStatusReasonType = "RegisteredResourceSourceMismatch"
)

type PruneStatusReason struct {
	Type    PruneStatusReasonType `json:"type"`
	Message string                `json:"message"`
}

// TargetRef identifies the migrated target object that the planner
// matched to a source object. For objects that resolve to a single migrated
// target, the prune plan uses `TargetRef`. For objects that may still be
// referenced across multiple migrated namespaces, the prune plan uses
// `TargetRefs`.
type TargetRef struct {
	ID           string `json:"id"`
	NamespaceID  string `json:"namespace_id,omitempty"`
	NamespaceFQN string `json:"namespace_fqn,omitempty"`
}

func (t TargetRef) IsZero() bool {
	return len(t.ID) == 0 && len(t.NamespaceID) == 0 && len(t.NamespaceFQN) == 0
}

func (r PruneStatusReason) IsZero() bool {
	return len(r.Type) == 0 && len(r.Message) == 0
}

type PrunePlan struct {
	Scopes               []Scope                         `json:"scopes"`
	Actions              []*PruneActionPlan              `json:"actions"`
	SubjectConditionSets []*PruneSubjectConditionSetPlan `json:"subject_condition_sets"`
	SubjectMappings      []*PruneSubjectMappingPlan      `json:"subject_mappings"`
	RegisteredResources  []*PruneRegisteredResourcePlan  `json:"registered_resources"`
	ObligationTriggers   []*PruneObligationTriggerPlan   `json:"obligation_triggers"`
}

// PruneActionPlan records the source action being considered for deletion and
// any migrated target actions that still reference or replace it.
type PruneActionPlan struct {
	Source          *policy.Action    `json:"source"`
	Status          PruneStatus       `json:"status"`
	MigratedTargets []TargetRef       `json:"migrated_targets,omitempty"`
	Reason          PruneStatusReason `json:"reason,omitzero"`
}

// PruneSubjectConditionSetPlan records the source SCS being considered for
// deletion and any migrated target subject condition sets that still reference
// or replace it.
type PruneSubjectConditionSetPlan struct {
	Source          *policy.SubjectConditionSet `json:"source"`
	Status          PruneStatus                 `json:"status"`
	MigratedTargets []TargetRef                 `json:"migrated_targets,omitempty"`
	Reason          PruneStatusReason           `json:"reason,omitzero"`
}

// PruneSubjectMappingPlan records the source subject mapping being considered
// for deletion and the single migrated target subject mapping matched to it by
// migration metadata.
type PruneSubjectMappingPlan struct {
	Source         *policy.SubjectMapping `json:"source"`
	Status         PruneStatus            `json:"status"`
	MigratedTarget TargetRef              `json:"migrated_target,omitzero"`
	Reason         PruneStatusReason      `json:"reason,omitzero"`
}

// PruneRegisteredResourcePlan records the resolved RR source being considered
// for deletion and the single migrated target RR matched to it by migration
// metadata.
type PruneRegisteredResourcePlan struct {
	// Source is the resolved RR source from planning and may be filtered by interactive review.
	Source *policy.RegisteredResource `json:"source"`
	// FullSource is the authoritative RR source reloaded from the global namespace for prune verification.
	FullSource     *policy.RegisteredResource `json:"full_source,omitempty"`
	Status         PruneStatus                `json:"status"`
	MigratedTarget TargetRef                  `json:"migrated_target,omitzero"`
	Reason         PruneStatusReason          `json:"reason,omitzero"`
}

// PruneObligationTriggerPlan records the source obligation trigger being
// considered for deletion and the single migrated target obligation trigger
// matched to it by migration metadata.
type PruneObligationTriggerPlan struct {
	Source         *policy.ObligationTrigger `json:"source"`
	Status         PruneStatus               `json:"status"`
	MigratedTarget TargetRef                 `json:"migrated_target,omitzero"`
	Reason         PruneStatusReason         `json:"reason,omitzero"`
}
