package namespacedpolicy

import (
	"fmt"
	"strings"

	"github.com/opentdf/platform/protocol/go/policy"
)

type PruneStatus string

const (
	PruneStatusDelete            PruneStatus = "delete"
	PruneStatusBlocked           PruneStatus = "blocked"
	PruneStatusUnresolved        PruneStatus = "unresolved"
	targetRefSummaryPartCapacity             = 2
)

type PruneStatusReasonType string

const (
	PruneStatusReasonTypeMigratedTargetNotFound           PruneStatusReasonType = "MigratedTargetNotFound"
	PruneStatusReasonTypeNoMatchingLabelsFound            PruneStatusReasonType = "NoMatchingLabelsFound"
	PruneStatusReasonTypeMismatchedMigrationLabel         PruneStatusReasonType = "MismatchedMigrationLabel"
	PruneStatusReasonTypeMissingMigrationLabel            PruneStatusReasonType = "MissingMigrationLabel"
	PruneStatusReasonTypeInUse                            PruneStatusReasonType = "InUse"
	PruneStatusReasonTypeNeedsMigration                   PruneStatusReasonType = "NeedsMigration"
	PruneStatusReasonTypeRegisteredResourceSourceMismatch PruneStatusReasonType = "RegisteredResourceSourceMismatch"

	pruneStatusReasonMessageMigratedTargetNotFound              = "no migrated target was found for this source"
	pruneStatusReasonMessageInUse                               = "source object is still referenced by legacy policy"
	pruneStatusReasonMessageNoMatchingLabelsFound               = "canonical migrated targets were found, but none carry migrated_from for this source"
	pruneStatusReasonMessageMismatchedMigrationLabel            = "migrated target carries migrated_from metadata for a different source"
	pruneStatusReasonMessageMissingMigrationLabel               = "migrated target is missing migrated_from metadata for this source"
	pruneStatusReasonMessageNeedsMigration                      = "source object does not have a migrated target yet"
	pruneStatusReasonMessageRegisteredResourceSourceMismatchFmt = "resolved registered resource view does not match the full source object for target namespace %q; source contains values outside the resolved migration view"
)

type PruneStatusReason struct {
	Type    PruneStatusReasonType `json:"type"`
	Message string                `json:"message"`
	fmt.Stringer
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

func (t TargetRef) String() string {
	return targetRefSummary(t)
}

func targetRefSummary(target TargetRef) string {
	if target.IsZero() {
		return noneLabel
	}

	parts := make([]string, 0, targetRefSummaryPartCapacity)
	if id := strings.TrimSpace(target.ID); id != "" {
		parts = append(parts, "id: "+strconvQuote(id))
	}

	namespace := strings.TrimSpace(target.NamespaceFQN)
	if namespace == "" {
		namespace = strings.TrimSpace(target.NamespaceID)
	}
	if namespace != "" {
		parts = append(parts, "namespace: "+strconvQuote(namespace))
	}

	if len(parts) == 0 {
		return noneLabel
	}
	return strings.Join(parts, " ")
}

func (r PruneStatusReason) IsZero() bool {
	return len(r.Type) == 0 && len(r.Message) == 0
}

func (r PruneStatusReason) String() string {
	if r.IsZero() {
		return noneLabel
	}
	if strings.TrimSpace(r.Message) == "" {
		return string(r.Type)
	}
	if r.Type == "" {
		return r.Message
	}
	return fmt.Sprintf("%s: %s", r.Type, r.Message)
}

type PrunePlan struct {
	Scopes               []Scope                         `json:"scopes"`
	Actions              []*PruneActionPlan              `json:"actions"`
	SubjectConditionSets []*PruneSubjectConditionSetPlan `json:"subject_condition_sets"`
	SubjectMappings      []*PruneSubjectMappingPlan      `json:"subject_mappings"`
	RegisteredResources  []*PruneRegisteredResourcePlan  `json:"registered_resources"`
	ObligationTriggers   []*PruneObligationTriggerPlan   `json:"obligation_triggers"`
}

type prunePlanItem interface {
	hasSource() bool
	status() PruneStatus
	setStatus(PruneStatus)
	reason() PruneStatusReason
	setReason(PruneStatusReason)
	execution() *ExecutionResult
}

// PruneActionPlan records the source action being considered for deletion and
// any migrated target actions that still reference or replace it.
type PruneActionPlan struct {
	Source          *policy.Action    `json:"source"`
	Status          PruneStatus       `json:"status"`
	MigratedTargets []TargetRef       `json:"migrated_targets,omitempty"`
	Reason          PruneStatusReason `json:"reason,omitzero"`
	Execution       *ExecutionResult  `json:"execution,omitempty"` // The CreatedTargetID is not used for the PrunePlans.
}

func (p *PruneActionPlan) hasSource() bool {
	return p != nil && p.Source != nil
}

func (p *PruneActionPlan) status() PruneStatus {
	if p == nil {
		return ""
	}
	return p.Status
}

func (p *PruneActionPlan) setStatus(status PruneStatus) {
	if p != nil {
		p.Status = status
	}
}

func (p *PruneActionPlan) reason() PruneStatusReason {
	if p == nil {
		return PruneStatusReason{}
	}
	return p.Reason
}

func (p *PruneActionPlan) setReason(reason PruneStatusReason) {
	if p != nil {
		p.Reason = reason
	}
}

func (p *PruneActionPlan) execution() *ExecutionResult {
	if p == nil {
		return nil
	}
	return p.Execution
}

// PruneSubjectConditionSetPlan records the source SCS being considered for
// deletion and any migrated target subject condition sets that still reference
// or replace it.
type PruneSubjectConditionSetPlan struct {
	Source          *policy.SubjectConditionSet `json:"source"`
	Status          PruneStatus                 `json:"status"`
	MigratedTargets []TargetRef                 `json:"migrated_targets,omitempty"`
	Reason          PruneStatusReason           `json:"reason,omitzero"`
	Execution       *ExecutionResult            `json:"execution,omitempty"`
}

func (p *PruneSubjectConditionSetPlan) hasSource() bool {
	return p != nil && p.Source != nil
}

func (p *PruneSubjectConditionSetPlan) status() PruneStatus {
	if p == nil {
		return ""
	}
	return p.Status
}

func (p *PruneSubjectConditionSetPlan) setStatus(status PruneStatus) {
	if p != nil {
		p.Status = status
	}
}

func (p *PruneSubjectConditionSetPlan) reason() PruneStatusReason {
	if p == nil {
		return PruneStatusReason{}
	}
	return p.Reason
}

func (p *PruneSubjectConditionSetPlan) setReason(reason PruneStatusReason) {
	if p != nil {
		p.Reason = reason
	}
}

func (p *PruneSubjectConditionSetPlan) execution() *ExecutionResult {
	if p == nil {
		return nil
	}
	return p.Execution
}

// PruneSubjectMappingPlan records the source subject mapping being considered
// for deletion and the single migrated target subject mapping matched to it by
// migration metadata.
type PruneSubjectMappingPlan struct {
	Source         *policy.SubjectMapping `json:"source"`
	Status         PruneStatus            `json:"status"`
	MigratedTarget TargetRef              `json:"migrated_target,omitzero"`
	Reason         PruneStatusReason      `json:"reason,omitzero"`
	Execution      *ExecutionResult       `json:"execution,omitempty"`
}

func (p *PruneSubjectMappingPlan) hasSource() bool {
	return p != nil && p.Source != nil
}

func (p *PruneSubjectMappingPlan) status() PruneStatus {
	if p == nil {
		return ""
	}
	return p.Status
}

func (p *PruneSubjectMappingPlan) setStatus(status PruneStatus) {
	if p != nil {
		p.Status = status
	}
}

func (p *PruneSubjectMappingPlan) reason() PruneStatusReason {
	if p == nil {
		return PruneStatusReason{}
	}
	return p.Reason
}

func (p *PruneSubjectMappingPlan) setReason(reason PruneStatusReason) {
	if p != nil {
		p.Reason = reason
	}
}

func (p *PruneSubjectMappingPlan) execution() *ExecutionResult {
	if p == nil {
		return nil
	}
	return p.Execution
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
	Execution      *ExecutionResult           `json:"execution,omitempty"`
}

func (p *PruneRegisteredResourcePlan) hasSource() bool {
	return p != nil && p.Source != nil
}

func (p *PruneRegisteredResourcePlan) status() PruneStatus {
	if p == nil {
		return ""
	}
	return p.Status
}

func (p *PruneRegisteredResourcePlan) setStatus(status PruneStatus) {
	if p != nil {
		p.Status = status
	}
}

func (p *PruneRegisteredResourcePlan) reason() PruneStatusReason {
	if p == nil {
		return PruneStatusReason{}
	}
	return p.Reason
}

func (p *PruneRegisteredResourcePlan) setReason(reason PruneStatusReason) {
	if p != nil {
		p.Reason = reason
	}
}

func (p *PruneRegisteredResourcePlan) execution() *ExecutionResult {
	if p == nil {
		return nil
	}
	return p.Execution
}

// PruneObligationTriggerPlan records the source obligation trigger being
// considered for deletion and the single migrated target obligation trigger
// matched to it by migration metadata.
type PruneObligationTriggerPlan struct {
	Source         *policy.ObligationTrigger `json:"source"`
	Status         PruneStatus               `json:"status"`
	MigratedTarget TargetRef                 `json:"migrated_target,omitzero"`
	Reason         PruneStatusReason         `json:"reason,omitzero"`
	Execution      *ExecutionResult          `json:"execution,omitempty"`
}

func (p *PruneObligationTriggerPlan) hasSource() bool {
	return p != nil && p.Source != nil
}

func (p *PruneObligationTriggerPlan) status() PruneStatus {
	if p == nil {
		return ""
	}
	return p.Status
}

func (p *PruneObligationTriggerPlan) setStatus(status PruneStatus) {
	if p != nil {
		p.Status = status
	}
}

func (p *PruneObligationTriggerPlan) reason() PruneStatusReason {
	if p == nil {
		return PruneStatusReason{}
	}
	return p.Reason
}

func (p *PruneObligationTriggerPlan) setReason(reason PruneStatusReason) {
	if p != nil {
		p.Reason = reason
	}
}

func (p *PruneObligationTriggerPlan) execution() *ExecutionResult {
	if p == nil {
		return nil
	}
	return p.Execution
}
