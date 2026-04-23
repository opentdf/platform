package namespacedpolicy

import (
	"errors"
	"strings"

	identifier "github.com/opentdf/platform/lib/identifier"
	"github.com/opentdf/platform/protocol/go/policy"
)

var (
	ErrNilRetrieved              = errors.New("planner retrieved state is required")
	ErrMissingTargetNamespace    = errors.New("missing target namespace")
	ErrUndeterminedTargetMapping = errors.New("could not determine target namespace")

	ErrMissingActionID                         = errors.New("action reference missing id")
	ErrMissingSubjectConditionSetID            = errors.New("subject condition set reference missing id")
	ErrUnresolvedActionDependency              = errors.New("action dependency not resolved in target namespace")
	ErrUnresolvedSubjectConditionSetDependency = errors.New("subject condition set dependency not resolved in target namespace")
)

type UnresolvedReason string

const (
	UnresolvedReasonRegisteredResourceConflictingNamespaces UnresolvedReason = "registered_resource_conflicting_namespaces"
)

type Unresolved struct {
	Reason  UnresolvedReason
	Message string
}

type Plan struct {
	Scopes               []Scope                    `json:"scopes"`
	Namespaces           []*NamespacePlan           `json:"namespaces"`
	Actions              []*ActionPlan              `json:"actions"`
	SubjectConditionSets []*SubjectConditionSetPlan `json:"subject_condition_sets"`
	SubjectMappings      []*SubjectMappingPlan      `json:"subject_mappings"`
	RegisteredResources  []*RegisteredResourcePlan  `json:"registered_resources"`
	ObligationTriggers   []*ObligationTriggerPlan   `json:"obligation_triggers"`
}

type NamespacePlan struct {
	Namespace            *policy.Namespace `json:"namespace"`
	Actions              []string          `json:"actions,omitempty"`
	SubjectConditionSets []string          `json:"subject_condition_sets,omitempty"`
	SubjectMappings      []string          `json:"subject_mappings,omitempty"`
	RegisteredResources  []string          `json:"registered_resources,omitempty"`
	ObligationTriggers   []string          `json:"obligation_triggers,omitempty"`
}

type TargetStatus string

const (
	TargetStatusCreate           TargetStatus = "create"
	TargetStatusAlreadyMigrated  TargetStatus = "already_migrated"
	TargetStatusExistingStandard TargetStatus = "existing_standard"
	TargetStatusSkipped          TargetStatus = "skipped"
	TargetStatusUnresolved       TargetStatus = "unresolved"
)

type ExecutionResult struct {
	RunID           string `json:"run_id,omitempty"`
	Applied         bool   `json:"applied,omitempty"`
	CreatedTargetID string `json:"created_target_id,omitempty"`
	Failure         string `json:"failure,omitempty"`
}

type ActionPlan struct {
	Source  *policy.Action      `json:"source"`
	Targets []*ActionTargetPlan `json:"targets,omitempty"`
}

type ActionTargetPlan struct {
	Namespace  *policy.Namespace `json:"namespace"`
	Status     TargetStatus      `json:"status"`
	ExistingID string            `json:"existing_id,omitempty"`
	Execution  *ExecutionResult  `json:"execution,omitempty"`
	Reason     string            `json:"reason,omitempty"`
}

type SubjectConditionSetPlan struct {
	Source  *policy.SubjectConditionSet      `json:"source"`
	Targets []*SubjectConditionSetTargetPlan `json:"targets,omitempty"`
}

type SubjectConditionSetTargetPlan struct {
	Namespace  *policy.Namespace `json:"namespace"`
	Status     TargetStatus      `json:"status"`
	ExistingID string            `json:"existing_id,omitempty"`
	Execution  *ExecutionResult  `json:"execution,omitempty"`
	Reason     string            `json:"reason,omitempty"`
}

type SubjectMappingPlan struct {
	Source *policy.SubjectMapping    `json:"source"`
	Target *SubjectMappingTargetPlan `json:"target,omitempty"`
}

type SubjectMappingTargetPlan struct {
	Namespace                   *policy.Namespace `json:"namespace"`
	Status                      TargetStatus      `json:"status"`
	ExistingID                  string            `json:"existing_id,omitempty"`
	Execution                   *ExecutionResult  `json:"execution,omitempty"`
	Reason                      string            `json:"reason,omitempty"`
	ActionSourceIDs             []string          `json:"action_source_ids,omitempty"`
	SubjectConditionSetSourceID string            `json:"subject_condition_set_source_id,omitempty"`
}

type RegisteredResourcePlan struct {
	Source     *policy.RegisteredResource    `json:"source"`
	Target     *RegisteredResourceTargetPlan `json:"target,omitempty"`
	Unresolved string                        `json:"unresolved,omitempty"`
}

type RegisteredResourceTargetPlan struct {
	Namespace  *policy.Namespace              `json:"namespace"`
	Status     TargetStatus                   `json:"status"`
	ExistingID string                         `json:"existing_id,omitempty"`
	Execution  *ExecutionResult               `json:"execution,omitempty"`
	Reason     string                         `json:"reason,omitempty"`
	Values     []*RegisteredResourceValuePlan `json:"values,omitempty"`
}

type RegisteredResourceValuePlan struct {
	Source         *policy.RegisteredResourceValue    `json:"source"`
	ActionBindings []*RegisteredResourceActionBinding `json:"action_bindings,omitempty"`
	Execution      *ExecutionResult                   `json:"execution,omitempty"`
}

type RegisteredResourceActionBinding struct {
	SourceActionID string        `json:"source_action_id"`
	AttributeValue *policy.Value `json:"attribute_value,omitempty"`
}

type ObligationTriggerPlan struct {
	Source *policy.ObligationTrigger    `json:"source"`
	Target *ObligationTriggerTargetPlan `json:"target,omitempty"`
}

type ObligationTriggerTargetPlan struct {
	Namespace      *policy.Namespace `json:"namespace"`
	Status         TargetStatus      `json:"status"`
	ExistingID     string            `json:"existing_id,omitempty"`
	Execution      *ExecutionResult  `json:"execution,omitempty"`
	Reason         string            `json:"reason,omitempty"`
	ActionSourceID string            `json:"action_source_id,omitempty"`
}

func namespaceFromAttributeValue(value *policy.Value) *policy.Namespace {
	if value == nil {
		return nil
	}

	if namespace := value.GetAttribute().GetNamespace(); namespaceRefKey(namespace) != "" {
		return namespace
	}

	parsed, err := identifier.Parse[*identifier.FullyQualifiedAttribute](strings.TrimSpace(value.GetFqn()))
	if err != nil || parsed == nil || parsed.Namespace == "" {
		return nil
	}

	return &policy.Namespace{
		Fqn: (&identifier.FullyQualifiedAttribute{Namespace: parsed.Namespace}).FQN(),
	}
}

func namespaceFromObligationValue(value *policy.ObligationValue) *policy.Namespace {
	if value == nil {
		return nil
	}
	return value.GetObligation().GetNamespace()
}

func hasRegisteredResourceActionAttributeValues(resource *policy.RegisteredResource) bool {
	if resource == nil {
		return false
	}

	for _, value := range resource.GetValues() {
		if len(value.GetActionAttributeValues()) > 0 {
			return true
		}
	}

	return false
}

func hasObject[T interface{ GetId() string }](items []T, id string) bool {
	for _, item := range items {
		if item.GetId() == id {
			return true
		}
	}
	return false
}

// sameNamespace reports whether two namespace references identify the same
// namespace. IDs are compared with whitespace trimmed; FQNs are compared
// case-insensitively with whitespace trimmed. Two nil namespaces are
// considered equal (both represent legacy/global).
//
// NOTE: namespaceRefKey uses raw values without normalization for accumulator
// dedup keys. If normalization bugs surface there, consider unifying with
// this function's normalization logic.
func sameNamespace(left, right *policy.Namespace) bool {
	if left == nil || right == nil {
		return left == right
	}

	leftID := strings.TrimSpace(left.GetId())
	rightID := strings.TrimSpace(right.GetId())
	if leftID != "" && rightID != "" {
		return leftID == rightID
	}

	leftFQN := strings.ToLower(strings.TrimSpace(left.GetFqn()))
	rightFQN := strings.ToLower(strings.TrimSpace(right.GetFqn()))
	if leftFQN != "" && rightFQN != "" {
		return leftFQN == rightFQN
	}

	return false
}

func (t *ActionTargetPlan) TargetID() string {
	if t == nil {
		return ""
	}
	if t.Execution != nil && t.Execution.CreatedTargetID != "" {
		return t.Execution.CreatedTargetID
	}
	return t.ExistingID
}

func (t *SubjectConditionSetTargetPlan) TargetID() string {
	if t == nil {
		return ""
	}
	if t.Execution != nil && t.Execution.CreatedTargetID != "" {
		return t.Execution.CreatedTargetID
	}
	return t.ExistingID
}

func (t *SubjectMappingTargetPlan) TargetID() string {
	if t == nil {
		return ""
	}
	if t.Execution != nil && t.Execution.CreatedTargetID != "" {
		return t.Execution.CreatedTargetID
	}
	return t.ExistingID
}

func (t *RegisteredResourceTargetPlan) TargetID() string {
	if t == nil {
		return ""
	}
	if t.Execution != nil && t.Execution.CreatedTargetID != "" {
		return t.Execution.CreatedTargetID
	}
	return t.ExistingID
}

func (p *RegisteredResourceValuePlan) TargetID() string {
	if p == nil || p.Execution == nil {
		return ""
	}
	return p.Execution.CreatedTargetID
}

func (t *ObligationTriggerTargetPlan) TargetID() string {
	if t == nil {
		return ""
	}
	if t.Execution != nil && t.Execution.CreatedTargetID != "" {
		return t.Execution.CreatedTargetID
	}
	return t.ExistingID
}

func (p *Plan) LookupActionTarget(sourceID, namespaceID string) *ActionTargetPlan {
	if p == nil || sourceID == "" || namespaceID == "" {
		return nil
	}

	for _, action := range p.Actions {
		if action == nil || action.Source == nil || action.Source.GetId() != sourceID {
			continue
		}
		for _, target := range action.Targets {
			if target != nil && target.Namespace != nil && target.Namespace.GetId() == namespaceID {
				return target
			}
		}
	}

	return nil
}

func (p *Plan) LookupSubjectConditionSetTarget(sourceID, namespaceID string) *SubjectConditionSetTargetPlan {
	if p == nil || sourceID == "" || namespaceID == "" {
		return nil
	}

	for _, scs := range p.SubjectConditionSets {
		if scs == nil || scs.Source == nil || scs.Source.GetId() != sourceID {
			continue
		}
		for _, target := range scs.Targets {
			if target != nil && target.Namespace != nil && target.Namespace.GetId() == namespaceID {
				return target
			}
		}
	}

	return nil
}
