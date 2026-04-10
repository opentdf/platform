package namespacedpolicy

import (
	"errors"
	"sort"
	"strings"

	identifier "github.com/opentdf/platform/lib/identifier"
	"github.com/opentdf/platform/protocol/go/policy"
)

var (
	ErrNilRetrieved              = errors.New("planner retrieved state is required")
	ErrMissingTargetNamespace    = errors.New("missing target namespace")
	ErrUndeterminedTargetMapping = errors.New("could not determine target namespace")
)

const (
	errDuplicateCanonicalMatch = "multiple existing target objects match canonical equality in the target namespace"
)

type Plan struct {
	Scopes               []Scope                    `json:"scopes"`
	Namespaces           []*NamespacePlan           `json:"namespaces"`
	Actions              []*ActionPlan              `json:"actions"`
	SubjectConditionSets []*SubjectConditionSetPlan `json:"subject_condition_sets"`
	SubjectMappings      []*SubjectMappingPlan      `json:"subject_mappings"`
	RegisteredResources  []*RegisteredResourcePlan  `json:"registered_resources"`
	ObligationTriggers   []*ObligationTriggerPlan   `json:"obligation_triggers"`
	Unused               *UnusedPlan                `json:"unused,omitempty"`
	Unresolved           *UnresolvedPlan            `json:"unresolved,omitempty"`
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
	TargetStatusUnresolved       TargetStatus = "unresolved"
)

type ActionPlan struct {
	Source     *policy.Action      `json:"source"`
	References []*ActionReference  `json:"references,omitempty"`
	Targets    []*ActionTargetPlan `json:"targets,omitempty"`
	Unresolved string              `json:"unresolved,omitempty"`
}

type ActionReferenceKind string

const (
	ActionReferenceKindSubjectMapping     ActionReferenceKind = "subject_mapping"
	ActionReferenceKindRegisteredResource ActionReferenceKind = "registered_resource"
	ActionReferenceKindObligationTrigger  ActionReferenceKind = "obligation_trigger"
)

type ActionReference struct {
	Kind      ActionReferenceKind `json:"kind"`
	ID        string              `json:"id"`
	Namespace *policy.Namespace   `json:"namespace,omitempty"`
}

type ActionTargetPlan struct {
	Namespace *policy.Namespace `json:"namespace"`
	Status    TargetStatus      `json:"status"`
	Existing  *policy.Action    `json:"existing,omitempty"`
	Reason    string            `json:"reason,omitempty"`
}

type SubjectConditionSetPlan struct {
	Source     *policy.SubjectConditionSet      `json:"source"`
	Targets    []*SubjectConditionSetTargetPlan `json:"targets,omitempty"`
	Unresolved string                           `json:"unresolved,omitempty"`
}

type SubjectConditionSetTargetPlan struct {
	Namespace *policy.Namespace           `json:"namespace"`
	Status    TargetStatus                `json:"status"`
	Existing  *policy.SubjectConditionSet `json:"existing,omitempty"`
	Reason    string                      `json:"reason,omitempty"`
}

type SubjectMappingPlan struct {
	Source     *policy.SubjectMapping      `json:"source"`
	Targets    []*SubjectMappingTargetPlan `json:"targets,omitempty"`
	Unresolved string                      `json:"unresolved,omitempty"`
}

type SubjectMappingTargetPlan struct {
	Namespace           *policy.Namespace           `json:"namespace"`
	Status              TargetStatus                `json:"status"`
	Existing            *policy.SubjectMapping      `json:"existing,omitempty"`
	Reason              string                      `json:"reason,omitempty"`
	Actions             []*ActionBinding            `json:"actions,omitempty"`
	SubjectConditionSet *SubjectConditionSetBinding `json:"subject_condition_set,omitempty"`
}

type RegisteredResourcePlan struct {
	Source     *policy.RegisteredResource      `json:"source"`
	Targets    []*RegisteredResourceTargetPlan `json:"targets,omitempty"`
	Unresolved string                          `json:"unresolved,omitempty"`
}

type RegisteredResourceTargetPlan struct {
	Namespace *policy.Namespace              `json:"namespace"`
	Status    TargetStatus                   `json:"status"`
	Existing  *policy.RegisteredResource     `json:"existing,omitempty"`
	Reason    string                         `json:"reason,omitempty"`
	Values    []*RegisteredResourceValuePlan `json:"values,omitempty"`
}

type RegisteredResourceValuePlan struct {
	Source         *policy.RegisteredResourceValue    `json:"source"`
	ActionBindings []*RegisteredResourceActionBinding `json:"action_bindings,omitempty"`
}

type RegisteredResourceActionBinding struct {
	SourceActionID  string         `json:"source_action_id"`
	AttributeValue  *policy.Value  `json:"attribute_value,omitempty"`
	ActionTargetRef *ActionBinding `json:"action_target,omitempty"`
}

type ObligationTriggerPlan struct {
	Source     *policy.ObligationTrigger      `json:"source"`
	Targets    []*ObligationTriggerTargetPlan `json:"targets,omitempty"`
	Unresolved string                         `json:"unresolved,omitempty"`
}

type ObligationTriggerTargetPlan struct {
	Namespace *policy.Namespace         `json:"namespace"`
	Status    TargetStatus              `json:"status"`
	Existing  *policy.ObligationTrigger `json:"existing,omitempty"`
	Reason    string                    `json:"reason,omitempty"`
	Action    *ActionBinding            `json:"action,omitempty"`
}

type ActionBinding struct {
	SourceID  string            `json:"source_id"`
	Namespace *policy.Namespace `json:"namespace,omitempty"`
	Status    TargetStatus      `json:"status"`
	TargetID  string            `json:"target_id,omitempty"`
	Reason    string            `json:"reason,omitempty"`
}

type SubjectConditionSetBinding struct {
	SourceID  string            `json:"source_id"`
	Namespace *policy.Namespace `json:"namespace,omitempty"`
	Status    TargetStatus      `json:"status"`
	TargetID  string            `json:"target_id,omitempty"`
	Reason    string            `json:"reason,omitempty"`
}

type UnusedPlan struct {
	Actions []*UnusedAction `json:"actions,omitempty"`
}

type UnusedAction struct {
	Source     *policy.Action     `json:"source"`
	References []*ActionReference `json:"references,omitempty"`
	Reason     string             `json:"reason"`
}

type UnresolvedPlan struct {
	Actions              []*ActionIssue              `json:"actions,omitempty"`
	SubjectConditionSets []*SubjectConditionSetIssue `json:"subject_condition_sets,omitempty"`
	SubjectMappings      []*SubjectMappingIssue      `json:"subject_mappings,omitempty"`
	RegisteredResources  []*RegisteredResourceIssue  `json:"registered_resources,omitempty"`
	ObligationTriggers   []*ObligationTriggerIssue   `json:"obligation_triggers,omitempty"`
}

type ActionIssue struct {
	Source    *policy.Action    `json:"source"`
	Namespace *policy.Namespace `json:"namespace,omitempty"`
	Reason    string            `json:"reason"`
}

type SubjectConditionSetIssue struct {
	Source    *policy.SubjectConditionSet `json:"source"`
	Namespace *policy.Namespace           `json:"namespace,omitempty"`
	Reason    string                      `json:"reason"`
}

type SubjectMappingIssue struct {
	Source    *policy.SubjectMapping `json:"source"`
	Namespace *policy.Namespace      `json:"namespace,omitempty"`
	Reason    string                 `json:"reason"`
}

type RegisteredResourceIssue struct {
	Resource  *policy.RegisteredResource `json:"resource"`
	Namespace *policy.Namespace          `json:"namespace,omitempty"`
	Reason    string                     `json:"reason"`
}

type ObligationTriggerIssue struct {
	Source    *policy.ObligationTrigger `json:"source"`
	Namespace *policy.Namespace         `json:"namespace,omitempty"`
	Reason    string                    `json:"reason"`
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

func orderPlan(plan *Plan, namespaces []*policy.Namespace) *Plan {
	if plan == nil {
		return nil
	}

	namespacePositions := namespacePositionIndex(namespaces)

	orderActionPlans(plan.Actions, namespacePositions)
	orderSubjectConditionSetPlans(plan.SubjectConditionSets, namespacePositions)
	orderNamespacePlans(plan.Namespaces)
	orderUnusedPlan(plan.Unused)
	orderUnresolvedPlan(plan.Unresolved, namespacePositions)

	return plan
}

func orderActionPlans(actions []*ActionPlan, namespacePositions map[string]int) {
	for _, action := range actions {
		if action == nil {
			continue
		}
		orderActionReferences(action.References, namespacePositions)
		orderActionTargets(action.Targets, namespacePositions)
	}

	sort.SliceStable(actions, func(i, j int) bool {
		return actionPlanID(actions[i]) < actionPlanID(actions[j])
	})
}

func orderSubjectConditionSetPlans(sets []*SubjectConditionSetPlan, namespacePositions map[string]int) {
	for _, set := range sets {
		if set == nil {
			continue
		}
		orderSubjectConditionSetTargets(set.Targets, namespacePositions)
	}

	sort.SliceStable(sets, func(i, j int) bool {
		return subjectConditionSetPlanID(sets[i]) < subjectConditionSetPlanID(sets[j])
	})
}

func orderNamespacePlans(plans []*NamespacePlan) {
	for _, plan := range plans {
		if plan == nil {
			continue
		}
		sort.Strings(plan.Actions)
		sort.Strings(plan.SubjectConditionSets)
		sort.Strings(plan.SubjectMappings)
		sort.Strings(plan.RegisteredResources)
		sort.Strings(plan.ObligationTriggers)
	}
}

func orderUnusedPlan(plan *UnusedPlan) {
	if plan == nil {
		return
	}

	for _, action := range plan.Actions {
		if action == nil {
			continue
		}
		orderActionReferences(action.References, nil)
	}

	sort.SliceStable(plan.Actions, func(i, j int) bool {
		return unusedActionID(plan.Actions[i]) < unusedActionID(plan.Actions[j])
	})
}

func orderUnresolvedPlan(plan *UnresolvedPlan, namespacePositions map[string]int) {
	if plan == nil {
		return
	}

	sort.SliceStable(plan.Actions, func(i, j int) bool {
		return compareIssueOrder(actionIssueID(plan.Actions[i]), actionIssueNamespace(plan.Actions[i]), actionIssueReason(plan.Actions[i]), actionIssueID(plan.Actions[j]), actionIssueNamespace(plan.Actions[j]), actionIssueReason(plan.Actions[j]), namespacePositions)
	})
	sort.SliceStable(plan.SubjectConditionSets, func(i, j int) bool {
		return compareIssueOrder(subjectConditionSetIssueID(plan.SubjectConditionSets[i]), subjectConditionSetIssueNamespace(plan.SubjectConditionSets[i]), subjectConditionSetIssueReason(plan.SubjectConditionSets[i]), subjectConditionSetIssueID(plan.SubjectConditionSets[j]), subjectConditionSetIssueNamespace(plan.SubjectConditionSets[j]), subjectConditionSetIssueReason(plan.SubjectConditionSets[j]), namespacePositions)
	})
	sort.SliceStable(plan.SubjectMappings, func(i, j int) bool {
		return compareIssueOrder(subjectMappingIssueID(plan.SubjectMappings[i]), subjectMappingIssueNamespace(plan.SubjectMappings[i]), subjectMappingIssueReason(plan.SubjectMappings[i]), subjectMappingIssueID(plan.SubjectMappings[j]), subjectMappingIssueNamespace(plan.SubjectMappings[j]), subjectMappingIssueReason(plan.SubjectMappings[j]), namespacePositions)
	})
	sort.SliceStable(plan.RegisteredResources, func(i, j int) bool {
		return compareIssueOrder(registeredResourceIssueID(plan.RegisteredResources[i]), registeredResourceIssueNamespace(plan.RegisteredResources[i]), registeredResourceIssueReason(plan.RegisteredResources[i]), registeredResourceIssueID(plan.RegisteredResources[j]), registeredResourceIssueNamespace(plan.RegisteredResources[j]), registeredResourceIssueReason(plan.RegisteredResources[j]), namespacePositions)
	})
	sort.SliceStable(plan.ObligationTriggers, func(i, j int) bool {
		return compareIssueOrder(obligationTriggerIssueID(plan.ObligationTriggers[i]), obligationTriggerIssueNamespace(plan.ObligationTriggers[i]), obligationTriggerIssueReason(plan.ObligationTriggers[i]), obligationTriggerIssueID(plan.ObligationTriggers[j]), obligationTriggerIssueNamespace(plan.ObligationTriggers[j]), obligationTriggerIssueReason(plan.ObligationTriggers[j]), namespacePositions)
	})
}

func orderActionReferences(references []*ActionReference, namespacePositions map[string]int) {
	sort.SliceStable(references, func(i, j int) bool {
		left := references[i]
		right := references[j]
		if left == nil {
			return false
		}
		if right == nil {
			return true
		}
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		if left.ID != right.ID {
			return left.ID < right.ID
		}
		return compareNamespaceOrder(left.Namespace, right.Namespace, namespacePositions)
	})
}

func orderActionTargets(targets []*ActionTargetPlan, namespacePositions map[string]int) {
	sort.SliceStable(targets, func(i, j int) bool {
		return compareNamespaceOrder(actionTargetNamespace(targets[i]), actionTargetNamespace(targets[j]), namespacePositions)
	})
}

func orderSubjectConditionSetTargets(targets []*SubjectConditionSetTargetPlan, namespacePositions map[string]int) {
	sort.SliceStable(targets, func(i, j int) bool {
		return compareNamespaceOrder(subjectConditionSetTargetNamespace(targets[i]), subjectConditionSetTargetNamespace(targets[j]), namespacePositions)
	})
}

func namespacePositionIndex(namespaces []*policy.Namespace) map[string]int {
	positions := make(map[string]int, len(namespaces))
	for index, namespace := range namespaces {
		if namespace == nil || namespace.GetId() == "" {
			continue
		}
		positions[namespace.GetId()] = index
	}
	return positions
}

func compareIssueOrder(leftID string, leftNamespace *policy.Namespace, leftReason string, rightID string, rightNamespace *policy.Namespace, rightReason string, namespacePositions map[string]int) bool {
	if leftID != rightID {
		return leftID < rightID
	}
	if compareNamespaceOrder(leftNamespace, rightNamespace, namespacePositions) {
		return true
	}
	if compareNamespaceOrder(rightNamespace, leftNamespace, namespacePositions) {
		return false
	}
	return leftReason < rightReason
}

func compareNamespaceOrder(left, right *policy.Namespace, namespacePositions map[string]int) bool {
	leftPos, leftFound := namespacePosition(namespacePositions, left)
	rightPos, rightFound := namespacePosition(namespacePositions, right)
	if leftFound && rightFound && leftPos != rightPos {
		return leftPos < rightPos
	}
	if leftFound != rightFound {
		return leftFound
	}
	return namespaceRefKey(left) < namespaceRefKey(right)
}

func namespacePosition(positions map[string]int, namespace *policy.Namespace) (int, bool) {
	if namespace == nil {
		return 0, false
	}
	position, ok := positions[namespace.GetId()]
	return position, ok
}

func actionPlanID(action *ActionPlan) string {
	if action == nil || action.Source == nil {
		return ""
	}
	return action.Source.GetId()
}

func subjectConditionSetPlanID(set *SubjectConditionSetPlan) string {
	if set == nil || set.Source == nil {
		return ""
	}
	return set.Source.GetId()
}

func unusedActionID(action *UnusedAction) string {
	if action == nil || action.Source == nil {
		return ""
	}
	return action.Source.GetId()
}

func actionIssueID(issue *ActionIssue) string {
	if issue == nil || issue.Source == nil {
		return ""
	}
	return issue.Source.GetId()
}

func actionIssueNamespace(issue *ActionIssue) *policy.Namespace {
	if issue == nil {
		return nil
	}
	return issue.Namespace
}

func actionIssueReason(issue *ActionIssue) string {
	if issue == nil {
		return ""
	}
	return issue.Reason
}

func subjectConditionSetIssueID(issue *SubjectConditionSetIssue) string {
	if issue == nil || issue.Source == nil {
		return ""
	}
	return issue.Source.GetId()
}

func subjectConditionSetIssueNamespace(issue *SubjectConditionSetIssue) *policy.Namespace {
	if issue == nil {
		return nil
	}
	return issue.Namespace
}

func subjectConditionSetIssueReason(issue *SubjectConditionSetIssue) string {
	if issue == nil {
		return ""
	}
	return issue.Reason
}

func subjectMappingIssueID(issue *SubjectMappingIssue) string {
	if issue == nil || issue.Source == nil {
		return ""
	}
	return issue.Source.GetId()
}

func subjectMappingIssueNamespace(issue *SubjectMappingIssue) *policy.Namespace {
	if issue == nil {
		return nil
	}
	return issue.Namespace
}

func subjectMappingIssueReason(issue *SubjectMappingIssue) string {
	if issue == nil {
		return ""
	}
	return issue.Reason
}

func registeredResourceIssueID(issue *RegisteredResourceIssue) string {
	if issue == nil || issue.Resource == nil {
		return ""
	}
	return issue.Resource.GetId()
}

func registeredResourceIssueNamespace(issue *RegisteredResourceIssue) *policy.Namespace {
	if issue == nil {
		return nil
	}
	return issue.Namespace
}

func registeredResourceIssueReason(issue *RegisteredResourceIssue) string {
	if issue == nil {
		return ""
	}
	return issue.Reason
}

func obligationTriggerIssueID(issue *ObligationTriggerIssue) string {
	if issue == nil || issue.Source == nil {
		return ""
	}
	return issue.Source.GetId()
}

func obligationTriggerIssueNamespace(issue *ObligationTriggerIssue) *policy.Namespace {
	if issue == nil {
		return nil
	}
	return issue.Namespace
}

func obligationTriggerIssueReason(issue *ObligationTriggerIssue) string {
	if issue == nil {
		return ""
	}
	return issue.Reason
}

func actionTargetNamespace(target *ActionTargetPlan) *policy.Namespace {
	if target == nil {
		return nil
	}
	return target.Namespace
}

func subjectConditionSetTargetNamespace(target *SubjectConditionSetTargetPlan) *policy.Namespace {
	if target == nil {
		return nil
	}
	return target.Namespace
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

func hasUnresolved(plan UnresolvedPlan) bool {
	return len(plan.Actions) > 0 ||
		len(plan.SubjectConditionSets) > 0 ||
		len(plan.SubjectMappings) > 0 ||
		len(plan.RegisteredResources) > 0 ||
		len(plan.ObligationTriggers) > 0
}

func hasUnused(plan UnusedPlan) bool {
	return len(plan.Actions) > 0
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
	if t == nil || t.Existing == nil {
		return ""
	}
	return t.Existing.GetId()
}

func (t *SubjectConditionSetTargetPlan) TargetID() string {
	if t == nil || t.Existing == nil {
		return ""
	}
	return t.Existing.GetId()
}

func (t *SubjectMappingTargetPlan) TargetID() string {
	if t == nil || t.Existing == nil {
		return ""
	}
	return t.Existing.GetId()
}

func (t *RegisteredResourceTargetPlan) TargetID() string {
	if t == nil || t.Existing == nil {
		return ""
	}
	return t.Existing.GetId()
}

func (t *ObligationTriggerTargetPlan) TargetID() string {
	if t == nil || t.Existing == nil {
		return ""
	}
	return t.Existing.GetId()
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
