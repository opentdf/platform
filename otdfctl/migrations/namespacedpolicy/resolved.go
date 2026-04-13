package namespacedpolicy

import (
	"fmt"
	"strings"

	"github.com/opentdf/platform/protocol/go/policy"
)

type ResolvedTargets struct {
	Scopes               []Scope
	Actions              []*ResolvedAction
	SubjectConditionSets []*ResolvedSubjectConditionSet
	SubjectMappings      []*ResolvedSubjectMapping
	RegisteredResources  []*ResolvedRegisteredResource
	ObligationTriggers   []*ResolvedObligationTrigger
}

type ResolvedAction struct {
	Source     *policy.Action
	References []*ActionReference
	Results    []*ResolvedActionResult
	Unresolved string
}

type ResolvedActionResult struct {
	Namespace        *policy.Namespace
	AlreadyMigrated  *policy.Action
	ExistingStandard *policy.Action
	NeedsCreate      bool
	Unresolved       string
}

type ResolvedSubjectConditionSet struct {
	Source     *policy.SubjectConditionSet
	Results    []*ResolvedSubjectConditionSetResult
	Unresolved string
}

type ResolvedSubjectConditionSetResult struct {
	Namespace       *policy.Namespace
	AlreadyMigrated *policy.SubjectConditionSet
	NeedsCreate     bool
	Unresolved      string
}

type ResolvedSubjectMapping struct {
	Source          *policy.SubjectMapping
	Namespace       *policy.Namespace
	AlreadyMigrated *policy.SubjectMapping
	NeedsCreate     bool
	Unresolved      string
}

type ResolvedRegisteredResource struct {
	Source          *policy.RegisteredResource
	Namespace       *policy.Namespace
	AlreadyMigrated *policy.RegisteredResource
	NeedsCreate     bool
	Unresolved      string
}

type ResolvedObligationTrigger struct {
	Source          *policy.ObligationTrigger
	Namespace       *policy.Namespace
	AlreadyMigrated *policy.ObligationTrigger
	NeedsCreate     bool
	Unresolved      string
}

type resolver struct {
	derived            *DerivedTargets
	existing           *ExistingTargets
	actionResultsByKey map[string]*ResolvedActionResult
	scsResultsByKey    map[string]*ResolvedSubjectConditionSetResult
}

// resolveExisting classifies each derived source/target placement as already
// migrated, satisfied by an existing target object, needing creation, or still
// unresolved. This is the phase that ties the derived namespace targets to live
// target-side state before the final per-namespace plan is built.
func resolveExisting(derived *DerivedTargets, existing *ExistingTargets) *ResolvedTargets {
	if existing == nil {
		existing = newExistingTargets()
	}

	r := &resolver{
		derived:            derived,
		existing:           existing,
		actionResultsByKey: make(map[string]*ResolvedActionResult),
		scsResultsByKey:    make(map[string]*ResolvedSubjectConditionSetResult),
	}

	return &ResolvedTargets{
		Scopes:               append([]Scope(nil), derived.Scopes...),
		Actions:              r.resolveActions(),
		SubjectConditionSets: r.resolveSubjectConditionSets(),
		SubjectMappings:      r.resolveSubjectMappings(),
		RegisteredResources:  r.resolveRegisteredResources(),
		ObligationTriggers:   r.resolveObligationTriggers(),
	}
}

func (r *resolver) resolveActions() []*ResolvedAction {
	if r == nil || r.derived == nil {
		return nil
	}

	resolved := make([]*ResolvedAction, 0, len(r.derived.Actions))
	for _, action := range r.derived.Actions {
		resolved = append(resolved, r.resolveAction(action))
	}
	return resolved
}

func (r *resolver) resolveAction(derived *DerivedAction) *ResolvedAction {
	item := &ResolvedAction{}
	if derived == nil {
		return item
	}

	item.Source = derived.Source
	item.References = append([]*ActionReference(nil), derived.References...)
	item.Unresolved = derived.Unresolved
	item.Results = make([]*ResolvedActionResult, 0, len(derived.Targets))
	for _, namespace := range derived.Targets {
		result := r.resolveActionTarget(derived, namespace)
		item.Results = append(item.Results, result)
		if derived.Source != nil {
			r.addActionResult(derived.Source.GetId(), result)
		}
	}

	return item
}

func (r *resolver) resolveActionTarget(derived *DerivedAction, namespace *policy.Namespace) *ResolvedActionResult {
	result := &ResolvedActionResult{Namespace: namespace}
	if derived == nil || derived.Source == nil {
		result.Unresolved = fmt.Errorf("%w: empty action candidate", ErrUndeterminedTargetMapping).Error()
		return result
	}
	if namespace == nil {
		result.Unresolved = fmt.Errorf("%w: empty namespace reference", ErrUndeterminedTargetMapping).Error()
		return result
	}
	return r.resolveActionTargetFromExisting(derived.Source, namespace)
}

func (r *resolver) resolveActionTargetFromExisting(source *policy.Action, namespace *policy.Namespace) *ResolvedActionResult {
	result := &ResolvedActionResult{Namespace: namespace}
	if r.isStandardAction(source) {
		return r.resolveStandardActionTarget(source, namespace)
	}

	existing, reason := resolveExistingAction(source, r.existing.CustomActions[namespace.GetId()])
	switch {
	case existing != nil:
		result.AlreadyMigrated = existing
		return result
	case reason != "":
		result.Unresolved = reason
		return result
	}

	result.NeedsCreate = true
	return result
}

func (r *resolver) resolveStandardActionTarget(source *policy.Action, namespace *policy.Namespace) *ResolvedActionResult {
	result := &ResolvedActionResult{Namespace: namespace}
	if namespace == nil || namespace.GetId() == "" {
		result.Unresolved = fmt.Errorf("%w: empty namespace reference", ErrUndeterminedTargetMapping).Error()
		return result
	}

	matches := make([]*policy.Action, 0, 1)
	for _, action := range r.existing.StandardActions[namespace.GetId()] {
		if !actionCanonicalEqual(source, action) {
			continue
		}
		matches = append(matches, action)
	}

	switch len(matches) {
	case 1:
		result.ExistingStandard = matches[0]
	case 0:
		result.Unresolved = "matching standard action not found in target namespace"
	default:
		result.Unresolved = "multiple standard actions match in target namespace"
	}

	return result
}

func (r *resolver) isStandardAction(action *policy.Action) bool {
	if r == nil || action == nil {
		return false
	}

	if action.GetStandard() != policy.Action_STANDARD_ACTION_UNSPECIFIED {
		return true
	}

	switch strings.ToLower(strings.TrimSpace(action.GetName())) {
	case "create", "read", "update", "delete":
		return true
	default:
		return false
	}
}

func (r *resolver) resolveSubjectConditionSets() []*ResolvedSubjectConditionSet {
	if r == nil || r.derived == nil {
		return nil
	}

	resolved := make([]*ResolvedSubjectConditionSet, 0, len(r.derived.SubjectConditionSets))
	for _, scs := range r.derived.SubjectConditionSets {
		resolved = append(resolved, r.resolveSubjectConditionSet(scs))
	}
	return resolved
}

func (r *resolver) resolveSubjectConditionSet(derived *DerivedSubjectConditionSet) *ResolvedSubjectConditionSet {
	item := &ResolvedSubjectConditionSet{}
	if derived == nil {
		return item
	}

	item.Source = derived.Source
	item.Unresolved = derived.Unresolved
	item.Results = make([]*ResolvedSubjectConditionSetResult, 0, len(derived.Targets))
	for _, namespace := range derived.Targets {
		result := r.resolveSubjectConditionSetTarget(derived, namespace)
		item.Results = append(item.Results, result)
		if derived.Source != nil {
			r.addSubjectConditionSetResult(derived.Source.GetId(), result)
		}
	}

	return item
}

func (r *resolver) resolveSubjectConditionSetTarget(derived *DerivedSubjectConditionSet, namespace *policy.Namespace) *ResolvedSubjectConditionSetResult {
	result := &ResolvedSubjectConditionSetResult{Namespace: namespace}
	if derived == nil || derived.Source == nil {
		result.Unresolved = fmt.Errorf("%w: empty subject condition set candidate", ErrUndeterminedTargetMapping).Error()
		return result
	}
	if namespace == nil {
		result.Unresolved = fmt.Errorf("%w: empty namespace reference", ErrUndeterminedTargetMapping).Error()
		return result
	}
	existing, reason := resolveExistingSubjectConditionSet(derived.Source, r.existing.SubjectConditionSets[namespace.GetId()])
	switch {
	case existing != nil:
		result.AlreadyMigrated = existing
	case reason != "":
		result.Unresolved = reason
	default:
		result.NeedsCreate = true
	}

	return result
}

func (r *resolver) resolveSubjectMappings() []*ResolvedSubjectMapping {
	if r == nil || r.derived == nil {
		return nil
	}

	resolved := make([]*ResolvedSubjectMapping, 0, len(r.derived.SubjectMappings))
	for _, mapping := range r.derived.SubjectMappings {
		resolved = append(resolved, r.resolveSubjectMapping(mapping))
	}
	return resolved
}

func (r *resolver) resolveSubjectMapping(derived *DerivedSubjectMapping) *ResolvedSubjectMapping {
	item := &ResolvedSubjectMapping{}
	if derived == nil {
		return item
	}

	item.Source = derived.Source
	item.Namespace = derived.Target
	item.Unresolved = derived.Unresolved

	if item.Unresolved != "" {
		return item
	}
	if item.Source == nil {
		item.Unresolved = fmt.Errorf("%w: empty subject mapping candidate", ErrUndeterminedTargetMapping).Error()
		return item
	}
	if item.Namespace == nil {
		item.Unresolved = fmt.Errorf("%w: empty namespace reference", ErrUndeterminedTargetMapping).Error()
		return item
	}
	// Subject mappings are only safe to resolve once their action and subject
	// condition set dependencies are themselves resolvable in the same target
	// namespace. This keeps the plan graph internally consistent.
	if reason := r.resolveSubjectMappingDependencies(item.Source, item.Namespace); reason != "" {
		item.Unresolved = reason
		return item
	}

	existing, reason := resolveExistingSubjectMapping(item.Source, r.existing.SubjectMappings[item.Namespace.GetId()])
	switch {
	case existing != nil:
		item.AlreadyMigrated = existing
	case reason != "":
		item.Unresolved = reason
	default:
		item.NeedsCreate = true
	}

	return item
}

func (r *resolver) resolveRegisteredResources() []*ResolvedRegisteredResource {
	if r == nil || r.derived == nil {
		return nil
	}

	resolved := make([]*ResolvedRegisteredResource, 0, len(r.derived.RegisteredResources))
	for _, resource := range r.derived.RegisteredResources {
		resolved = append(resolved, r.resolveRegisteredResource(resource))
	}
	return resolved
}

func (r *resolver) resolveRegisteredResource(derived *DerivedRegisteredResource) *ResolvedRegisteredResource {
	item := &ResolvedRegisteredResource{}
	if derived == nil {
		return item
	}

	item.Source = derived.Source
	item.Namespace = derived.Target
	item.Unresolved = derived.Unresolved

	if item.Unresolved != "" {
		return item
	}
	if item.Source == nil {
		item.Unresolved = fmt.Errorf("%w: registered resource is empty", ErrUndeterminedTargetMapping).Error()
		return item
	}
	if item.Namespace == nil {
		item.Unresolved = fmt.Errorf("%w: empty namespace reference", ErrUndeterminedTargetMapping).Error()
		return item
	}
	existing, reason := resolveExistingRegisteredResource(item.Source, r.existing.RegisteredResources[item.Namespace.GetId()])
	switch {
	case existing != nil:
		item.AlreadyMigrated = existing
	case reason != "":
		item.Unresolved = reason
	default:
		item.NeedsCreate = true
	}

	return item
}

func (r *resolver) resolveObligationTriggers() []*ResolvedObligationTrigger {
	if r == nil || r.derived == nil {
		return nil
	}

	resolved := make([]*ResolvedObligationTrigger, 0, len(r.derived.ObligationTriggers))
	for _, trigger := range r.derived.ObligationTriggers {
		resolved = append(resolved, r.resolveObligationTrigger(trigger))
	}
	return resolved
}

func (r *resolver) resolveObligationTrigger(derived *DerivedObligationTrigger) *ResolvedObligationTrigger {
	item := &ResolvedObligationTrigger{}
	if derived == nil {
		return item
	}

	item.Source = derived.Source
	item.Namespace = derived.Target
	item.Unresolved = derived.Unresolved

	if item.Unresolved != "" {
		return item
	}
	if item.Source == nil {
		item.Unresolved = fmt.Errorf("%w: empty obligation trigger candidate", ErrUndeterminedTargetMapping).Error()
		return item
	}
	if item.Namespace == nil {
		item.Unresolved = fmt.Errorf("%w: empty namespace reference", ErrUndeterminedTargetMapping).Error()
		return item
	}
	existing, reason := resolveExistingObligationTrigger(item.Source, r.existing.ObligationTriggers[item.Namespace.GetId()])
	switch {
	case existing != nil:
		item.AlreadyMigrated = existing
	case reason != "":
		item.Unresolved = reason
	default:
		item.NeedsCreate = true
	}

	return item
}

func (r *resolver) addActionResult(sourceID string, result *ResolvedActionResult) {
	if sourceID == "" || result == nil || result.Namespace == nil || result.Namespace.GetId() == "" {
		return
	}
	r.actionResultsByKey[resolvedResultKey(sourceID, result.Namespace.GetId())] = result
}

func (r *resolver) addSubjectConditionSetResult(sourceID string, result *ResolvedSubjectConditionSetResult) {
	if sourceID == "" || result == nil || result.Namespace == nil || result.Namespace.GetId() == "" {
		return
	}
	r.scsResultsByKey[resolvedResultKey(sourceID, result.Namespace.GetId())] = result
}

func (r *resolver) resolveSubjectMappingDependencies(mapping *policy.SubjectMapping, namespace *policy.Namespace) string {
	for _, action := range mapping.GetActions() {
		actionID := action.GetId()
		if actionID == "" {
			return "subject mapping references an action without an id"
		}

		result := r.actionResultsByKey[resolvedResultKey(actionID, namespace.GetId())]
		if result == nil {
			return fmt.Sprintf("subject mapping dependency action %q is not resolved in namespace %q", actionID, namespace.GetId())
		}
		if !resolvedActionResultSatisfied(result) {
			if result.Unresolved != "" {
				return fmt.Sprintf("subject mapping dependency action %q is unresolved: %s", actionID, result.Unresolved)
			}
			return fmt.Sprintf("subject mapping dependency action %q is not satisfiable in namespace %q", actionID, namespace.GetId())
		}
	}

	scsID := mapping.GetSubjectConditionSet().GetId()
	if scsID == "" {
		return "subject mapping references a subject condition set without an id"
	}

	result := r.scsResultsByKey[resolvedResultKey(scsID, namespace.GetId())]
	if result == nil {
		return fmt.Sprintf("subject mapping dependency subject condition set %q is not resolved in namespace %q", scsID, namespace.GetId())
	}
	if !resolvedSubjectConditionSetResultSatisfied(result) {
		if result.Unresolved != "" {
			return fmt.Sprintf("subject mapping dependency subject condition set %q is unresolved: %s", scsID, result.Unresolved)
		}
		return fmt.Sprintf("subject mapping dependency subject condition set %q is not satisfiable in namespace %q", scsID, namespace.GetId())
	}

	return ""
}

func resolveExistingAction(source *policy.Action, existing []*policy.Action) (*policy.Action, string) {
	if source == nil {
		return nil, fmt.Errorf("%w: empty action candidate", ErrUndeterminedTargetMapping).Error()
	}

	matches := make([]*policy.Action, 0, 1)
	for _, action := range existing {
		if actionCanonicalEqual(source, action) {
			matches = append(matches, action)
		}
	}

	switch len(matches) {
	case 1:
		return matches[0], ""
	case 0:
		return nil, ""
	default:
		return nil, errDuplicateCanonicalMatch
	}
}

func resolveExistingSubjectConditionSet(source *policy.SubjectConditionSet, existing []*policy.SubjectConditionSet) (*policy.SubjectConditionSet, string) {
	if source == nil {
		return nil, fmt.Errorf("%w: empty subject condition set candidate", ErrUndeterminedTargetMapping).Error()
	}

	matches := make([]*policy.SubjectConditionSet, 0, 1)
	for _, scs := range existing {
		if subjectConditionSetCanonicalEqual(source, scs) {
			matches = append(matches, scs)
		}
	}

	switch len(matches) {
	case 1:
		return matches[0], ""
	case 0:
		return nil, ""
	default:
		return nil, errDuplicateCanonicalMatch
	}
}

func resolveExistingSubjectMapping(source *policy.SubjectMapping, existing []*policy.SubjectMapping) (*policy.SubjectMapping, string) {
	if source == nil {
		return nil, fmt.Errorf("%w: empty subject mapping candidate", ErrUndeterminedTargetMapping).Error()
	}

	matches := make([]*policy.SubjectMapping, 0, 1)
	for _, mapping := range existing {
		if subjectMappingCanonicalEqual(source, mapping) {
			matches = append(matches, mapping)
		}
	}

	switch len(matches) {
	case 1:
		return matches[0], ""
	case 0:
		return nil, ""
	default:
		return nil, errDuplicateCanonicalMatch
	}
}

func resolveExistingRegisteredResource(source *policy.RegisteredResource, existing []*policy.RegisteredResource) (*policy.RegisteredResource, string) {
	if source == nil {
		return nil, fmt.Errorf("%w: registered resource is empty", ErrUndeterminedTargetMapping).Error()
	}

	matches := make([]*policy.RegisteredResource, 0, 1)
	for _, resource := range existing {
		if registeredResourceCanonicalEqual(source, resource) {
			matches = append(matches, resource)
		}
	}

	switch len(matches) {
	case 1:
		return matches[0], ""
	case 0:
		return nil, ""
	default:
		return nil, errDuplicateCanonicalMatch
	}
}

func resolveExistingObligationTrigger(source *policy.ObligationTrigger, existing []*policy.ObligationTrigger) (*policy.ObligationTrigger, string) {
	if source == nil {
		return nil, fmt.Errorf("%w: empty obligation trigger candidate", ErrUndeterminedTargetMapping).Error()
	}

	matches := make([]*policy.ObligationTrigger, 0, 1)
	for _, trigger := range existing {
		if obligationTriggerCanonicalEqual(source, trigger) {
			matches = append(matches, trigger)
		}
	}

	switch len(matches) {
	case 1:
		return matches[0], ""
	case 0:
		return nil, ""
	default:
		return nil, errDuplicateCanonicalMatch
	}
}

func resolvedResultKey(sourceID, namespaceID string) string {
	return sourceID + "|" + namespaceID
}

func resolvedActionResultSatisfied(result *ResolvedActionResult) bool {
	if result == nil || result.Unresolved != "" {
		return false
	}
	return result.AlreadyMigrated != nil || result.ExistingStandard != nil || result.NeedsCreate
}

func resolvedSubjectConditionSetResultSatisfied(result *ResolvedSubjectConditionSetResult) bool {
	if result == nil || result.Unresolved != "" {
		return false
	}
	return result.AlreadyMigrated != nil || result.NeedsCreate
}
