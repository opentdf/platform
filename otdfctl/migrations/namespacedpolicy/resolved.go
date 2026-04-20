package namespacedpolicy

import (
	"errors"
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
}

type ResolvedActionResult struct {
	Namespace        *policy.Namespace
	AlreadyMigrated  *policy.Action
	ExistingStandard *policy.Action
	NeedsCreate      bool
}

type ResolvedSubjectConditionSet struct {
	Source  *policy.SubjectConditionSet
	Results []*ResolvedSubjectConditionSetResult
}

type ResolvedSubjectConditionSetResult struct {
	Namespace       *policy.Namespace
	AlreadyMigrated *policy.SubjectConditionSet
	NeedsCreate     bool
}

type ResolvedSubjectMapping struct {
	Source          *policy.SubjectMapping
	Namespace       *policy.Namespace
	AlreadyMigrated *policy.SubjectMapping
	NeedsCreate     bool
}

type ResolvedRegisteredResource struct {
	Source          *policy.RegisteredResource
	Namespace       *policy.Namespace
	AlreadyMigrated *policy.RegisteredResource
	NeedsCreate     bool
	Unresolved      *Unresolved
}

type ResolvedObligationTrigger struct {
	Source          *policy.ObligationTrigger
	Namespace       *policy.Namespace
	AlreadyMigrated *policy.ObligationTrigger
	NeedsCreate     bool
}

type resolver struct {
	derived            *DerivedTargets
	existing           *ExistingTargets
	scopes             scopeSet
	actionResultsByKey map[string]*ResolvedActionResult
	scsResultsByKey    map[string]*ResolvedSubjectConditionSetResult
}

// resolveExisting classifies each derived source/target placement as already
// migrated, satisfied by an existing target object, needing creation, or still
// unresolved. This is the phase that ties the derived namespace targets to live
// target-side state before the final per-namespace plan is built.
func resolveExisting(derived *DerivedTargets, existing *ExistingTargets) (*ResolvedTargets, error) {
	if existing == nil {
		existing = newExistingTargets()
	}

	r := &resolver{
		derived:            derived,
		existing:           existing,
		scopes:             scopesFromSlice(derived.Scopes),
		actionResultsByKey: make(map[string]*ResolvedActionResult),
		scsResultsByKey:    make(map[string]*ResolvedSubjectConditionSetResult),
	}

	resolvedActions, err := r.resolveActions()
	if err != nil {
		return nil, err
	}
	resolvedSubjectConditionSets, err := r.resolveSubjectConditionSets()
	if err != nil {
		return nil, err
	}
	resolvedSubjectMappings, err := r.resolveSubjectMappings()
	if err != nil {
		return nil, err
	}
	resolvedRegisteredResources, err := r.resolveRegisteredResources()
	if err != nil {
		return nil, err
	}
	resolvedObligationTriggers, err := r.resolveObligationTriggers()
	if err != nil {
		return nil, err
	}

	return &ResolvedTargets{
		Scopes:               append([]Scope(nil), derived.Scopes...),
		Actions:              resolvedActions,
		SubjectConditionSets: resolvedSubjectConditionSets,
		SubjectMappings:      resolvedSubjectMappings,
		RegisteredResources:  resolvedRegisteredResources,
		ObligationTriggers:   resolvedObligationTriggers,
	}, nil
}

func (r *resolver) resolveActions() ([]*ResolvedAction, error) {
	if r == nil || r.derived == nil {
		return nil, nil
	}

	resolved := make([]*ResolvedAction, 0, len(r.derived.Actions))
	for _, action := range r.derived.Actions {
		item, err := r.resolveAction(action)
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, item)
	}
	return resolved, nil
}

func (r *resolver) resolveAction(derived *DerivedAction) (*ResolvedAction, error) {
	if derived == nil || derived.Source == nil {
		return nil, fmt.Errorf("%w: empty action candidate", ErrUndeterminedTargetMapping)
	}

	item := &ResolvedAction{
		Source:     derived.Source,
		References: append([]*ActionReference(nil), derived.References...),
		Results:    make([]*ResolvedActionResult, 0, len(derived.Targets)),
	}
	for _, namespace := range derived.Targets {
		result, err := r.resolveActionTargetFromExisting(derived.Source, namespace)
		if err != nil {
			return nil, fmt.Errorf("action %q in namespace %q: %w", derived.Source.GetId(), namespace.GetId(), err)
		}
		item.Results = append(item.Results, result)
		r.addActionResult(derived.Source.GetId(), result)
	}

	return item, nil
}

func (r *resolver) resolveActionTargetFromExisting(source *policy.Action, namespace *policy.Namespace) (*ResolvedActionResult, error) {
	if namespace.GetId() == "" {
		return nil, fmt.Errorf("%w: empty namespace reference", ErrUndeterminedTargetMapping)
	}

	result := &ResolvedActionResult{Namespace: namespace}
	if r.isStandardAction(source) {
		return r.resolveStandardActionTarget(source, namespace)
	}

	existing, found, err := resolveExistingAction(source, r.existing.CustomActions[namespace.GetId()])
	switch {
	case found:
		result.AlreadyMigrated = existing
		return result, nil
	case err != nil:
		return nil, err
	}

	result.NeedsCreate = true
	return result, nil
}

func (r *resolver) resolveStandardActionTarget(source *policy.Action, namespace *policy.Namespace) (*ResolvedActionResult, error) {
	result := &ResolvedActionResult{Namespace: namespace}

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
		return nil, errors.New("matching standard action not found in target namespace")
	default:
		return nil, errors.New("multiple standard actions match in target namespace")
	}

	return result, nil
}

func (r *resolver) isStandardAction(action *policy.Action) bool {
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

func (r *resolver) resolveSubjectConditionSets() ([]*ResolvedSubjectConditionSet, error) {
	if r == nil || r.derived == nil {
		return nil, nil
	}

	resolved := make([]*ResolvedSubjectConditionSet, 0, len(r.derived.SubjectConditionSets))
	for _, scs := range r.derived.SubjectConditionSets {
		item, err := r.resolveSubjectConditionSet(scs)
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, item)
	}
	return resolved, nil
}

func (r *resolver) resolveSubjectConditionSet(derived *DerivedSubjectConditionSet) (*ResolvedSubjectConditionSet, error) {
	if derived == nil || derived.Source == nil {
		return nil, fmt.Errorf("%w: empty subject condition set candidate", ErrUndeterminedTargetMapping)
	}

	item := &ResolvedSubjectConditionSet{
		Source:  derived.Source,
		Results: make([]*ResolvedSubjectConditionSetResult, 0, len(derived.Targets)),
	}
	for _, namespace := range derived.Targets {
		result, err := r.resolveSubjectConditionSetTargetFromExisting(derived.Source, namespace)
		if err != nil {
			return nil, fmt.Errorf("subject condition set %q in namespace %q: %w", derived.Source.GetId(), namespace.GetId(), err)
		}
		item.Results = append(item.Results, result)
		r.addSubjectConditionSetResult(derived.Source.GetId(), result)
	}

	return item, nil
}

func (r *resolver) resolveSubjectConditionSetTargetFromExisting(source *policy.SubjectConditionSet, namespace *policy.Namespace) (*ResolvedSubjectConditionSetResult, error) {
	if namespace.GetId() == "" {
		return nil, fmt.Errorf("%w: empty namespace reference", ErrUndeterminedTargetMapping)
	}
	result := &ResolvedSubjectConditionSetResult{Namespace: namespace}
	existing, found, err := resolveExistingSubjectConditionSet(source, r.existing.SubjectConditionSets[namespace.GetId()])
	switch {
	case found:
		result.AlreadyMigrated = existing
	case err != nil:
		return nil, err
	default:
		result.NeedsCreate = true
	}

	return result, nil
}

func (r *resolver) resolveSubjectMappings() ([]*ResolvedSubjectMapping, error) {
	if r == nil || r.derived == nil || !r.scopes.has(ScopeSubjectMappings) {
		return nil, nil
	}

	resolved := make([]*ResolvedSubjectMapping, 0, len(r.derived.SubjectMappings))
	for _, mapping := range r.derived.SubjectMappings {
		item, err := r.resolveSubjectMapping(mapping)
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, item)
	}
	return resolved, nil
}

func (r *resolver) resolveSubjectMapping(derived *DerivedSubjectMapping) (*ResolvedSubjectMapping, error) {
	if derived == nil || derived.Source == nil {
		return nil, fmt.Errorf("%w: empty subject mapping candidate", ErrUndeterminedTargetMapping)
	}

	if derived.Target == nil {
		return nil, fmt.Errorf("%w: empty namespace reference", ErrUndeterminedTargetMapping)
	}

	item := &ResolvedSubjectMapping{
		Source:    derived.Source,
		Namespace: derived.Target,
	}
	// Subject mappings are only safe to resolve once their action and subject
	// condition set dependencies are themselves resolvable in the same target
	// namespace. This keeps the plan graph internally consistent.
	if err := r.resolveSubjectMappingDependencies(item.Source, item.Namespace); err != nil {
		return nil, fmt.Errorf("subject mapping %q in namespace %q: %w", item.Source.GetId(), item.Namespace.GetId(), err)
	}

	existing, found, err := resolveExistingSubjectMapping(item.Source, r.existing.SubjectMappings[item.Namespace.GetId()])
	switch {
	case found:
		item.AlreadyMigrated = existing
	case err != nil:
		return nil, fmt.Errorf("subject mapping %q in namespace %q: %w", item.Source.GetId(), item.Namespace.GetId(), err)
	default:
		item.NeedsCreate = true
	}

	return item, nil
}

func (r *resolver) resolveRegisteredResources() ([]*ResolvedRegisteredResource, error) {
	if r == nil || r.derived == nil || !r.scopes.has(ScopeRegisteredResources) {
		return nil, nil
	}

	resolved := make([]*ResolvedRegisteredResource, 0, len(r.derived.RegisteredResources))
	for _, resource := range r.derived.RegisteredResources {
		item, err := r.resolveRegisteredResource(resource)
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, item)
	}
	return resolved, nil
}

func (r *resolver) resolveRegisteredResource(derived *DerivedRegisteredResource) (*ResolvedRegisteredResource, error) {
	item := &ResolvedRegisteredResource{}
	if derived == nil {
		return item, nil
	}

	item.Source = derived.Source
	item.Namespace = derived.Target
	item.Unresolved = derived.Unresolved

	if item.Unresolved != nil {
		return item, nil
	}
	if item.Source == nil {
		return nil, fmt.Errorf("%w: registered resource is empty", ErrUndeterminedTargetMapping)
	}
	if item.Namespace == nil {
		return nil, fmt.Errorf("%w: empty namespace reference", ErrUndeterminedTargetMapping)
	}
	existing, found, err := resolveExistingRegisteredResource(item.Source, r.existing.RegisteredResources[item.Namespace.GetId()])
	switch {
	case found:
		item.AlreadyMigrated = existing
	case err != nil:
		return nil, fmt.Errorf("registered resource %q in namespace %q: %w", item.Source.GetId(), item.Namespace.GetId(), err)
	default:
		item.NeedsCreate = true
	}

	return item, nil
}

func (r *resolver) resolveObligationTriggers() ([]*ResolvedObligationTrigger, error) {
	if r == nil || r.derived == nil || !r.scopes.has(ScopeObligationTriggers) {
		return nil, nil
	}

	resolved := make([]*ResolvedObligationTrigger, 0, len(r.derived.ObligationTriggers))
	for _, trigger := range r.derived.ObligationTriggers {
		item, err := r.resolveObligationTrigger(trigger)
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, item)
	}
	return resolved, nil
}

func (r *resolver) resolveObligationTrigger(derived *DerivedObligationTrigger) (*ResolvedObligationTrigger, error) {
	if derived == nil || derived.Source == nil {
		return nil, fmt.Errorf("%w: empty obligation trigger candidate", ErrUndeterminedTargetMapping)
	}
	if derived.Target == nil {
		return nil, fmt.Errorf("%w: empty namespace reference", ErrUndeterminedTargetMapping)
	}

	item := &ResolvedObligationTrigger{
		Source:    derived.Source,
		Namespace: derived.Target,
	}
	existing, found, err := resolveExistingObligationTrigger(item.Source, r.existing.ObligationTriggers[item.Namespace.GetId()])
	switch {
	case found:
		item.AlreadyMigrated = existing
	case err != nil:
		return nil, fmt.Errorf("obligation trigger %q in namespace %q: %w", item.Source.GetId(), item.Namespace.GetId(), err)
	default:
		item.NeedsCreate = true
	}

	return item, nil
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

func (r *resolver) resolveSubjectMappingDependencies(mapping *policy.SubjectMapping, namespace *policy.Namespace) error {
	for _, action := range mapping.GetActions() {
		actionID := action.GetId()
		if actionID == "" {
			return errors.New("subject mapping references an action without an id")
		}

		result := r.actionResultsByKey[resolvedResultKey(actionID, namespace.GetId())]
		if result == nil {
			return fmt.Errorf("subject mapping dependency action %q is not resolved in namespace %q", actionID, namespace.GetId())
		}
	}

	scsID := mapping.GetSubjectConditionSet().GetId()
	if scsID == "" {
		return errors.New("subject mapping references a subject condition set without an id")
	}

	result := r.scsResultsByKey[resolvedResultKey(scsID, namespace.GetId())]
	if result == nil {
		return fmt.Errorf("subject mapping dependency subject condition set %q is not resolved in namespace %q", scsID, namespace.GetId())
	}

	return nil
}

func resolveExistingAction(source *policy.Action, existing []*policy.Action) (*policy.Action, bool, error) {
	matches := make([]*policy.Action, 0, 1)
	for _, action := range existing {
		if actionCanonicalEqual(source, action) {
			matches = append(matches, action)
		}
	}

	switch len(matches) {
	case 1:
		return matches[0], true, nil
	case 0:
		return nil, false, nil
	default:
		return nil, false, ErrDuplicateCanonicalMatch
	}
}

func resolveExistingSubjectConditionSet(source *policy.SubjectConditionSet, existing []*policy.SubjectConditionSet) (*policy.SubjectConditionSet, bool, error) {
	matches := make([]*policy.SubjectConditionSet, 0, 1)
	for _, scs := range existing {
		if subjectConditionSetCanonicalEqual(source, scs) {
			matches = append(matches, scs)
		}
	}

	switch len(matches) {
	case 1:
		return matches[0], true, nil
	case 0:
		return nil, false, nil
	default:
		return nil, false, ErrDuplicateCanonicalMatch
	}
}

func resolveExistingSubjectMapping(source *policy.SubjectMapping, existing []*policy.SubjectMapping) (*policy.SubjectMapping, bool, error) {
	matches := make([]*policy.SubjectMapping, 0, 1)
	for _, mapping := range existing {
		if subjectMappingCanonicalEqual(source, mapping) {
			matches = append(matches, mapping)
		}
	}

	switch len(matches) {
	case 1:
		return matches[0], true, nil
	case 0:
		return nil, false, nil
	default:
		return nil, false, ErrDuplicateCanonicalMatch
	}
}

func resolveExistingRegisteredResource(source *policy.RegisteredResource, existing []*policy.RegisteredResource) (*policy.RegisteredResource, bool, error) {
	matches := make([]*policy.RegisteredResource, 0, 1)
	for _, resource := range existing {
		if registeredResourceCanonicalEqual(source, resource) {
			matches = append(matches, resource)
		}
	}

	switch len(matches) {
	case 1:
		return matches[0], true, nil
	case 0:
		return nil, false, nil
	default:
		return nil, false, ErrDuplicateCanonicalMatch
	}
}

func resolveExistingObligationTrigger(source *policy.ObligationTrigger, existing []*policy.ObligationTrigger) (*policy.ObligationTrigger, bool, error) {
	matches := make([]*policy.ObligationTrigger, 0, 1)
	for _, trigger := range existing {
		if obligationTriggerCanonicalEqual(source, trigger) {
			matches = append(matches, trigger)
		}
	}

	switch len(matches) {
	case 1:
		return matches[0], true, nil
	case 0:
		return nil, false, nil
	default:
		return nil, false, ErrDuplicateCanonicalMatch
	}
}

func resolvedResultKey(sourceID, namespaceID string) string {
	return sourceID + "|" + namespaceID
}

func scopesFromSlice(scopes []Scope) scopeSet {
	set := make(scopeSet, len(scopes))
	for _, scope := range scopes {
		set[scope] = struct{}{}
	}
	return set
}
