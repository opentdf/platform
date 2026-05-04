package namespacedpolicy

import (
	"errors"
)

var ErrNilResolvedTargets = errors.New("planner resolved state is required")

// finalizePlan converts the fully resolved graph into the current Plan shape.
// This is the last planner stage before artifact building/execution wiring.
func finalizePlan(resolved *ResolvedTargets) (*Plan, error) {
	if resolved == nil {
		return nil, ErrNilResolvedTargets
	}

	scopes, err := normalizeScopes(resolved.Scopes)
	if err != nil {
		return nil, err
	}

	finalizer := newPlanFinalizer(resolved)

	if scopes.requiresActions() {
		for _, action := range resolved.Actions {
			finalizer.addResolvedAction(action)
		}
	}

	if scopes.requiresSubjectConditionSets() {
		for _, scs := range resolved.SubjectConditionSets {
			finalizer.addResolvedSubjectConditionSet(scs)
		}
	}

	if scopes.has(ScopeSubjectMappings) {
		for _, mapping := range resolved.SubjectMappings {
			finalizer.addResolvedSubjectMapping(mapping)
		}
	}

	if scopes.has(ScopeRegisteredResources) {
		for _, resource := range resolved.RegisteredResources {
			finalizer.addResolvedRegisteredResource(resource)
		}
	}

	if scopes.has(ScopeObligationTriggers) {
		for _, trigger := range resolved.ObligationTriggers {
			finalizer.addResolvedObligationTrigger(trigger)
		}
	}

	return finalizer.build(), nil
}

// planFinalizer folds resolved placements into an executable plan that
// preserves per-target status and dependency bindings for downstream creates.
type planFinalizer struct {
	resolved             *ResolvedTargets
	actions              []*ActionPlan
	subjectConditionSets []*SubjectConditionSetPlan
	subjectMappings      []*SubjectMappingPlan
	registeredResources  []*RegisteredResourcePlan
	obligationTriggers   []*ObligationTriggerPlan
}

func newPlanFinalizer(resolved *ResolvedTargets) *planFinalizer {
	return &planFinalizer{
		resolved: resolved,
	}
}

func (f *planFinalizer) build() *Plan {
	return &Plan{
		Scopes:               append([]Scope(nil), f.resolved.Scopes...),
		Actions:              append([]*ActionPlan(nil), f.actions...),
		SubjectConditionSets: append([]*SubjectConditionSetPlan(nil), f.subjectConditionSets...),
		SubjectMappings:      append([]*SubjectMappingPlan(nil), f.subjectMappings...),
		RegisteredResources:  append([]*RegisteredResourcePlan(nil), f.registeredResources...),
		ObligationTriggers:   append([]*ObligationTriggerPlan(nil), f.obligationTriggers...),
	}
}

func (f *planFinalizer) addResolvedAction(item *ResolvedAction) {
	if item == nil || item.Source == nil {
		return
	}

	if len(item.Results) == 0 {
		return
	}

	actionPlan := &ActionPlan{
		Source:  item.Source,
		Targets: make([]*ActionTargetPlan, 0, len(item.Results)),
	}

	for _, result := range item.Results {
		target := newActionTargetPlan(result)
		if target == nil {
			continue
		}
		actionPlan.Targets = append(actionPlan.Targets, target)
	}

	f.actions = append(f.actions, actionPlan)
}

func (f *planFinalizer) addResolvedSubjectConditionSet(item *ResolvedSubjectConditionSet) {
	if item == nil || item.Source == nil {
		return
	}

	scsPlan := &SubjectConditionSetPlan{
		Source:  item.Source,
		Targets: make([]*SubjectConditionSetTargetPlan, 0, len(item.Results)),
	}

	for _, result := range item.Results {
		target := newSubjectConditionSetTargetPlan(result)
		if target == nil {
			continue
		}
		scsPlan.Targets = append(scsPlan.Targets, target)
	}

	f.subjectConditionSets = append(f.subjectConditionSets, scsPlan)
}

func (f *planFinalizer) addResolvedSubjectMapping(item *ResolvedSubjectMapping) {
	if item == nil || item.Source == nil {
		return
	}

	mappingPlan := &SubjectMappingPlan{Source: item.Source}

	target := f.newSubjectMappingTarget(item)
	if target != nil {
		mappingPlan.Target = target
	}

	f.subjectMappings = append(f.subjectMappings, mappingPlan)
}

func (f *planFinalizer) addResolvedRegisteredResource(item *ResolvedRegisteredResource) {
	if item == nil || item.Source == nil {
		return
	}

	resourcePlan := &RegisteredResourcePlan{Source: item.Source}
	if item.Unresolved != nil {
		resourcePlan.Unresolved = item.Unresolved.Message
	}

	target := f.newRegisteredResourceTarget(item)
	if target != nil {
		resourcePlan.Target = target
	}

	f.registeredResources = append(f.registeredResources, resourcePlan)
}

func (f *planFinalizer) addResolvedObligationTrigger(item *ResolvedObligationTrigger) {
	if item == nil || item.Source == nil {
		return
	}

	triggerPlan := &ObligationTriggerPlan{Source: item.Source}

	target := f.newObligationTriggerTarget(item)
	if target != nil {
		triggerPlan.Target = target
	}

	f.obligationTriggers = append(f.obligationTriggers, triggerPlan)
}

func (f *planFinalizer) newSubjectMappingTarget(item *ResolvedSubjectMapping) *SubjectMappingTargetPlan {
	if item == nil || item.Namespace == nil {
		return nil
	}

	target := &SubjectMappingTargetPlan{
		Namespace: item.Namespace,
	}

	switch {
	case item.AlreadyMigrated != nil:
		target.Status = TargetStatusAlreadyMigrated
		target.ExistingID = item.AlreadyMigrated.GetId()
		return target
	case item.NeedsCreate:
		target.Status = TargetStatusCreate
	default:
		return nil
	}

	target.ActionSourceIDs = make([]string, 0, len(item.Source.GetActions()))
	for _, action := range item.Source.GetActions() {
		target.ActionSourceIDs = append(target.ActionSourceIDs, action.GetId())
	}
	target.SubjectConditionSetSourceID = item.Source.GetSubjectConditionSet().GetId()

	return target
}

func (f *planFinalizer) newRegisteredResourceTarget(item *ResolvedRegisteredResource) *RegisteredResourceTargetPlan {
	if item == nil || item.Namespace == nil {
		return nil
	}

	target := &RegisteredResourceTargetPlan{
		Namespace: item.Namespace,
	}

	switch {
	case item.AlreadyMigrated != nil:
		target.Status = TargetStatusAlreadyMigrated
		target.ExistingID = item.AlreadyMigrated.GetId()
		return target
	case item.NeedsCreate:
		target.Status = TargetStatusCreate
	default:
		return nil
	}

	target.Values = make([]*RegisteredResourceValuePlan, 0, len(item.Source.GetValues()))
	for _, value := range item.Source.GetValues() {
		valuePlan := &RegisteredResourceValuePlan{
			Source:         value,
			ActionBindings: make([]*RegisteredResourceActionBinding, 0, len(value.GetActionAttributeValues())),
		}
		for _, aav := range value.GetActionAttributeValues() {
			if aav == nil {
				continue
			}
			valuePlan.ActionBindings = append(valuePlan.ActionBindings, &RegisteredResourceActionBinding{
				SourceActionID: aav.GetAction().GetId(),
				AttributeValue: aav.GetAttributeValue(),
			})
		}
		target.Values = append(target.Values, valuePlan)
	}

	return target
}

func (f *planFinalizer) newObligationTriggerTarget(item *ResolvedObligationTrigger) *ObligationTriggerTargetPlan {
	if item == nil || item.Namespace == nil {
		return nil
	}

	target := &ObligationTriggerTargetPlan{
		Namespace: item.Namespace,
	}
	switch {
	case item.AlreadyMigrated != nil:
		target.Status = TargetStatusAlreadyMigrated
		target.ExistingID = item.AlreadyMigrated.GetId()
		return target
	case item.NeedsCreate:
		target.Status = TargetStatusCreate
	default:
		return nil
	}
	target.ActionSourceID = item.Source.GetAction().GetId()

	return target
}

func newActionTargetPlan(result *ResolvedActionResult) *ActionTargetPlan {
	if result == nil || result.Namespace == nil {
		return nil
	}

	target := &ActionTargetPlan{Namespace: result.Namespace}
	switch {
	case result.AlreadyMigrated != nil:
		target.Status = TargetStatusAlreadyMigrated
		target.ExistingID = result.AlreadyMigrated.GetId()
	case result.ExistingStandard != nil:
		target.Status = TargetStatusExistingStandard
		target.ExistingID = result.ExistingStandard.GetId()
	case result.NeedsCreate:
		target.Status = TargetStatusCreate
	default:
		return nil
	}

	return target
}

func newSubjectConditionSetTargetPlan(result *ResolvedSubjectConditionSetResult) *SubjectConditionSetTargetPlan {
	if result == nil || result.Namespace == nil {
		return nil
	}

	target := &SubjectConditionSetTargetPlan{Namespace: result.Namespace}
	switch {
	case result.AlreadyMigrated != nil:
		target.Status = TargetStatusAlreadyMigrated
		target.ExistingID = result.AlreadyMigrated.GetId()
	case result.NeedsCreate:
		target.Status = TargetStatusCreate
	default:
		return nil
	}

	return target
}
