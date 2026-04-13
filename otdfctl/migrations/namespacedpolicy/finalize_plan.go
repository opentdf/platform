package namespacedpolicy

import (
	"errors"

	"github.com/opentdf/platform/protocol/go/policy"
)

var ErrNilResolvedTargets = errors.New("planner resolved state is required")

const unusedActionReason = "action is not referenced by any subject mapping, registered resource, or obligation trigger"

// finalizePlan converts the fully resolved graph into the current Plan shape.
// This is the last planner stage before artifact building/execution wiring.
func finalizePlan(resolved *ResolvedTargets, namespaces []*policy.Namespace) (*Plan, error) {
	if resolved == nil {
		return nil, ErrNilResolvedTargets
	}

	scopes, err := normalizeScopes(resolved.Scopes)
	if err != nil {
		return nil, err
	}

	finalizer := newPlanFinalizer(resolved, namespaces)

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
	namespaces           []*policy.Namespace
	namespacePlansByID   map[string]*NamespacePlan
	actions              []*ActionPlan
	subjectConditionSets []*SubjectConditionSetPlan
	subjectMappings      []*SubjectMappingPlan
	registeredResources  []*RegisteredResourcePlan
	obligationTriggers   []*ObligationTriggerPlan
	actionTargetsByKey   map[string]*ActionTargetPlan
	scsTargetsByKey      map[string]*SubjectConditionSetTargetPlan
	unused               UnusedPlan
	unresolved           UnresolvedPlan
}

func newPlanFinalizer(resolved *ResolvedTargets, namespaces []*policy.Namespace) *planFinalizer {
	return &planFinalizer{
		resolved:           resolved,
		namespaces:         namespaces,
		namespacePlansByID: make(map[string]*NamespacePlan),
		actionTargetsByKey: make(map[string]*ActionTargetPlan),
		scsTargetsByKey:    make(map[string]*SubjectConditionSetTargetPlan),
	}
}

func (f *planFinalizer) build() *Plan {
	plan := &Plan{
		Scopes:               append([]Scope(nil), f.resolved.Scopes...),
		Namespaces:           make([]*NamespacePlan, 0, len(f.namespacePlansByID)),
		Actions:              append([]*ActionPlan(nil), f.actions...),
		SubjectConditionSets: append([]*SubjectConditionSetPlan(nil), f.subjectConditionSets...),
		SubjectMappings:      append([]*SubjectMappingPlan(nil), f.subjectMappings...),
		RegisteredResources:  append([]*RegisteredResourcePlan(nil), f.registeredResources...),
		ObligationTriggers:   append([]*ObligationTriggerPlan(nil), f.obligationTriggers...),
	}

	for _, namespace := range f.namespaces {
		if namespace == nil || namespace.GetId() == "" {
			continue
		}
		if namespacePlan, ok := f.namespacePlansByID[namespace.GetId()]; ok {
			plan.Namespaces = append(plan.Namespaces, namespacePlan)
		}
	}

	if hasUnused(f.unused) {
		plan.Unused = &f.unused
	}

	if hasUnresolved(f.unresolved) {
		plan.Unresolved = &f.unresolved
	}

	return plan
}

func (f *planFinalizer) addResolvedAction(item *ResolvedAction) {
	if item == nil || item.Source == nil {
		return
	}

	if item.Unresolved == "" && len(item.Results) == 0 && len(item.References) == 0 {
		f.addUnusedAction(item.Source, item.References, unusedActionReason)
		return
	}

	actionPlan := &ActionPlan{
		Source:     item.Source,
		References: append([]*ActionReference(nil), item.References...),
		Targets:    make([]*ActionTargetPlan, 0, len(item.Results)),
	}
	if item.Unresolved != "" {
		actionPlan.Unresolved = item.Unresolved
		f.addActionIssue(item.Source, nil, item.Unresolved)
	}

	for _, result := range item.Results {
		target := newActionTargetPlan(result)
		if target == nil {
			continue
		}
		actionPlan.Targets = append(actionPlan.Targets, target)
		f.storeActionTarget(item.Source.GetId(), target)

		if target.Status == TargetStatusUnresolved {
			f.addActionIssue(item.Source, target.Namespace, target.Reason)
			continue
		}
		f.addNamespacePlacement(target.Namespace, ScopeActions, item.Source.GetId())
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
	if item.Unresolved != "" {
		scsPlan.Unresolved = item.Unresolved
		f.addSubjectConditionSetIssue(item.Source, nil, item.Unresolved)
	}

	for _, result := range item.Results {
		target := newSubjectConditionSetTargetPlan(result)
		if target == nil {
			continue
		}
		scsPlan.Targets = append(scsPlan.Targets, target)
		f.storeSubjectConditionSetTarget(item.Source.GetId(), target)

		if target.Status == TargetStatusUnresolved {
			f.addSubjectConditionSetIssue(item.Source, target.Namespace, target.Reason)
			continue
		}
		f.addNamespacePlacement(target.Namespace, ScopeSubjectConditionSets, item.Source.GetId())
	}

	f.subjectConditionSets = append(f.subjectConditionSets, scsPlan)
}

func (f *planFinalizer) addResolvedSubjectMapping(item *ResolvedSubjectMapping) {
	if item == nil || item.Source == nil {
		return
	}

	mappingPlan := &SubjectMappingPlan{Source: item.Source}
	if item.Unresolved != "" {
		mappingPlan.Unresolved = item.Unresolved
	}

	target := f.newSubjectMappingTarget(item)
	if target != nil {
		mappingPlan.Targets = append(mappingPlan.Targets, target)
		if target.Status == TargetStatusUnresolved {
			f.addSubjectMappingIssue(item.Source, target.Namespace, target.Reason)
		} else {
			f.addNamespacePlacement(target.Namespace, ScopeSubjectMappings, item.Source.GetId())
		}
	} else if item.Unresolved != "" {
		f.addSubjectMappingIssue(item.Source, item.Namespace, item.Unresolved)
	}

	f.subjectMappings = append(f.subjectMappings, mappingPlan)
}

func (f *planFinalizer) addResolvedRegisteredResource(item *ResolvedRegisteredResource) {
	if item == nil || item.Source == nil {
		return
	}

	resourcePlan := &RegisteredResourcePlan{Source: item.Source}
	if item.Unresolved != "" {
		resourcePlan.Unresolved = item.Unresolved
	}

	target := f.newRegisteredResourceTarget(item)
	if target != nil {
		resourcePlan.Targets = append(resourcePlan.Targets, target)
		if target.Status == TargetStatusUnresolved {
			f.addRegisteredResourceIssue(item.Source, target.Namespace, target.Reason)
		} else {
			f.addNamespacePlacement(target.Namespace, ScopeRegisteredResources, item.Source.GetId())
		}
	} else if item.Unresolved != "" {
		f.addRegisteredResourceIssue(item.Source, item.Namespace, item.Unresolved)
	}

	f.registeredResources = append(f.registeredResources, resourcePlan)
}

func (f *planFinalizer) addResolvedObligationTrigger(item *ResolvedObligationTrigger) {
	if item == nil || item.Source == nil {
		return
	}

	triggerPlan := &ObligationTriggerPlan{Source: item.Source}
	if item.Unresolved != "" {
		triggerPlan.Unresolved = item.Unresolved
	}

	target := f.newObligationTriggerTarget(item)
	if target != nil {
		triggerPlan.Targets = append(triggerPlan.Targets, target)
		if target.Status == TargetStatusUnresolved {
			f.addObligationTriggerIssue(item.Source, target.Namespace, target.Reason)
		} else {
			f.addNamespacePlacement(target.Namespace, ScopeObligationTriggers, item.Source.GetId())
		}
	} else if item.Unresolved != "" {
		f.addObligationTriggerIssue(item.Source, item.Namespace, item.Unresolved)
	}

	f.obligationTriggers = append(f.obligationTriggers, triggerPlan)
}

func (f *planFinalizer) namespacePlan(namespace *policy.Namespace) *NamespacePlan {
	if namespace == nil || namespace.GetId() == "" {
		return nil
	}

	namespacePlan, ok := f.namespacePlansByID[namespace.GetId()]
	if ok {
		return namespacePlan
	}

	namespacePlan = &NamespacePlan{
		Namespace: namespace,
	}
	f.namespacePlansByID[namespace.GetId()] = namespacePlan
	return namespacePlan
}

func (f *planFinalizer) addNamespacePlacement(namespace *policy.Namespace, scope Scope, sourceID string) {
	if namespace == nil || namespace.GetId() == "" || sourceID == "" {
		return
	}

	namespacePlan := f.namespacePlan(namespace)
	if namespacePlan == nil {
		return
	}

	switch scope {
	case ScopeActions:
		namespacePlan.Actions = appendUniqueString(namespacePlan.Actions, sourceID)
	case ScopeSubjectConditionSets:
		namespacePlan.SubjectConditionSets = appendUniqueString(namespacePlan.SubjectConditionSets, sourceID)
	case ScopeSubjectMappings:
		namespacePlan.SubjectMappings = appendUniqueString(namespacePlan.SubjectMappings, sourceID)
	case ScopeRegisteredResources:
		namespacePlan.RegisteredResources = appendUniqueString(namespacePlan.RegisteredResources, sourceID)
	case ScopeObligationTriggers:
		namespacePlan.ObligationTriggers = appendUniqueString(namespacePlan.ObligationTriggers, sourceID)
	}
}

func (f *planFinalizer) storeActionTarget(sourceID string, target *ActionTargetPlan) {
	if sourceID == "" || target == nil || target.Namespace == nil || target.Namespace.GetId() == "" {
		return
	}
	f.actionTargetsByKey[resolvedResultKey(sourceID, target.Namespace.GetId())] = target
}

func (f *planFinalizer) storeSubjectConditionSetTarget(sourceID string, target *SubjectConditionSetTargetPlan) {
	if sourceID == "" || target == nil || target.Namespace == nil || target.Namespace.GetId() == "" {
		return
	}
	f.scsTargetsByKey[resolvedResultKey(sourceID, target.Namespace.GetId())] = target
}

func (f *planFinalizer) newSubjectMappingTarget(item *ResolvedSubjectMapping) *SubjectMappingTargetPlan {
	if item == nil || item.Namespace == nil {
		return nil
	}

	target := &SubjectMappingTargetPlan{
		Namespace: item.Namespace,
		Actions:   make([]*ActionBinding, 0, len(item.Source.GetActions())),
	}

	switch {
	case item.AlreadyMigrated != nil:
		target.Status = TargetStatusAlreadyMigrated
		target.Existing = item.AlreadyMigrated
	case item.NeedsCreate:
		target.Status = TargetStatusCreate
	case item.Unresolved != "":
		target.Status = TargetStatusUnresolved
		target.Reason = item.Unresolved
	default:
		return nil
	}

	for _, action := range item.Source.GetActions() {
		target.Actions = append(target.Actions, f.actionBinding(action.GetId(), item.Namespace))
	}
	target.SubjectConditionSet = f.subjectConditionSetBinding(item.Source.GetSubjectConditionSet().GetId(), item.Namespace)

	return target
}

func (f *planFinalizer) newRegisteredResourceTarget(item *ResolvedRegisteredResource) *RegisteredResourceTargetPlan {
	if item == nil || item.Namespace == nil {
		return nil
	}

	target := &RegisteredResourceTargetPlan{
		Namespace: item.Namespace,
		Values:    make([]*RegisteredResourceValuePlan, 0, len(item.Source.GetValues())),
	}

	switch {
	case item.AlreadyMigrated != nil:
		target.Status = TargetStatusAlreadyMigrated
		target.Existing = item.AlreadyMigrated
	case item.NeedsCreate:
		target.Status = TargetStatusCreate
	case item.Unresolved != "":
		target.Status = TargetStatusUnresolved
		target.Reason = item.Unresolved
	default:
		return nil
	}

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
				ActionTargetRef: f.actionBinding(
					aav.GetAction().GetId(),
					item.Namespace,
				),
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
		target.Existing = item.AlreadyMigrated
	case item.NeedsCreate:
		target.Status = TargetStatusCreate
	case item.Unresolved != "":
		target.Status = TargetStatusUnresolved
		target.Reason = item.Unresolved
	default:
		return nil
	}
	target.Action = f.actionBinding(item.Source.GetAction().GetId(), item.Namespace)

	return target
}

func (f *planFinalizer) actionBinding(sourceID string, namespace *policy.Namespace) *ActionBinding {
	if sourceID == "" || namespace == nil {
		return nil
	}

	target := f.actionTargetsByKey[resolvedResultKey(sourceID, namespace.GetId())]
	if target == nil {
		return &ActionBinding{
			SourceID:  sourceID,
			Namespace: namespace,
			Status:    TargetStatusUnresolved,
			Reason:    "action target is not available in the finalized plan",
		}
	}

	return &ActionBinding{
		SourceID:  sourceID,
		Namespace: namespace,
		Status:    target.Status,
		TargetID:  target.TargetID(),
		Reason:    target.Reason,
	}
}

func (f *planFinalizer) subjectConditionSetBinding(sourceID string, namespace *policy.Namespace) *SubjectConditionSetBinding {
	if sourceID == "" || namespace == nil {
		return nil
	}

	target := f.scsTargetsByKey[resolvedResultKey(sourceID, namespace.GetId())]
	if target == nil {
		return &SubjectConditionSetBinding{
			SourceID:  sourceID,
			Namespace: namespace,
			Status:    TargetStatusUnresolved,
			Reason:    "subject condition set target is not available in the finalized plan",
		}
	}

	return &SubjectConditionSetBinding{
		SourceID:  sourceID,
		Namespace: namespace,
		Status:    target.Status,
		TargetID:  target.TargetID(),
		Reason:    target.Reason,
	}
}

func (f *planFinalizer) addActionIssue(action *policy.Action, namespace *policy.Namespace, reason string) {
	if action == nil || reason == "" {
		return
	}
	// TODO: Replace this linear dedupe scan with a set if unresolved issue counts
	// grow enough for this path to matter.
	for _, issue := range f.unresolved.Actions {
		if issue != nil && issue.Source != nil && issue.Source.GetId() == action.GetId() && sameNamespace(issue.Namespace, namespace) && issue.Reason == reason {
			return
		}
	}
	f.unresolved.Actions = append(f.unresolved.Actions, &ActionIssue{Source: action, Namespace: namespace, Reason: reason})
}

func (f *planFinalizer) addUnusedAction(action *policy.Action, references []*ActionReference, reason string) {
	if action == nil || reason == "" {
		return
	}
	for _, unused := range f.unused.Actions {
		if unused != nil && unused.Source != nil && unused.Source.GetId() == action.GetId() && unused.Reason == reason {
			return
		}
	}
	f.unused.Actions = append(f.unused.Actions, &UnusedAction{
		Source:     action,
		References: append([]*ActionReference(nil), references...),
		Reason:     reason,
	})
}

func (f *planFinalizer) addSubjectConditionSetIssue(scs *policy.SubjectConditionSet, namespace *policy.Namespace, reason string) {
	if scs == nil || reason == "" {
		return
	}
	for _, issue := range f.unresolved.SubjectConditionSets {
		if issue != nil && issue.Source != nil && issue.Source.GetId() == scs.GetId() && sameNamespace(issue.Namespace, namespace) && issue.Reason == reason {
			return
		}
	}
	f.unresolved.SubjectConditionSets = append(f.unresolved.SubjectConditionSets, &SubjectConditionSetIssue{Source: scs, Namespace: namespace, Reason: reason})
}

func (f *planFinalizer) addSubjectMappingIssue(mapping *policy.SubjectMapping, namespace *policy.Namespace, reason string) {
	if mapping == nil || reason == "" {
		return
	}
	for _, issue := range f.unresolved.SubjectMappings {
		if issue != nil && issue.Source != nil && issue.Source.GetId() == mapping.GetId() && sameNamespace(issue.Namespace, namespace) && issue.Reason == reason {
			return
		}
	}
	f.unresolved.SubjectMappings = append(f.unresolved.SubjectMappings, &SubjectMappingIssue{Source: mapping, Namespace: namespace, Reason: reason})
}

func (f *planFinalizer) addRegisteredResourceIssue(resource *policy.RegisteredResource, namespace *policy.Namespace, reason string) {
	if resource == nil || reason == "" {
		return
	}
	for _, issue := range f.unresolved.RegisteredResources {
		if issue != nil && issue.Resource != nil &&
			issue.Resource.GetId() == resource.GetId() &&
			sameNamespace(issue.Namespace, namespace) &&
			issue.Reason == reason {
			return
		}
	}
	f.unresolved.RegisteredResources = append(f.unresolved.RegisteredResources, &RegisteredResourceIssue{
		Resource:  resource,
		Namespace: namespace,
		Reason:    reason,
	})
}

func (f *planFinalizer) addObligationTriggerIssue(trigger *policy.ObligationTrigger, namespace *policy.Namespace, reason string) {
	if trigger == nil || reason == "" {
		return
	}
	for _, issue := range f.unresolved.ObligationTriggers {
		if issue != nil && issue.Source != nil && issue.Source.GetId() == trigger.GetId() && sameNamespace(issue.Namespace, namespace) && issue.Reason == reason {
			return
		}
	}
	f.unresolved.ObligationTriggers = append(f.unresolved.ObligationTriggers, &ObligationTriggerIssue{Source: trigger, Namespace: namespace, Reason: reason})
}

func newActionTargetPlan(result *ResolvedActionResult) *ActionTargetPlan {
	if result == nil || result.Namespace == nil {
		return nil
	}

	target := &ActionTargetPlan{Namespace: result.Namespace}
	switch {
	case result.AlreadyMigrated != nil:
		target.Status = TargetStatusAlreadyMigrated
		target.Existing = result.AlreadyMigrated
	case result.ExistingStandard != nil:
		target.Status = TargetStatusExistingStandard
		target.Existing = result.ExistingStandard
	case result.NeedsCreate:
		target.Status = TargetStatusCreate
	case result.Unresolved != "":
		target.Status = TargetStatusUnresolved
		target.Reason = result.Unresolved
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
		target.Existing = result.AlreadyMigrated
	case result.NeedsCreate:
		target.Status = TargetStatusCreate
	case result.Unresolved != "":
		target.Status = TargetStatusUnresolved
		target.Reason = result.Unresolved
	default:
		return nil
	}

	return target
}

func appendUniqueString(items []string, value string) []string {
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}
