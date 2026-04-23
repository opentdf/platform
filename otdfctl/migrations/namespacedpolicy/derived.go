package namespacedpolicy

import (
	"errors"
	"fmt"

	"github.com/opentdf/platform/protocol/go/policy"
)

type DerivedTargets struct {
	Scopes               []Scope
	Actions              []*DerivedAction
	SubjectConditionSets []*DerivedSubjectConditionSet
	SubjectMappings      []*DerivedSubjectMapping
	RegisteredResources  []*DerivedRegisteredResource
	ObligationTriggers   []*DerivedObligationTrigger
}

type DerivedAction struct {
	Source  *policy.Action
	Targets []*policy.Namespace
}

type DerivedSubjectConditionSet struct {
	Source  *policy.SubjectConditionSet
	Targets []*policy.Namespace
}

type DerivedSubjectMapping struct {
	Source *policy.SubjectMapping
	Target *policy.Namespace
}

type DerivedRegisteredResource struct {
	Source     *policy.RegisteredResource
	Target     *policy.Namespace
	Unresolved *Unresolved
}

type DerivedObligationTrigger struct {
	Source *policy.ObligationTrigger
	Target *policy.Namespace
}

type targetDeriver struct {
	namespaces        []*policy.Namespace
	namespaceByID     map[string]*policy.Namespace
	namespaceByFQN    map[string]*policy.Namespace
	actionTargetsByID map[string]*namespaceAccumulator
	scsTargetsByID    map[string]*namespaceAccumulator
}

var errSkipRegisteredResource = errors.New("skip registered resource")

func deriveTargets(retrieved *Retrieved, namespaces []*policy.Namespace) (*DerivedTargets, error) {
	if retrieved == nil {
		return nil, ErrNilRetrieved
	}

	deriver := newTargetDeriver(namespaces)
	derived := &DerivedTargets{
		Scopes:               append([]Scope(nil), retrieved.Scopes...),
		Actions:              make([]*DerivedAction, 0, len(retrieved.Candidates.Actions)),
		SubjectConditionSets: make([]*DerivedSubjectConditionSet, 0, len(retrieved.Candidates.SubjectConditionSets)),
		SubjectMappings:      make([]*DerivedSubjectMapping, 0, len(retrieved.Candidates.SubjectMappings)),
		RegisteredResources:  make([]*DerivedRegisteredResource, 0, len(retrieved.Candidates.RegisteredResources)),
		ObligationTriggers:   make([]*DerivedObligationTrigger, 0, len(retrieved.Candidates.ObligationTriggers)),
	}

	for _, mapping := range retrieved.Candidates.SubjectMappings {
		if mapping == nil {
			continue
		}
		item, err := deriver.deriveSubjectMapping(mapping)
		if err != nil {
			return nil, err
		}
		derived.SubjectMappings = append(derived.SubjectMappings, item)
		deriver.observeSubjectMapping(item)
	}

	for _, resource := range retrieved.Candidates.RegisteredResources {
		if resource == nil {
			continue
		}
		item, err := deriver.deriveRegisteredResource(resource)
		if err != nil {
			if errors.Is(err, errSkipRegisteredResource) {
				continue
			}
			return nil, err
		}
		derived.RegisteredResources = append(derived.RegisteredResources, item)
		deriver.observeRegisteredResource(item)
	}

	for _, trigger := range retrieved.Candidates.ObligationTriggers {
		if trigger == nil {
			continue
		}
		item, err := deriver.deriveObligationTrigger(trigger)
		if err != nil {
			return nil, err
		}
		derived.ObligationTriggers = append(derived.ObligationTriggers, item)
		deriver.observeObligationTrigger(item)
	}

	for _, action := range retrieved.Candidates.Actions {
		if action == nil {
			continue
		}
		item := deriver.deriveAction(action)
		if item == nil {
			continue
		}
		derived.Actions = append(derived.Actions, item)
	}

	for _, scs := range retrieved.Candidates.SubjectConditionSets {
		if scs == nil {
			continue
		}
		item := deriver.deriveSubjectConditionSet(scs)
		if item == nil {
			continue
		}
		derived.SubjectConditionSets = append(derived.SubjectConditionSets, item)
	}

	return derived, nil
}

func newTargetDeriver(namespaces []*policy.Namespace) *targetDeriver {
	namespaceByID := make(map[string]*policy.Namespace, len(namespaces))
	namespaceByFQN := make(map[string]*policy.Namespace, len(namespaces))
	for _, namespace := range namespaces {
		if namespace == nil {
			continue
		}
		if id := namespace.GetId(); id != "" {
			namespaceByID[id] = namespace
		}
		if fqn := namespace.GetFqn(); fqn != "" {
			namespaceByFQN[fqn] = namespace
		}
	}

	return &targetDeriver{
		namespaces:        namespaces,
		namespaceByID:     namespaceByID,
		namespaceByFQN:    namespaceByFQN,
		actionTargetsByID: make(map[string]*namespaceAccumulator),
		scsTargetsByID:    make(map[string]*namespaceAccumulator),
	}
}

func (d *targetDeriver) deriveSubjectMapping(mapping *policy.SubjectMapping) (*DerivedSubjectMapping, error) {
	item := &DerivedSubjectMapping{Source: mapping}
	namespace, err := d.resolveNamespace(namespaceFromAttributeValue(mapping.GetAttributeValue()))
	if err != nil {
		return nil, fmt.Errorf("subject mapping %q: %w", mapping.GetId(), err)
	}

	item.Target = namespace
	return item, nil
}

func (d *targetDeriver) deriveRegisteredResource(resource *policy.RegisteredResource) (*DerivedRegisteredResource, error) {
	item := &DerivedRegisteredResource{Source: resource}

	namespaceRef, ok := registeredResourceNamespaceRef(resource)
	if !ok {
		// Registered resources only resolve when their action-attribute values
		// imply exactly one target namespace. No AAV-derived namespace, or AAVs
		// spanning multiple namespaces, leaves the RR unresolved here.
		if hasRegisteredResourceActionAttributeValues(resource) {
			item.Unresolved = &Unresolved{
				Reason:  UnresolvedReasonRegisteredResourceConflictingNamespaces,
				Message: fmt.Errorf("%w: registered resource spans multiple target namespaces", ErrUndeterminedTargetMapping).Error(),
			}
			return item, nil
		}
		// Skip registered resources that have no action-attribute values because they do not provide a derivable namespace target.
		return nil, errSkipRegisteredResource
	}

	namespace, err := d.resolveNamespace(namespaceRef)
	if err != nil {
		return nil, fmt.Errorf("registered resource %q: %w", resource.GetId(), err)
	}

	item.Target = namespace
	return item, nil
}

func (d *targetDeriver) deriveObligationTrigger(trigger *policy.ObligationTrigger) (*DerivedObligationTrigger, error) {
	item := &DerivedObligationTrigger{Source: trigger}
	namespace, err := d.resolveNamespace(namespaceFromObligationValue(trigger.GetObligationValue()))
	if err != nil {
		return nil, fmt.Errorf("obligation trigger %q: %w", trigger.GetId(), err)
	}

	item.Target = namespace
	return item, nil
}

// deriveAction returns nil when the action has no observed referencing
// subject mapping, registered resource, or obligation trigger in scope — an
// orphan action has no target namespace to migrate to and is silently skipped
// rather than carried through as an empty-targets ResolvedAction.
func (d *targetDeriver) deriveAction(action *policy.Action) *DerivedAction {
	targets := d.targets(d.actionTargetsByID[action.GetId()])
	if len(targets) == 0 {
		return nil
	}

	return &DerivedAction{
		Source:  action,
		Targets: targets,
	}
}

// deriveSubjectConditionSet returns nil when the SCS has no referencing
// subject mapping in scope — a legacy SCS that isn't being migrated is silently
// skipped rather than treated as a retrieval invariant violation.
func (d *targetDeriver) deriveSubjectConditionSet(scs *policy.SubjectConditionSet) *DerivedSubjectConditionSet {
	targets := d.targets(d.scsTargetsByID[scs.GetId()])
	if len(targets) == 0 {
		return nil
	}

	return &DerivedSubjectConditionSet{
		Source:  scs,
		Targets: targets,
	}
}

func (d *targetDeriver) observeSubjectMapping(item *DerivedSubjectMapping) {
	if item == nil || item.Source == nil || item.Target == nil {
		return
	}

	for _, action := range item.Source.GetActions() {
		d.addActionTarget(action.GetId(), item.Target)
	}

	if scsID := item.Source.GetSubjectConditionSet().GetId(); scsID != "" {
		d.addSubjectConditionSetTarget(scsID, item.Target)
	}
}

func (d *targetDeriver) observeRegisteredResource(item *DerivedRegisteredResource) {
	if item == nil || item.Source == nil || item.Target == nil {
		return
	}

	for _, value := range item.Source.GetValues() {
		for _, aav := range value.GetActionAttributeValues() {
			d.addActionTarget(aav.GetAction().GetId(), item.Target)
		}
	}
}

func (d *targetDeriver) observeObligationTrigger(item *DerivedObligationTrigger) {
	if item == nil || item.Source == nil || item.Target == nil {
		return
	}

	d.addActionTarget(item.Source.GetAction().GetId(), item.Target)
}

func (d *targetDeriver) addActionTarget(actionID string, namespace *policy.Namespace) {
	if actionID == "" || namespace == nil {
		return
	}

	targets := d.actionTargetsByID[actionID]
	if targets == nil {
		targets = newNamespaceAccumulator()
		d.actionTargetsByID[actionID] = targets
	}
	targets.add(namespace)
}

func (d *targetDeriver) addSubjectConditionSetTarget(scsID string, namespace *policy.Namespace) {
	if scsID == "" || namespace == nil {
		return
	}

	targets := d.scsTargetsByID[scsID]
	if targets == nil {
		targets = newNamespaceAccumulator()
		d.scsTargetsByID[scsID] = targets
	}
	targets.add(namespace)
}

func (d *targetDeriver) targets(targets *namespaceAccumulator) []*policy.Namespace {
	if targets == nil {
		return nil
	}

	return targets.slice()
}

func (d *targetDeriver) resolveNamespace(namespace *policy.Namespace) (*policy.Namespace, error) {
	if namespace == nil {
		return nil, fmt.Errorf("%w: empty namespace reference", ErrUndeterminedTargetMapping)
	}
	if id := namespace.GetId(); id != "" {
		if resolved, ok := d.namespaceByID[id]; ok {
			return resolved, nil
		}
	}
	if fqn := namespace.GetFqn(); fqn != "" {
		if resolved, ok := d.namespaceByFQN[fqn]; ok {
			return resolved, nil
		}
	}

	return nil, fmt.Errorf("%w: id=%q fqn=%q", ErrMissingTargetNamespace, namespace.GetId(), namespace.GetFqn())
}

func derivedActionNamespaces(derived *DerivedTargets) []*policy.Namespace {
	if derived == nil {
		return nil
	}

	ordered := newNamespaceAccumulator()
	for _, action := range derived.Actions {
		if action == nil {
			continue
		}
		for _, namespace := range action.Targets {
			ordered.add(namespace)
		}
	}

	return ordered.slice()
}

func derivedSubjectConditionSetNamespaces(derived *DerivedTargets) []*policy.Namespace {
	if derived == nil {
		return nil
	}

	ordered := newNamespaceAccumulator()
	for _, scs := range derived.SubjectConditionSets {
		if scs == nil {
			continue
		}
		for _, namespace := range scs.Targets {
			ordered.add(namespace)
		}
	}

	return ordered.slice()
}

func derivedSubjectMappingNamespaces(derived *DerivedTargets) []*policy.Namespace {
	if derived == nil {
		return nil
	}

	ordered := newNamespaceAccumulator()
	for _, mapping := range derived.SubjectMappings {
		if mapping == nil {
			continue
		}
		ordered.add(mapping.Target)
	}

	return ordered.slice()
}

func derivedRegisteredResourceNamespaces(derived *DerivedTargets) []*policy.Namespace {
	if derived == nil {
		return nil
	}

	ordered := newNamespaceAccumulator()
	for _, resource := range derived.RegisteredResources {
		if resource == nil {
			continue
		}
		ordered.add(resource.Target)
	}

	return ordered.slice()
}

func derivedObligationTriggerNamespaces(derived *DerivedTargets) []*policy.Namespace {
	if derived == nil {
		return nil
	}

	ordered := newNamespaceAccumulator()
	for _, trigger := range derived.ObligationTriggers {
		if trigger == nil {
			continue
		}
		ordered.add(trigger.Target)
	}

	return ordered.slice()
}

type namespaceAccumulator struct {
	items []*policy.Namespace
	seen  map[string]struct{}
}

func newNamespaceAccumulator() *namespaceAccumulator {
	return &namespaceAccumulator{
		seen: make(map[string]struct{}),
	}
}

func (a *namespaceAccumulator) add(namespace *policy.Namespace) {
	if a == nil || namespace == nil {
		return
	}
	key := namespaceRefKey(namespace)
	if key == "" {
		return
	}
	if _, ok := a.seen[key]; ok {
		return
	}
	a.seen[key] = struct{}{}
	a.items = append(a.items, namespace)
}

func (a *namespaceAccumulator) slice() []*policy.Namespace {
	if a == nil {
		return nil
	}

	return append([]*policy.Namespace(nil), a.items...)
}
