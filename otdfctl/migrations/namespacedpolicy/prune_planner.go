package namespacedpolicy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
)

var (
	ErrMultiplePruneScopes        = errors.New("prune planner accepts exactly one scope")
	ErrInvalidPruneResolvedTarget = errors.New("invalid prune resolved target")
)

// PrunePlanner classifies whether legacy policy objects can be deleted after
// migration. It accepts exactly one scope and uses one of two strategies:
//
//   - actions and subject condition sets are planned directly from currently
//     listed source objects because they are expected to be deleted last, after
//     their legacy dependents are gone
//   - subject mappings, registered resources, and obligation triggers reuse the
//     migration planner's resolved view because prune decisions for those scopes
//     still depend on resolved migrated targets
//
// Each prune item is classified as delete, blocked, or unresolved and carries
// the migrated target context that justified that decision.
type PrunePlanner struct {
	planner *MigrationPlanner
	scope   Scope
}

type prunePlannerConfig struct {
	pageSize int32
}

type PruneOption func(*prunePlannerConfig)

type pruneObject interface {
	GetId() string
	GetMetadata() *common.Metadata
}

type pruneSourceObject interface {
	GetId() string
}

type pruneMigratedObject interface {
	pruneObject
	*policy.SubjectMapping | *policy.RegisteredResource | *policy.ObligationTrigger
}

// NewPrunePlanner constructs a single-scope prune planner on top of the shared
// migration planner infrastructure. Direct-prune scopes reuse the same
// retriever and namespace discovery logic, while resolved-object scopes reuse
// the resolver state without planner-time interactive review.
func NewPrunePlanner(handler PolicyClient, scopeCSV string, opts ...PruneOption) (*PrunePlanner, error) {
	if handler == nil {
		return nil, ErrNilPlannerHandler
	}

	scopes, err := ParseScopes(scopeCSV)
	if err != nil {
		return nil, err
	}

	normalizedScopes, err := normalizeScopes(scopes)
	if err != nil {
		return nil, err
	}
	if len(normalizedScopes) != 1 {
		return nil, ErrMultiplePruneScopes
	}

	config := prunePlannerConfig{pageSize: defaultPlannerPageSize}
	for _, opt := range opts {
		opt(&config)
	}
	if config.pageSize <= 0 {
		config.pageSize = defaultPlannerPageSize
	}

	planner, err := NewMigrationPlanner(handler, scopeCSV, WithPageSize(config.pageSize))
	if err != nil {
		return nil, err
	}

	return &PrunePlanner{
		planner: planner,
		scope:   normalizedScopes.ordered()[0],
	}, nil
}

func WithPrunePageSize(pageSize int32) PruneOption {
	return func(config *prunePlannerConfig) {
		config.pageSize = pageSize
	}
}

// Plan produces a prune plan for the configured scope.
//
// Actions and subject condition sets bypass resolved migration output and are
// classified directly from current legacy usage plus canonical migrated target
// lookup. Subject mappings, registered resources, and obligation triggers first
// resolve through the migration planner and then translate that resolved state
// into prune statuses.
func (p *PrunePlanner) Plan(ctx context.Context) (*PrunePlan, error) {
	if p == nil || p.planner == nil {
		return nil, ErrNilPlannerHandler
	}
	if p.scope == "" {
		return nil, ErrEmptyPlannerScope
	}
	switch p.scope {
	case ScopeActions:
		return p.planActions(ctx)
	case ScopeSubjectConditionSets:
		return p.planSubjectConditionSets(ctx)
	case ScopeSubjectMappings, ScopeRegisteredResources, ScopeObligationTriggers:
		resolved, err := p.planner.resolve(ctx)
		if err != nil {
			return nil, err
		}
		if resolved == nil {
			return nil, ErrNilResolvedTargets
		}

		return buildPrunePlanFromResolved(p.scope, resolved)
	default:
		return nil, fmt.Errorf("%w: %s", ErrInvalidScope, p.scope)
	}
}

func (p *PrunePlanner) planActions(ctx context.Context) (*PrunePlan, error) {
	sourceActions, err := p.planner.retriever.retrieveActions(ctx)
	if err != nil {
		return nil, err
	}
	sourceActions = customLegacyActions(sourceActions)

	plan := &PrunePlan{
		Scope:   p.scope,
		Actions: make([]*PruneActionPlan, 0, len(sourceActions)),
	}
	if len(sourceActions) == 0 {
		return plan, nil
	}

	usedByID, err := p.usedLegacyActionsByID(ctx, objectIDSet(sourceActions))
	if err != nil {
		return nil, err
	}

	namespaces, err := p.planner.retriever.listNamespaces(ctx)
	if err != nil {
		return nil, err
	}
	targetNamespaces := dedupeTargetNamespaces(namespaces)

	customActionsByNamespace, _, err := p.planner.retriever.listActionsForNamespaces(ctx, targetNamespaces)
	if err != nil {
		return nil, err
	}

	for _, source := range sourceActions {
		if source.GetId() == "" {
			continue
		}

		status, reason, targets, err := pruneStatusForAction(source, usedByID, targetNamespaces, customActionsByNamespace)
		if err != nil {
			return nil, fmt.Errorf("action %q: %w", source.GetId(), err)
		}

		plan.Actions = append(plan.Actions, &PruneActionPlan{
			Source:          source,
			Status:          status,
			MigratedTargets: targets,
			Reason:          reason,
		})
	}

	return plan, nil
}

func (p *PrunePlanner) planSubjectConditionSets(ctx context.Context) (*PrunePlan, error) {
	sourceSCS, err := p.planner.retriever.retrieveSubjectConditionSets(ctx)
	if err != nil {
		return nil, err
	}

	plan := &PrunePlan{
		Scope:                p.scope,
		SubjectConditionSets: make([]*PruneSubjectConditionSetPlan, 0, len(sourceSCS)),
	}
	if len(sourceSCS) == 0 {
		return plan, nil
	}

	usedByID, err := p.usedLegacySubjectConditionSetsByID(ctx, objectIDSet(sourceSCS))
	if err != nil {
		return nil, err
	}

	namespaces, err := p.planner.retriever.listNamespaces(ctx)
	if err != nil {
		return nil, err
	}
	targetNamespaces := dedupeTargetNamespaces(namespaces)

	scsByNamespace, err := p.planner.retriever.listSubjectConditionSetsForNamespaces(ctx, targetNamespaces)
	if err != nil {
		return nil, err
	}

	for _, source := range sourceSCS {
		if source.GetId() == "" {
			continue
		}

		status, reason, targets, err := pruneStatusForSubjectConditionSet(source, usedByID, targetNamespaces, scsByNamespace)
		if err != nil {
			return nil, fmt.Errorf("subject condition set %q: %w", source.GetId(), err)
		}

		plan.SubjectConditionSets = append(plan.SubjectConditionSets, &PruneSubjectConditionSetPlan{
			Source:          source,
			Status:          status,
			MigratedTargets: targets,
			Reason:          reason,
		})
	}

	return plan, nil
}

func (p *PrunePlanner) usedLegacyActionsByID(ctx context.Context, sourceIDs map[string]struct{}) (map[string]struct{}, error) {
	used := make(map[string]struct{}, len(sourceIDs))
	if len(sourceIDs) == 0 {
		return used, nil
	}

	subjectMappings, err := p.planner.retriever.retrieveSubjectMappings(ctx)
	if err != nil {
		return nil, err
	}
	for _, mapping := range subjectMappings {
		if mapping == nil {
			continue
		}
		for _, action := range mapping.GetActions() {
			if action == nil {
				continue
			}
			if _, ok := sourceIDs[action.GetId()]; ok {
				used[action.GetId()] = struct{}{}
			}
		}
	}

	registeredResources, err := p.planner.retriever.retrieveRegisteredResources(ctx)
	if err != nil {
		return nil, err
	}
	for _, resource := range registeredResources {
		if resource == nil {
			continue
		}
		for _, value := range resource.GetValues() {
			if value == nil {
				continue
			}
			for _, aav := range value.GetActionAttributeValues() {
				if aav == nil || aav.GetAction() == nil {
					continue
				}
				if _, ok := sourceIDs[aav.GetAction().GetId()]; ok {
					used[aav.GetAction().GetId()] = struct{}{}
				}
			}
		}
	}

	obligationTriggers, err := p.planner.retriever.retrieveObligationTriggers(ctx, sourceIDs)
	if err != nil {
		return nil, err
	}
	for _, trigger := range obligationTriggers {
		if trigger == nil || trigger.GetAction() == nil {
			continue
		}
		if _, ok := sourceIDs[trigger.GetAction().GetId()]; ok {
			used[trigger.GetAction().GetId()] = struct{}{}
		}
	}

	return used, nil
}

func (p *PrunePlanner) usedLegacySubjectConditionSetsByID(ctx context.Context, sourceIDs map[string]struct{}) (map[string]struct{}, error) {
	used := make(map[string]struct{}, len(sourceIDs))
	if len(sourceIDs) == 0 {
		return used, nil
	}

	subjectMappings, err := p.planner.retriever.retrieveSubjectMappings(ctx)
	if err != nil {
		return nil, err
	}
	for _, mapping := range subjectMappings {
		if mapping == nil || mapping.GetSubjectConditionSet() == nil {
			continue
		}
		scsID := mapping.GetSubjectConditionSet().GetId()
		if _, ok := sourceIDs[scsID]; ok {
			used[scsID] = struct{}{}
		}
	}

	return used, nil
}

func buildPrunePlanFromResolved(scope Scope, resolved *ResolvedTargets) (*PrunePlan, error) {
	if resolved == nil {
		return &PrunePlan{}, nil
	}

	builder := newPrunePlanBuilder(scope, resolved)
	return builder.build()
}

type prunePlanBuilder struct {
	scope    Scope
	resolved *ResolvedTargets
}

func newPrunePlanBuilder(scope Scope, resolved *ResolvedTargets) *prunePlanBuilder {
	return &prunePlanBuilder{
		scope:    scope,
		resolved: resolved,
	}
}

func (b *prunePlanBuilder) build() (*PrunePlan, error) {
	plan := &PrunePlan{
		Scope: b.scope,
	}
	if b.scope == ScopeSubjectMappings {
		subjectMappings, err := b.subjectMappings()
		if err != nil {
			return nil, err
		}
		plan.SubjectMappings = subjectMappings
	}
	if b.scope == ScopeRegisteredResources {
		registeredResources, err := b.registeredResources()
		if err != nil {
			return nil, err
		}
		plan.RegisteredResources = registeredResources
	}
	if b.scope == ScopeObligationTriggers {
		obligationTriggers, err := b.obligationTriggers()
		if err != nil {
			return nil, err
		}
		plan.ObligationTriggers = obligationTriggers
	}
	return plan, nil
}

func (b *prunePlanBuilder) subjectMappings() ([]*PruneSubjectMappingPlan, error) {
	plans := make([]*PruneSubjectMappingPlan, 0, len(b.resolved.SubjectMappings))

	for _, mapping := range b.resolved.SubjectMappings {
		if mapping == nil || mapping.Source == nil {
			continue
		}

		status, reason, err := pruneStatusForResolvedObject(mapping.Source, mapping.AlreadyMigrated)
		if err != nil {
			return nil, fmt.Errorf("subject mapping %q: %w", mapping.Source.GetId(), err)
		}
		plans = append(plans, &PruneSubjectMappingPlan{
			Source:         mapping.Source,
			Status:         status,
			MigratedTarget: migratedTarget(mapping.AlreadyMigrated, mapping.Namespace),
			Reason:         reason,
		})
	}

	return plans, nil
}

// registeredResources classifies each resolved RR prune decision directly from
// the resolved migration state. Multi-namespace legacy RRs are blocked when no
// migrated target exists because the migration planner cannot determine a single
// target namespace for them and prune cannot safely auto-delete them.
func (b *prunePlanBuilder) registeredResources() ([]*PruneRegisteredResourcePlan, error) {
	plans := make([]*PruneRegisteredResourcePlan, 0, len(b.resolved.RegisteredResources))

	for _, resource := range b.resolved.RegisteredResources {
		if resource == nil {
			continue
		}
		if resource.Source == nil {
			continue
		}

		if pruneManualDeleteRequired(resource) {
			plans = append(plans, &PruneRegisteredResourcePlan{
				Source:         resource.Source,
				Status:         PruneStatusBlocked,
				MigratedTarget: migratedTarget(resource.AlreadyMigrated, resource.Namespace),
				Reason: newPruneReason(
					PruneStatusReasonTypeMultiNamespaceManualDelete,
					pruneStatusReasonMessageMultiNamespaceManualDelete,
				),
			})
			continue
		}

		status, reason, err := pruneStatusForRegisteredResource(resource.Source, resource.AlreadyMigrated)
		if err != nil {
			return nil, fmt.Errorf("registered resource %q: %w", resource.Source.GetId(), err)
		}

		plans = append(plans, &PruneRegisteredResourcePlan{
			Source:         resource.Source,
			Status:         status,
			MigratedTarget: migratedTarget(resource.AlreadyMigrated, resource.Namespace),
			Reason:         reason,
		})
	}

	return plans, nil
}

func pruneManualDeleteRequired(resource *ResolvedRegisteredResource) bool {
	return resource != nil &&
		resource.AlreadyMigrated == nil &&
		resource.Unresolved != nil &&
		resource.Unresolved.Reason == UnresolvedReasonRegisteredResourceConflictingNamespaces
}

func (b *prunePlanBuilder) obligationTriggers() ([]*PruneObligationTriggerPlan, error) {
	plans := make([]*PruneObligationTriggerPlan, 0, len(b.resolved.ObligationTriggers))

	for _, trigger := range b.resolved.ObligationTriggers {
		if trigger == nil || trigger.Source == nil {
			continue
		}

		status, reason, err := pruneStatusForResolvedObject(trigger.Source, trigger.AlreadyMigrated)
		if err != nil {
			return nil, fmt.Errorf("obligation trigger %q: %w", trigger.Source.GetId(), err)
		}
		plans = append(plans, &PruneObligationTriggerPlan{
			Source:         trigger.Source,
			Status:         status,
			MigratedTarget: migratedTarget(trigger.AlreadyMigrated, trigger.Namespace),
			Reason:         reason,
		})
	}

	return plans, nil
}

func customLegacyActions(actions []*policy.Action) []*policy.Action {
	custom := make([]*policy.Action, 0, len(actions))
	for _, action := range actions {
		if action.GetId() == "" || isStandardAction(action) {
			continue
		}
		custom = append(custom, action)
	}
	return custom
}

func pruneStatusForAction(source *policy.Action, usedByID map[string]struct{}, targetNamespaces []*policy.Namespace, actionsByNamespace map[string][]*policy.Action) (PruneStatus, PruneStatusReason, []TargetRef, error) {
	targets, foundCanonical, labelsMatch, err := matchedActionTargets(source, targetNamespaces, actionsByNamespace)
	if err != nil {
		return "", PruneStatusReason{}, nil, err
	}
	_, used := usedByID[source.GetId()]
	status, reason, migratedTargets := pruneStatusForCanonicalTargets(used, foundCanonical, labelsMatch, targets)
	return status, reason, migratedTargets, nil
}

func matchedActionTargets(source *policy.Action, targetNamespaces []*policy.Namespace, actionsByNamespace map[string][]*policy.Action) ([]TargetRef, bool, bool, error) {
	targets := make([]TargetRef, 0)
	foundCanonical := false
	labelsMatch := false

	for _, namespace := range targetNamespaces {
		for _, target := range actionsByNamespace[namespace.GetId()] {
			if target == nil || !actionCanonicalEqual(source, target) {
				continue
			}
			if target.GetId() == "" {
				return nil, false, false, fmt.Errorf("%w: migrated target for source %q has empty id", ErrInvalidPruneResolvedTarget, source.GetId())
			}
			foundCanonical = true
			targets = append(targets, singleMigratedTarget(target.GetId(), namespace))
			if migratedFromID(target) == source.GetId() {
				labelsMatch = true
			}
			break
		}
	}

	return targets, foundCanonical, labelsMatch, nil
}

func pruneStatusForSubjectConditionSet(source *policy.SubjectConditionSet, usedByID map[string]struct{}, targetNamespaces []*policy.Namespace, scsByNamespace map[string][]*policy.SubjectConditionSet) (PruneStatus, PruneStatusReason, []TargetRef, error) {
	targets, foundCanonical, labelsMatch, err := matchedSubjectConditionSetTargets(source, targetNamespaces, scsByNamespace)
	if err != nil {
		return "", PruneStatusReason{}, nil, err
	}
	_, used := usedByID[source.GetId()]
	status, reason, migratedTargets := pruneStatusForCanonicalTargets(used, foundCanonical, labelsMatch, targets)
	return status, reason, migratedTargets, nil
}

func matchedSubjectConditionSetTargets(source *policy.SubjectConditionSet, targetNamespaces []*policy.Namespace, scsByNamespace map[string][]*policy.SubjectConditionSet) ([]TargetRef, bool, bool, error) {
	targets := make([]TargetRef, 0)
	foundCanonical := false
	labelsMatch := false

	for _, namespace := range targetNamespaces {
		for _, target := range scsByNamespace[namespace.GetId()] {
			if target == nil || !subjectConditionSetCanonicalEqual(source, target) {
				continue
			}
			if target.GetId() == "" {
				return nil, false, false, fmt.Errorf("%w: migrated target for source %q has empty id", ErrInvalidPruneResolvedTarget, source.GetId())
			}
			foundCanonical = true
			targets = append(targets, singleMigratedTarget(target.GetId(), namespace))
			if migratedFromID(target) == source.GetId() {
				labelsMatch = true
			}
			break
		}
	}

	return targets, foundCanonical, labelsMatch, nil
}

// For actions and subject condition sets, prune runs after legacy policy graph
// objects are expected to be gone, so the planner can no longer reliably infer
// which target namespace a source object was intended to migrate into. In that
// state, a canonical match is only operator context. Delete requires that no
// legacy object is still using the source and that at least one canonical match
// carries the expected migrated_from label; additional canonical matches may
// still appear in the returned targets without that label.
func pruneStatusForCanonicalTargets(used, foundCanonical, labelsMatch bool, targets []TargetRef) (PruneStatus, PruneStatusReason, []TargetRef) {
	if used {
		return PruneStatusBlocked, newPruneReason(PruneStatusReasonTypeInUse, pruneStatusReasonMessageInUse), targets
	}
	// No canonical migrated target means the source object was not represented in
	// any target namespace. For actions/SCS, that is more precise than
	// needs-migration because these objects may have been left unmigrated simply
	// because nothing depended on them.
	if !foundCanonical {
		return PruneStatusBlocked, newPruneReason(PruneStatusReasonTypeMigratedTargetNotFound, pruneStatusReasonMessageMigratedTargetNotFound), nil
	}
	if !labelsMatch {
		return PruneStatusUnresolved, newPruneReason(PruneStatusReasonTypeNoMatchingLabelsFound, pruneStatusReasonMessageNoMatchingLabelsFound), targets
	}
	return PruneStatusDelete, PruneStatusReason{}, targets
}

// target is expected to already be canonically equal to the source object.
// For subject mappings and obligation triggers, that canonical check happens in
// the resolver before AlreadyMigrated is set. For registered resources, prune
// verifies canonical equality against the authoritative full source in
// registeredResources before calling this helper.
func pruneStatusForMigratedObject(target pruneObject, sourceID string) (PruneStatus, PruneStatusReason, error) {
	if target.GetId() == "" {
		return "", PruneStatusReason{}, fmt.Errorf("%w: migrated target for source %q has empty id", ErrInvalidPruneResolvedTarget, sourceID)
	}
	if migratedFromID(target) != sourceID {
		return PruneStatusUnresolved, pruneStatusReasonForMigrationLabel(target), nil
	}
	return PruneStatusDelete, PruneStatusReason{}, nil
}

func pruneStatusForResolvedObject[S pruneSourceObject, T pruneMigratedObject](source S, alreadyMigrated T) (PruneStatus, PruneStatusReason, error) {
	if alreadyMigrated == nil {
		return PruneStatusBlocked, newPruneReason(PruneStatusReasonTypeNeedsMigration, pruneStatusReasonMessageNeedsMigration), nil
	}
	return pruneStatusForMigratedObject(alreadyMigrated, source.GetId())
}

func pruneStatusForRegisteredResource(source, alreadyMigrated *policy.RegisteredResource) (PruneStatus, PruneStatusReason, error) {
	if alreadyMigrated == nil {
		return PruneStatusBlocked, newPruneReason(PruneStatusReasonTypeNeedsMigration, pruneStatusReasonMessageNeedsMigration), nil
	}
	return pruneStatusForMigratedObject(alreadyMigrated, source.GetId())
}

func migratedFromID(item pruneObject) string {
	if item == nil {
		return ""
	}
	return strings.TrimSpace(item.GetMetadata().GetLabels()[migrationLabelMigratedFrom])
}

func singleMigratedTarget(existingID string, namespace *policy.Namespace) TargetRef {
	if existingID == "" {
		return TargetRef{}
	}
	return TargetRef{
		ID:           existingID,
		NamespaceID:  namespace.GetId(),
		NamespaceFQN: namespace.GetFqn(),
	}
}

func migratedTarget(target pruneObject, namespace *policy.Namespace) TargetRef {
	if target == nil {
		return TargetRef{}
	}
	return singleMigratedTarget(target.GetId(), namespace)
}

func newPruneReason(reasonType PruneStatusReasonType, message string) PruneStatusReason {
	if reasonType == "" && strings.TrimSpace(message) == "" {
		return PruneStatusReason{}
	}
	return PruneStatusReason{
		Type:    reasonType,
		Message: message,
	}
}

func pruneStatusReasonForMigrationLabel(target pruneObject) PruneStatusReason {
	if migratedFromID(target) == "" {
		return newPruneReason(PruneStatusReasonTypeMissingMigrationLabel, pruneStatusReasonMessageMissingMigrationLabel)
	}
	return newPruneReason(PruneStatusReasonTypeMismatchedMigrationLabel, pruneStatusReasonMessageMismatchedMigrationLabel)
}
