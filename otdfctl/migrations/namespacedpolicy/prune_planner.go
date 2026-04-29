package namespacedpolicy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
)

const (
	pruneStatusReasonMessageMigratedTargetNotFound              = "migrated target not found"
	pruneStatusReasonMessageInUse                               = "in-use"
	pruneStatusReasonMessageNoMatchingLabelsFound               = "no canonical migrated target had a matching migration label"
	pruneStatusReasonMessageMismatchedMigrationLabel            = "migrated target has mismatched migration label"
	pruneStatusReasonMessageMissingMigrationLabel               = "migrated target missing migration label"
	pruneStatusReasonMessageNeedsMigration                      = "needs-migration"
	pruneStatusReasonMessageRegisteredResourceSourceMismatchFmt = "source registered resource contains values outside resolved migration view for target namespace %q; manual review required before source deletion"
)

var (
	ErrMultiplePruneScopes        = errors.New("prune planner accepts exactly one scope")
	ErrInvalidPruneResolvedTarget = errors.New("invalid prune resolved target")
	ErrInvalidPruneResolvedSource = errors.New("invalid prune resolved source")
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
	planner *Planner
	scopes  scopeSet
}

type prunePlannerConfig struct {
	pageSize int32
	reviewer InteractiveReviewer
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
// migration planner infrastructure. Interactive review is still supported for
// the resolved-object scopes, and direct-prune scopes reuse the same retriever
// and namespace discovery logic.
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

	plannerOpts := []Option{WithPageSize(config.pageSize)}
	if config.reviewer != nil {
		plannerOpts = append(plannerOpts, WithInteractiveReviewer(config.reviewer))
	}

	planner, err := NewPlanner(handler, scopeCSV, plannerOpts...)
	if err != nil {
		return nil, err
	}

	return &PrunePlanner{
		planner: planner,
		scopes:  normalizedScopes,
	}, nil
}

func WithPrunePageSize(pageSize int32) PruneOption {
	return func(config *prunePlannerConfig) {
		config.pageSize = pageSize
	}
}

func WithPruneInteractiveReviewer(reviewer InteractiveReviewer) PruneOption {
	return func(config *prunePlannerConfig) {
		config.reviewer = reviewer
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
	if len(p.scopes) == 0 {
		return nil, ErrEmptyPlannerScope
	}
	if p.scopes.has(ScopeActions) {
		return p.planActions(ctx)
	}
	if p.scopes.has(ScopeSubjectConditionSets) {
		return p.planSubjectConditionSets(ctx)
	}

	resolved, err := p.planner.resolve(ctx)
	if err != nil {
		return nil, err
	}
	if resolved == nil {
		return nil, ErrNilResolvedTargets
	}

	sourceRegisteredResources, err := p.sourceRegisteredResources(ctx)
	if err != nil {
		return nil, err
	}

	return buildPrunePlanFromResolved(p.scopes, resolved, sourceRegisteredResources)
}

func (p *PrunePlanner) planActions(ctx context.Context) (*PrunePlan, error) {
	sourceActions, err := p.planner.retriever.retrieveActions(ctx)
	if err != nil {
		return nil, err
	}
	sourceActions = customLegacyActions(sourceActions)

	plan := &PrunePlan{
		Scopes:  p.scopes.ordered(),
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
		if source == nil || source.GetId() == "" {
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
		Scopes:               p.scopes.ordered(),
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

func (p *PrunePlanner) sourceRegisteredResources(ctx context.Context) (map[string]*policy.RegisteredResource, error) {
	if !p.scopes.has(ScopeRegisteredResources) {
		return map[string]*policy.RegisteredResource{}, nil
	}

	resources, err := p.planner.retriever.retrieveRegisteredResources(ctx)
	if err != nil {
		return nil, err
	}

	return sourceRegisteredResourcesByID(resources), nil
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

func buildPrunePlanFromResolved(scopes scopeSet, resolved *ResolvedTargets, sourceRegisteredResources map[string]*policy.RegisteredResource) (*PrunePlan, error) {
	if resolved == nil {
		return &PrunePlan{}, nil
	}

	builder := newPrunePlanBuilder(scopes, resolved, sourceRegisteredResources)
	return builder.build()
}

type prunePlanBuilder struct {
	scopes                    scopeSet
	resolved                  *ResolvedTargets
	sourceRegisteredResources map[string]*policy.RegisteredResource
}

func newPrunePlanBuilder(scopes scopeSet, resolved *ResolvedTargets, sourceRegisteredResources map[string]*policy.RegisteredResource) *prunePlanBuilder {
	return &prunePlanBuilder{
		scopes:                    scopes,
		resolved:                  resolved,
		sourceRegisteredResources: sourceRegisteredResources,
	}
}

func (b *prunePlanBuilder) build() (*PrunePlan, error) {
	plan := &PrunePlan{
		Scopes: b.scopes.ordered(),
	}
	if b.scopes.has(ScopeSubjectMappings) {
		subjectMappings, err := b.subjectMappings()
		if err != nil {
			return nil, err
		}
		plan.SubjectMappings = subjectMappings
	}
	if b.scopes.has(ScopeRegisteredResources) {
		registeredResources, err := b.registeredResources()
		if err != nil {
			return nil, err
		}
		plan.RegisteredResources = registeredResources
	}
	if b.scopes.has(ScopeObligationTriggers) {
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

// registeredResources verifies prune safety against the authoritative source RR.
// It first reloads the full source RR and marks the plan unresolved if the
// planner's resolved source is only a filtered view. For a full-source match, it
// then classifies the RR based on whether a migrated target exists and whether
// that target carries the expected migration metadata for the source RR.
func (b *prunePlanBuilder) registeredResources() ([]*PruneRegisteredResourcePlan, error) {
	plans := make([]*PruneRegisteredResourcePlan, 0, len(b.resolved.RegisteredResources))

	for _, resource := range b.resolved.RegisteredResources {
		if resource == nil {
			continue
		}
		if resource.Source == nil {
			continue
		}

		fullSource, err := b.registeredResourceSource(resource)
		if err != nil {
			return nil, err
		}

		if !registeredResourceCanonicalEqual(resource.Source, fullSource) {
			plans = append(plans, &PruneRegisteredResourcePlan{
				Source:         resource.Source,
				FullSource:     fullSource,
				Status:         PruneStatusUnresolved,
				MigratedTarget: migratedTarget(resource.AlreadyMigrated, resource.Namespace),
				Reason: newPruneReasonf(
					PruneStatusReasonTypeRegisteredResourceSourceMismatch,
					pruneStatusReasonMessageRegisteredResourceSourceMismatchFmt,
					namespaceLabel(resource.Namespace)),
			})
			continue
		}

		status, reason, err := pruneStatusForRegisteredResource(fullSource, resource.AlreadyMigrated)
		if err != nil {
			return nil, fmt.Errorf("registered resource %q: %w", resource.Source.GetId(), err)
		}

		plans = append(plans, &PruneRegisteredResourcePlan{
			Source:         resource.Source,
			FullSource:     fullSource,
			Status:         status,
			MigratedTarget: migratedTarget(resource.AlreadyMigrated, resource.Namespace),
			Reason:         reason,
		})
	}

	return plans, nil
}

func (b *prunePlanBuilder) registeredResourceSource(resource *ResolvedRegisteredResource) (*policy.RegisteredResource, error) {
	source := resource.Source
	if b.sourceRegisteredResources == nil {
		return nil, fmt.Errorf("%w: source registered resource verifier was not loaded", ErrInvalidPruneResolvedSource)
	}

	sourceID := source.GetId()
	if sourceID == "" {
		return nil, fmt.Errorf("%w: registered resource source has empty id", ErrInvalidPruneResolvedSource)
	}

	fullSource := b.sourceRegisteredResources[sourceID]
	if fullSource == nil {
		return nil, fmt.Errorf("%w: registered resource source %q not found during prune verification", ErrInvalidPruneResolvedSource, sourceID)
	}

	return fullSource, nil
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

func sourceRegisteredResourcesByID(resources []*policy.RegisteredResource) map[string]*policy.RegisteredResource {
	byID := make(map[string]*policy.RegisteredResource, len(resources))
	for _, resource := range resources {
		if resource == nil || resource.GetId() == "" {
			continue
		}
		byID[resource.GetId()] = resource
	}
	return byID
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

func newPruneReasonf(reasonType PruneStatusReasonType, format string, args ...any) PruneStatusReason {
	return newPruneReason(reasonType, fmt.Sprintf(format, args...))
}

func pruneStatusReasonForMigrationLabel(target pruneObject) PruneStatusReason {
	if migratedFromID(target) == "" {
		return newPruneReason(PruneStatusReasonTypeMissingMigrationLabel, pruneStatusReasonMessageMissingMigrationLabel)
	}
	return newPruneReason(PruneStatusReasonTypeMismatchedMigrationLabel, pruneStatusReasonMessageMismatchedMigrationLabel)
}
