package namespacedpolicy

import (
	"context"
	"errors"
	"fmt"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
)

var (
	_ pagedResponse = (*actions.ListActionsResponse)(nil)
	_ pagedResponse = (*subjectmapping.ListSubjectConditionSetsResponse)(nil)
	_ pagedResponse = (*subjectmapping.ListSubjectMappingsResponse)(nil)
	_ pagedResponse = (*registeredresources.ListRegisteredResourcesResponse)(nil)
	_ pagedResponse = (*obligations.ListObligationTriggersResponse)(nil)
	_ pagedResponse = (*namespaces.ListNamespacesResponse)(nil)
)

type pagedResponse interface {
	GetPagination() *policy.PageResponse
}

type Retriever struct {
	handler  PolicyClient
	pageSize int32
}

func newRetriever(handler PolicyClient, pageSize int32) *Retriever {
	return &Retriever{
		handler:  handler,
		pageSize: pageSize,
	}
}

func (r *Retriever) retrieve(ctx context.Context, scopes scopeSet) (*Retrieved, error) {
	retrieved := newRetrieved(scopes.ordered())

	if scopes.requiresSubjectMappings() {
		candidates, err := r.retrieveSubjectMappings(ctx)
		if err != nil {
			return nil, err
		}
		retrieved.Candidates.SubjectMappings = candidates
	}

	if scopes.requiresSubjectConditionSets() {
		candidates, err := r.retrieveSubjectConditionSets(ctx)
		if err != nil {
			return nil, err
		}
		retrieved.Candidates.SubjectConditionSets = candidates
	}

	if scopes.requiresActions() {
		candidates, err := r.retrieveActions(ctx)
		if err != nil {
			return nil, err
		}
		retrieved.Candidates.Actions = candidates
	}

	if scopes.requiresRegisteredResources() {
		candidates, err := r.retrieveRegisteredResources(ctx)
		if err != nil {
			return nil, err
		}
		retrieved.Candidates.RegisteredResources = candidates
	}

	if scopes.requiresObligationTriggers() {
		candidates, err := r.retrieveObligationTriggers(ctx)
		if err != nil {
			return nil, err
		}
		retrieved.Candidates.ObligationTriggers = candidates
	}

	return retrieved, nil
}

func (r *Retriever) listNamespaces(ctx context.Context) ([]*policy.Namespace, error) {
	var (
		all    []*policy.Namespace
		offset int32
	)

	for {
		resp, err := r.handler.ListNamespaces(ctx, common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE, r.pageSize, offset)
		if err != nil {
			return nil, fmt.Errorf("list namespaces: %w", err)
		}

		items := resp.GetNamespaces()
		if len(items) == 0 {
			break
		}

		all = append(all, items...)

		nextOffset, err := nextOffsetFromPage(resp)
		if err != nil {
			return nil, fmt.Errorf("list namespaces: %w", err)
		}
		if nextOffset <= 0 {
			break
		}
		offset = nextOffset
	}

	return all, nil
}

func (r *Retriever) listExistingTargets(ctx context.Context, scopes scopeSet, derived *DerivedTargets) (*ExistingTargets, error) {
	existing := newExistingTargets()

	if scopes.requiresActions() {
		customActions, standardActions, err := r.listActionsForNamespaces(ctx, derivedActionNamespaces(derived))
		if err != nil {
			return nil, err
		}
		existing.CustomActions = customActions
		existing.StandardActions = standardActions
	}

	if scopes.requiresSubjectConditionSets() {
		subjectConditionSets, err := r.listSubjectConditionSetsForNamespaces(ctx, derivedSubjectConditionSetNamespaces(derived))
		if err != nil {
			return nil, err
		}
		existing.SubjectConditionSets = subjectConditionSets
	}

	if scopes.has(ScopeSubjectMappings) {
		subjectMappings, err := r.listSubjectMappingsForNamespaces(ctx, derivedSubjectMappingNamespaces(derived))
		if err != nil {
			return nil, err
		}
		existing.SubjectMappings = subjectMappings
	}

	if scopes.has(ScopeRegisteredResources) {
		registeredResources, err := r.listRegisteredResourcesForNamespaces(ctx, derivedRegisteredResourceNamespaces(derived))
		if err != nil {
			return nil, err
		}
		existing.RegisteredResources = registeredResources
	}

	if scopes.has(ScopeObligationTriggers) {
		obligationTriggers, err := r.listObligationTriggersForNamespaces(ctx, derivedObligationTriggerNamespaces(derived))
		if err != nil {
			return nil, err
		}
		existing.ObligationTriggers = obligationTriggers
	}

	return existing, nil
}

func (r *Retriever) retrieveSubjectMappings(ctx context.Context) ([]*policy.SubjectMapping, error) {
	var (
		candidates []*policy.SubjectMapping
		offset     int32
	)

	for {
		resp, err := r.handler.ListSubjectMappings(ctx, r.pageSize, offset, "")
		if err != nil {
			return nil, fmt.Errorf("list subject mappings: %w", err)
		}

		items := resp.GetSubjectMappings()
		if len(items) == 0 {
			break
		}

		for _, mapping := range items {
			if mapping.GetId() == "" || !isLegacyNamespace(mapping.GetNamespace()) || hasObject(candidates, mapping.GetId()) {
				continue
			}
			candidates = append(candidates, mapping)
		}

		nextOffset, err := nextOffsetFromPage(resp)
		if err != nil {
			return nil, fmt.Errorf("list subject mappings: %w", err)
		}
		if nextOffset <= 0 {
			break
		}
		offset = nextOffset
	}

	return candidates, nil
}

func (r *Retriever) retrieveSubjectConditionSets(ctx context.Context) ([]*policy.SubjectConditionSet, error) {
	var candidates []*policy.SubjectConditionSet
	var offset int32

	for {
		resp, err := r.handler.ListSubjectConditionSets(ctx, r.pageSize, offset, "")
		if err != nil {
			return nil, fmt.Errorf("list subject condition sets: %w", err)
		}

		items := resp.GetSubjectConditionSets()
		if len(items) == 0 {
			break
		}

		for _, scs := range items {
			if scs.GetId() == "" {
				continue
			}
			if isLegacyNamespace(scs.GetNamespace()) && !hasObject(candidates, scs.GetId()) {
				candidates = append(candidates, scs)
			}
		}

		nextOffset, err := nextOffsetFromPage(resp)
		if err != nil {
			return nil, fmt.Errorf("list subject condition sets: %w", err)
		}
		if nextOffset <= 0 {
			break
		}
		offset = nextOffset
	}

	return candidates, nil
}

func (r *Retriever) retrieveRegisteredResources(ctx context.Context) ([]*policy.RegisteredResource, error) {
	var (
		candidates []*policy.RegisteredResource
		offset     int32
	)

	for {
		resp, err := r.handler.ListRegisteredResources(ctx, r.pageSize, offset, "")
		if err != nil {
			return nil, fmt.Errorf("list registered resources: %w", err)
		}

		items := resp.GetResources()
		if len(items) == 0 {
			break
		}

		for _, resource := range items {
			if resource.GetId() == "" || !isLegacyNamespace(resource.GetNamespace()) || hasObject(candidates, resource.GetId()) {
				continue
			}
			candidates = append(candidates, resource)
		}

		nextOffset, err := nextOffsetFromPage(resp)
		if err != nil {
			return nil, fmt.Errorf("list registered resources: %w", err)
		}
		if nextOffset <= 0 {
			break
		}
		offset = nextOffset
	}

	return candidates, nil
}

func (r *Retriever) retrieveActions(ctx context.Context) ([]*policy.Action, error) {
	var candidates []*policy.Action
	var offset int32

	for {
		resp, err := r.handler.ListActions(ctx, r.pageSize, offset, "")
		if err != nil {
			return nil, fmt.Errorf("list actions: %w", err)
		}

		if len(resp.GetActionsStandard()) == 0 && len(resp.GetActionsCustom()) == 0 {
			break
		}

		for _, action := range resp.GetActionsStandard() {
			if action.GetId() == "" {
				continue
			}
			if isLegacyNamespace(action.GetNamespace()) {
				if !hasObject(candidates, action.GetId()) {
					candidates = append(candidates, action)
				}
				continue
			}
		}

		for _, action := range resp.GetActionsCustom() {
			if action.GetId() == "" {
				continue
			}
			if isLegacyNamespace(action.GetNamespace()) {
				if !hasObject(candidates, action.GetId()) {
					candidates = append(candidates, action)
				}
				continue
			}
		}

		nextOffset, err := nextOffsetFromPage(resp)
		if err != nil {
			return nil, fmt.Errorf("list actions: %w", err)
		}
		if nextOffset <= 0 {
			break
		}
		offset = nextOffset
	}

	return candidates, nil
}

func (r *Retriever) retrieveObligationTriggers(ctx context.Context) ([]*policy.ObligationTrigger, error) {
	var (
		candidates []*policy.ObligationTrigger
		offset     int32
	)

	for {
		resp, err := r.handler.ListObligationTriggers(ctx, "", r.pageSize, offset)
		if err != nil {
			return nil, fmt.Errorf("list obligation triggers: %w", err)
		}

		items := resp.GetTriggers()
		if len(items) == 0 {
			break
		}

		for _, trigger := range items {
			if trigger.GetId() == "" || trigger.GetAction() == nil || !isLegacyNamespace(trigger.GetAction().GetNamespace()) || hasObject(candidates, trigger.GetId()) {
				continue
			}
			candidates = append(candidates, trigger)
		}

		nextOffset, err := nextOffsetFromPage(resp)
		if err != nil {
			return nil, fmt.Errorf("list obligation triggers: %w", err)
		}
		if nextOffset <= 0 {
			break
		}
		offset = nextOffset
	}

	return candidates, nil
}

func (r *Retriever) listActionsForNamespaces(ctx context.Context, namespaces []*policy.Namespace) (map[string][]*policy.Action, map[string][]*policy.Action, error) {
	customByNamespace := make(map[string][]*policy.Action)
	standardByNamespace := make(map[string][]*policy.Action)

	for _, namespace := range dedupeTargetNamespaces(namespaces) {
		var offset int32
		for {
			resp, err := r.handler.ListActions(ctx, r.pageSize, offset, namespace.GetId())
			if err != nil {
				return nil, nil, fmt.Errorf("list actions for namespace %s: %w", namespace.GetId(), err)
			}

			for _, action := range resp.GetActionsCustom() {
				if action.GetId() == "" || hasObject(customByNamespace[namespace.GetId()], action.GetId()) {
					continue
				}
				customByNamespace[namespace.GetId()] = append(customByNamespace[namespace.GetId()], action)
			}
			for _, action := range resp.GetActionsStandard() {
				if action.GetId() == "" || hasObject(standardByNamespace[namespace.GetId()], action.GetId()) {
					continue
				}
				standardByNamespace[namespace.GetId()] = append(standardByNamespace[namespace.GetId()], action)
			}

			nextOffset, err := nextOffsetFromPage(resp)
			if err != nil {
				return nil, nil, fmt.Errorf("list actions for namespace %s: %w", namespace.GetId(), err)
			}
			if nextOffset <= 0 {
				break
			}
			offset = nextOffset
		}
	}

	return customByNamespace, standardByNamespace, nil
}

func (r *Retriever) listSubjectConditionSetsForNamespaces(ctx context.Context, namespaces []*policy.Namespace) (map[string][]*policy.SubjectConditionSet, error) {
	byNamespace := make(map[string][]*policy.SubjectConditionSet)

	for _, namespace := range dedupeTargetNamespaces(namespaces) {
		var offset int32
		for {
			resp, err := r.handler.ListSubjectConditionSets(ctx, r.pageSize, offset, namespace.GetId())
			if err != nil {
				return nil, fmt.Errorf("list subject condition sets for namespace %s: %w", namespace.GetId(), err)
			}

			for _, scs := range resp.GetSubjectConditionSets() {
				if scs.GetId() == "" || hasObject(byNamespace[namespace.GetId()], scs.GetId()) {
					continue
				}
				byNamespace[namespace.GetId()] = append(byNamespace[namespace.GetId()], scs)
			}

			nextOffset, err := nextOffsetFromPage(resp)
			if err != nil {
				return nil, fmt.Errorf("list subject condition sets for namespace %s: %w", namespace.GetId(), err)
			}
			if nextOffset <= 0 {
				break
			}
			offset = nextOffset
		}
	}

	return byNamespace, nil
}

func (r *Retriever) listSubjectMappingsForNamespaces(ctx context.Context, namespaces []*policy.Namespace) (map[string][]*policy.SubjectMapping, error) {
	byNamespace := make(map[string][]*policy.SubjectMapping)

	for _, namespace := range dedupeTargetNamespaces(namespaces) {
		var offset int32
		for {
			resp, err := r.handler.ListSubjectMappings(ctx, r.pageSize, offset, namespace.GetId())
			if err != nil {
				return nil, fmt.Errorf("list subject mappings for namespace %s: %w", namespace.GetId(), err)
			}

			for _, mapping := range resp.GetSubjectMappings() {
				if mapping.GetId() == "" || hasObject(byNamespace[namespace.GetId()], mapping.GetId()) {
					continue
				}
				byNamespace[namespace.GetId()] = append(byNamespace[namespace.GetId()], mapping)
			}

			nextOffset, err := nextOffsetFromPage(resp)
			if err != nil {
				return nil, fmt.Errorf("list subject mappings for namespace %s: %w", namespace.GetId(), err)
			}
			if nextOffset <= 0 {
				break
			}
			offset = nextOffset
		}
	}

	return byNamespace, nil
}

func (r *Retriever) listRegisteredResourcesForNamespaces(ctx context.Context, namespaces []*policy.Namespace) (map[string][]*policy.RegisteredResource, error) {
	byNamespace := make(map[string][]*policy.RegisteredResource)

	for _, namespace := range dedupeTargetNamespaces(namespaces) {
		var offset int32
		for {
			resp, err := r.handler.ListRegisteredResources(ctx, r.pageSize, offset, namespace.GetId())
			if err != nil {
				return nil, fmt.Errorf("list registered resources for namespace %s: %w", namespace.GetId(), err)
			}

			for _, resource := range resp.GetResources() {
				if resource.GetId() == "" || hasObject(byNamespace[namespace.GetId()], resource.GetId()) {
					continue
				}
				byNamespace[namespace.GetId()] = append(byNamespace[namespace.GetId()], resource)
			}

			nextOffset, err := nextOffsetFromPage(resp)
			if err != nil {
				return nil, fmt.Errorf("list registered resources for namespace %s: %w", namespace.GetId(), err)
			}
			if nextOffset <= 0 {
				break
			}
			offset = nextOffset
		}
	}

	return byNamespace, nil
}

func (r *Retriever) listObligationTriggersForNamespaces(ctx context.Context, namespaces []*policy.Namespace) (map[string][]*policy.ObligationTrigger, error) {
	byNamespace := make(map[string][]*policy.ObligationTrigger)

	for _, namespace := range dedupeTargetNamespaces(namespaces) {
		var offset int32
		for {
			resp, err := r.handler.ListObligationTriggers(ctx, namespace.GetId(), r.pageSize, offset)
			if err != nil {
				return nil, fmt.Errorf("list obligation triggers for namespace %s: %w", namespace.GetId(), err)
			}

			for _, trigger := range resp.GetTriggers() {
				if trigger.GetId() == "" || hasObject(byNamespace[namespace.GetId()], trigger.GetId()) {
					continue
				}
				byNamespace[namespace.GetId()] = append(byNamespace[namespace.GetId()], trigger)
			}

			nextOffset, err := nextOffsetFromPage(resp)
			if err != nil {
				return nil, fmt.Errorf("list obligation triggers for namespace %s: %w", namespace.GetId(), err)
			}
			if nextOffset <= 0 {
				break
			}
			offset = nextOffset
		}
	}

	return byNamespace, nil
}

func dedupeTargetNamespaces(namespaces []*policy.Namespace) []*policy.Namespace {
	deduped := make([]*policy.Namespace, 0, len(namespaces))
	seen := make(map[string]struct{}, len(namespaces))

	for _, namespace := range namespaces {
		if namespace == nil || namespace.GetId() == "" {
			continue
		}
		if _, ok := seen[namespace.GetId()]; ok {
			continue
		}
		seen[namespace.GetId()] = struct{}{}
		deduped = append(deduped, namespace)
	}

	return deduped
}

func isLegacyNamespace(namespace *policy.Namespace) bool {
	return namespace == nil || (namespace.GetId() == "" && namespace.GetFqn() == "")
}

func namespaceRefKey(namespace *policy.Namespace) string {
	if namespace == nil {
		return ""
	}
	if id := namespace.GetId(); id != "" {
		return "id:" + id
	}
	if fqn := namespace.GetFqn(); fqn != "" {
		return "fqn:" + fqn
	}
	return ""
}

func nextOffsetFromPage(resp pagedResponse) (int32, error) {
	page := resp.GetPagination()
	if page == nil {
		return 0, errors.New("missing pagination in response")
	}

	return page.GetNextOffset(), nil
}
