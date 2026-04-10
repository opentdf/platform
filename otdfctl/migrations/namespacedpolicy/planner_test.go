package namespacedpolicy

import (
	"context"
	"testing"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlannerPlanMarksActionAlreadyMigratedWithoutMetadata(t *testing.T) {
	t.Parallel()

	targetNamespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	legacyAction := &policy.Action{
		Id:   "action-legacy",
		Name: "decrypt",
	}
	targetAction := &policy.Action{
		Id:        "action-target",
		Name:      "decrypt",
		Namespace: targetNamespace,
	}
	legacyMapping := &policy.SubjectMapping{
		Id: "mapping-legacy",
		Actions: []*policy.Action{
			{
				Id:   legacyAction.GetId(),
				Name: legacyAction.GetName(),
			},
		},
		AttributeValue: &policy.Value{
			Fqn: "https://example.com/attr/classification/value/secret",
		},
	}

	handler := &plannerTestHandler{
		actionsByNamespace: map[string]*actions.ListActionsResponse{
			"": {
				ActionsCustom: []*policy.Action{legacyAction},
				Pagination:    emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				ActionsCustom: []*policy.Action{targetAction},
				Pagination:    emptyPageResponse(),
			},
		},
		subjectMappingsByNamespace: map[string]*subjectmapping.ListSubjectMappingsResponse{
			"": {
				SubjectMappings: []*policy.SubjectMapping{legacyMapping},
				Pagination:      emptyPageResponse(),
			},
		},
		namespacesResponse: &namespaces.ListNamespacesResponse{
			Namespaces: []*policy.Namespace{targetNamespace},
			Pagination: emptyPageResponse(),
		},
	}

	planner, err := NewPlanner(handler, "actions")
	require.NoError(t, err)

	plan, err := planner.Plan(context.Background())
	require.NoError(t, err)
	require.Len(t, plan.Actions, 1)
	require.Len(t, plan.Actions[0].Targets, 1)

	assert.Equal(t, TargetStatusAlreadyMigrated, plan.Actions[0].Targets[0].Status)
	require.NotNil(t, plan.Actions[0].Targets[0].Existing)
	assert.Equal(t, targetAction.GetId(), plan.Actions[0].Targets[0].Existing.GetId())
	assert.Equal(t, []string{"", targetNamespace.GetId()}, handler.actionCalls)
	assert.Equal(t, []string{""}, handler.subjectMappingCalls)
}

func TestFinalizePlanAppliesOrderingAtBuildTime(t *testing.T) {
	t.Parallel()

	namespaceA := &policy.Namespace{
		Id:  "ns-a",
		Fqn: "https://example.com/a",
	}
	namespaceB := &policy.Namespace{
		Id:  "ns-b",
		Fqn: "https://example.com/b",
	}

	resolved := &ResolvedTargets{
		Scopes: []Scope{ScopeActions, ScopeSubjectConditionSets},
		Actions: []*ResolvedAction{
			{
				Source: &policy.Action{Id: "action-b", Name: "beta"},
				References: []*ActionReference{
					{Kind: ActionReferenceKindSubjectMapping, ID: "mapping-b", Namespace: namespaceB},
					{Kind: ActionReferenceKindRegisteredResource, ID: "resource-a", Namespace: namespaceA},
					{Kind: ActionReferenceKindSubjectMapping, ID: "mapping-a", Namespace: namespaceA},
				},
				Results: []*ResolvedActionResult{
					{Namespace: namespaceB, NeedsCreate: true},
					{Namespace: namespaceA, NeedsCreate: true},
				},
			},
			{
				Source: &policy.Action{Id: "action-a", Name: "alpha"},
				Results: []*ResolvedActionResult{
					{Namespace: namespaceB, NeedsCreate: true},
				},
			},
		},
		SubjectConditionSets: []*ResolvedSubjectConditionSet{
			{
				Source: &policy.SubjectConditionSet{Id: "scs-b"},
				Results: []*ResolvedSubjectConditionSetResult{
					{Namespace: namespaceB, NeedsCreate: true},
					{Namespace: namespaceA, NeedsCreate: true},
				},
			},
			{
				Source: &policy.SubjectConditionSet{Id: "scs-a"},
				Results: []*ResolvedSubjectConditionSetResult{
					{Namespace: namespaceB, NeedsCreate: true},
				},
			},
		},
	}

	plan, err := finalizePlan(resolved, []*policy.Namespace{namespaceA, namespaceB})
	require.NoError(t, err)

	require.Len(t, plan.Actions, 2)
	assert.Equal(t, "action-a", plan.Actions[0].Source.GetId())
	assert.Equal(t, "action-b", plan.Actions[1].Source.GetId())

	require.Len(t, plan.Actions[1].Targets, 2)
	assert.Equal(t, namespaceA.GetId(), plan.Actions[1].Targets[0].Namespace.GetId())
	assert.Equal(t, namespaceB.GetId(), plan.Actions[1].Targets[1].Namespace.GetId())

	require.Len(t, plan.Actions[1].References, 3)
	assert.Equal(t, ActionReferenceKindRegisteredResource, plan.Actions[1].References[0].Kind)
	assert.Equal(t, "resource-a", plan.Actions[1].References[0].ID)
	assert.Equal(t, ActionReferenceKindSubjectMapping, plan.Actions[1].References[1].Kind)
	assert.Equal(t, "mapping-a", plan.Actions[1].References[1].ID)
	assert.Equal(t, ActionReferenceKindSubjectMapping, plan.Actions[1].References[2].Kind)
	assert.Equal(t, "mapping-b", plan.Actions[1].References[2].ID)

	require.Len(t, plan.SubjectConditionSets, 2)
	assert.Equal(t, "scs-a", plan.SubjectConditionSets[0].Source.GetId())
	assert.Equal(t, "scs-b", plan.SubjectConditionSets[1].Source.GetId())

	require.Len(t, plan.SubjectConditionSets[1].Targets, 2)
	assert.Equal(t, namespaceA.GetId(), plan.SubjectConditionSets[1].Targets[0].Namespace.GetId())
	assert.Equal(t, namespaceB.GetId(), plan.SubjectConditionSets[1].Targets[1].Namespace.GetId())

	require.Len(t, plan.Namespaces, 2)
	assert.Equal(t, namespaceA.GetId(), plan.Namespaces[0].Namespace.GetId())
	assert.Equal(t, []string{"action-b"}, plan.Namespaces[0].Actions)
	assert.Equal(t, []string{"scs-b"}, plan.Namespaces[0].SubjectConditionSets)
	assert.Equal(t, namespaceB.GetId(), plan.Namespaces[1].Namespace.GetId())
	assert.Equal(t, []string{"action-a", "action-b"}, plan.Namespaces[1].Actions)
	assert.Equal(t, []string{"scs-a", "scs-b"}, plan.Namespaces[1].SubjectConditionSets)
}

func TestPlannerPlanDoesNotLeakSupportSubjectMappingsIntoActionScope(t *testing.T) {
	t.Parallel()

	targetNamespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	legacyCreate := &policy.Action{
		Id:   "action-create",
		Name: "create",
	}
	legacyRead := &policy.Action{
		Id:   "action-read",
		Name: "read",
	}
	legacyCustom := &policy.Action{
		Id:   "action-custom-1",
		Name: "custom_action_1",
	}
	legacySCS := &policy.SubjectConditionSet{
		Id: "scs-1",
	}
	resourceValue := &policy.RegisteredResourceValue{
		Id:       "resource-value-1",
		Resource: &policy.RegisteredResource{Id: "resource-1"},
		ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
			{
				Id: "aav-create",
				Action: &policy.Action{
					Id:   legacyCreate.GetId(),
					Name: legacyCreate.GetName(),
				},
				AttributeValue: &policy.Value{
					Attribute: &policy.Attribute{
						Namespace: targetNamespace,
					},
				},
			},
			{
				Id: "aav-custom",
				Action: &policy.Action{
					Id:   legacyCustom.GetId(),
					Name: legacyCustom.GetName(),
				},
				AttributeValue: &policy.Value{
					Attribute: &policy.Attribute{
						Namespace: targetNamespace,
					},
				},
			},
		},
	}
	legacyResource := &policy.RegisteredResource{
		Id:     "resource-1",
		Name:   "resource-1",
		Values: []*policy.RegisteredResourceValue{resourceValue},
	}
	legacyMapping := &policy.SubjectMapping{
		Id: "mapping-1",
		AttributeValue: &policy.Value{
			Attribute: &policy.Attribute{
				Namespace: targetNamespace,
			},
		},
		SubjectConditionSet: &policy.SubjectConditionSet{
			Id: legacySCS.GetId(),
		},
		Actions: []*policy.Action{
			{
				Id:   legacyRead.GetId(),
				Name: legacyRead.GetName(),
			},
		},
	}
	handler := &plannerTestHandler{
		actionsByNamespace: map[string]*actions.ListActionsResponse{
			"": {
				ActionsStandard: []*policy.Action{legacyCreate, legacyRead},
				ActionsCustom:   []*policy.Action{legacyCustom},
				Pagination:      emptyPageResponse(),
			},
			targetNamespace.GetId(): {
				ActionsStandard: []*policy.Action{
					{
						Id:        "target-create",
						Name:      legacyCreate.GetName(),
						Namespace: targetNamespace,
					},
				},
				Pagination: emptyPageResponse(),
			},
		},
		subjectConditionSetsByNamespace: map[string]*subjectmapping.ListSubjectConditionSetsResponse{
			"": {
				SubjectConditionSets: []*policy.SubjectConditionSet{legacySCS},
				Pagination:           emptyPageResponse(),
			},
		},
		subjectMappingsByNamespace: map[string]*subjectmapping.ListSubjectMappingsResponse{
			"": {
				SubjectMappings: []*policy.SubjectMapping{legacyMapping},
				Pagination:      emptyPageResponse(),
			},
		},
		registeredResourcesByNamespace: map[string]*registeredresources.ListRegisteredResourcesResponse{
			"": {
				Resources:  []*policy.RegisteredResource{legacyResource},
				Pagination: emptyPageResponse(),
			},
		},
		namespacesResponse: &namespaces.ListNamespacesResponse{
			Namespaces: []*policy.Namespace{targetNamespace},
			Pagination: emptyPageResponse(),
		},
	}

	planner, err := NewPlanner(handler, "subject-condition-sets,registered-resources")
	require.NoError(t, err)

	plan, err := planner.Plan(context.Background())
	require.NoError(t, err)

	assert.Equal(t, []Scope{ScopeActions, ScopeSubjectConditionSets, ScopeRegisteredResources}, plan.Scopes)
	assert.ElementsMatch(t, []string{legacyCreate.GetId(), legacyCustom.GetId()}, actionSourceIDs(plan.Actions))
	assert.NotContains(t, actionSourceIDs(plan.Actions), legacyRead.GetId())
	require.Len(t, plan.SubjectConditionSets, 1)
	assert.Equal(t, legacySCS.GetId(), plan.SubjectConditionSets[0].Source.GetId())
	assert.Equal(t, []string{"", targetNamespace.GetId()}, handler.actionCalls)
	assert.Equal(t, []string{""}, handler.subjectMappingCalls)
}

type plannerTestHandler struct {
	actionsByNamespace              map[string]*actions.ListActionsResponse
	subjectConditionSetsByNamespace map[string]*subjectmapping.ListSubjectConditionSetsResponse
	subjectMappingsByNamespace      map[string]*subjectmapping.ListSubjectMappingsResponse
	registeredResourcesByNamespace  map[string]*registeredresources.ListRegisteredResourcesResponse
	obligationTriggersByNamespace   map[string]*obligations.ListObligationTriggersResponse
	namespacesResponse              *namespaces.ListNamespacesResponse
	actionCalls                     []string
	subjectConditionSetCalls        []string
	subjectMappingCalls             []string
	registeredResourceCalls         []string
	obligationTriggerCalls          []string
}

func (h *plannerTestHandler) ListActions(_ context.Context, limit, offset int32, namespace string) (*actions.ListActionsResponse, error) {
	h.actionCalls = append(h.actionCalls, namespace)
	if resp, ok := h.actionsByNamespace[namespace]; ok {
		return resp, nil
	}
	return &actions.ListActionsResponse{Pagination: emptyPageResponse()}, nil
}

func (h *plannerTestHandler) ListSubjectConditionSets(_ context.Context, limit, offset int32, namespace string) (*subjectmapping.ListSubjectConditionSetsResponse, error) {
	h.subjectConditionSetCalls = append(h.subjectConditionSetCalls, namespace)
	if resp, ok := h.subjectConditionSetsByNamespace[namespace]; ok {
		return resp, nil
	}
	return &subjectmapping.ListSubjectConditionSetsResponse{Pagination: emptyPageResponse()}, nil
}

func (h *plannerTestHandler) ListSubjectMappings(_ context.Context, limit, offset int32, namespace string) (*subjectmapping.ListSubjectMappingsResponse, error) {
	h.subjectMappingCalls = append(h.subjectMappingCalls, namespace)
	if resp, ok := h.subjectMappingsByNamespace[namespace]; ok {
		return resp, nil
	}
	return &subjectmapping.ListSubjectMappingsResponse{Pagination: emptyPageResponse()}, nil
}

func (h *plannerTestHandler) ListRegisteredResources(_ context.Context, limit, offset int32, namespace string) (*registeredresources.ListRegisteredResourcesResponse, error) {
	h.registeredResourceCalls = append(h.registeredResourceCalls, namespace)
	if resp, ok := h.registeredResourcesByNamespace[namespace]; ok {
		return resp, nil
	}
	return &registeredresources.ListRegisteredResourcesResponse{Pagination: emptyPageResponse()}, nil
}

func (h *plannerTestHandler) ListObligationTriggers(_ context.Context, namespace string, limit, offset int32) (*obligations.ListObligationTriggersResponse, error) {
	h.obligationTriggerCalls = append(h.obligationTriggerCalls, namespace)
	if resp, ok := h.obligationTriggersByNamespace[namespace]; ok {
		return resp, nil
	}
	return &obligations.ListObligationTriggersResponse{Pagination: emptyPageResponse()}, nil
}

func (h *plannerTestHandler) ListNamespaces(_ context.Context, state common.ActiveStateEnum, limit, offset int32) (*namespaces.ListNamespacesResponse, error) {
	if h.namespacesResponse != nil {
		return h.namespacesResponse, nil
	}
	return &namespaces.ListNamespacesResponse{Pagination: emptyPageResponse()}, nil
}

func emptyPageResponse() *policy.PageResponse {
	return &policy.PageResponse{}
}

func actionSourceIDs(actions []*ActionPlan) []string {
	ids := make([]string, 0, len(actions))
	for _, action := range actions {
		if action == nil || action.Source == nil {
			continue
		}
		ids = append(ids, action.Source.GetId())
	}

	return ids
}
