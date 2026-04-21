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

func TestRetrieverRetrieveActionsFiltersLegacyAndDedupes(t *testing.T) {
	t.Parallel()

	handler := &plannerTestHandler{
		actionsByNamespace: map[string]*actions.ListActionsResponse{
			"": {
				ActionsStandard: []*policy.Action{
					{Id: "action-dup", Name: "read"},
					{
						Id:        "action-namespaced",
						Name:      "write",
						Namespace: &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"},
					},
				},
				ActionsCustom: []*policy.Action{
					{Id: "action-dup", Name: "read"},
					{Id: "action-custom", Name: "decrypt"},
				},
				Pagination: emptyPageResponse(),
			},
		},
	}

	actions, err := newRetriever(handler, 25).retrieveActions(t.Context())
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{"action-dup", "action-custom"}, policyObjectIDs(actions))
	assert.Equal(t, []string{""}, handler.actionCalls)
}

func TestRetrieverListRegisteredResourcesForNamespacesDedupesNamespacesAndHydratesValues(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	inlineValue := &policy.RegisteredResourceValue{Value: "inline-value"}
	value := &policy.RegisteredResourceValue{
		Id:    "value-1",
		Value: "prod",
		Metadata: &common.Metadata{
			Labels: map[string]string{
				"owner": "platform",
			},
		},
		ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
			testActionAttributeValue(
				"action-1",
				"decrypt",
				testAttributeValue("https://example.com/attr/classification/value/secret", nil),
			),
		},
	}
	resource := &policy.RegisteredResource{
		Id:     "resource-1",
		Name:   "documents",
		Values: []*policy.RegisteredResourceValue{inlineValue},
	}
	handler := &plannerTestHandler{
		registeredResourcesByNamespace: map[string]*registeredresources.ListRegisteredResourcesResponse{
			namespace.GetId(): {
				Resources:  []*policy.RegisteredResource{resource},
				Pagination: emptyPageResponse(),
			},
		},
		registeredResourceValuesByResourceID: map[string]*registeredresources.ListRegisteredResourceValuesResponse{
			resource.GetId(): {
				Values:     []*policy.RegisteredResourceValue{value},
				Pagination: emptyPageResponse(),
			},
		},
	}

	resources, err := newRetriever(handler, 25).listRegisteredResourcesForNamespaces(
		context.Background(),
		[]*policy.Namespace{namespace, namespace},
	)
	require.NoError(t, err)

	require.Contains(t, resources, namespace.GetId())
	require.Len(t, resources[namespace.GetId()], 1)
	assert.Equal(t, resource.GetId(), resources[namespace.GetId()][0].GetId())
	require.Len(t, resources[namespace.GetId()][0].GetValues(), 1)
	assert.Equal(t, "prod", resources[namespace.GetId()][0].GetValues()[0].GetValue())
	assert.Equal(t, map[string]string{"owner": "platform"}, resources[namespace.GetId()][0].GetValues()[0].GetMetadata().GetLabels())
	assert.Equal(t, []string{namespace.GetId()}, handler.registeredResourceCalls)
	assert.Equal(t, []string{resource.GetId()}, handler.registeredResourceValueCalls)
}

func TestRetrieverRetrieveSubjectMappingsDedupesAcrossPages(t *testing.T) {
	t.Parallel()

	handler := &pagedRetrieveTestHandler{
		subjectMappingPages: map[int32]*subjectmapping.ListSubjectMappingsResponse{
			0: {
				SubjectMappings: []*policy.SubjectMapping{
					{Id: "mapping-dup"},
					{
						Id:        "mapping-namespaced",
						Namespace: &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"},
					},
				},
				Pagination: pageResponse(1),
			},
			1: {
				SubjectMappings: []*policy.SubjectMapping{
					{Id: "mapping-dup"},
					{Id: "mapping-new"},
					{Id: ""},
				},
				Pagination: emptyPageResponse(),
			},
		},
	}

	mappings, err := newRetriever(handler, 25).retrieveSubjectMappings(t.Context())
	require.NoError(t, err)

	assert.Equal(t, []string{"mapping-dup", "mapping-new"}, policyObjectIDs(mappings))
}

func TestRetrieverRetrieveRegisteredResourcesDedupesAcrossPages(t *testing.T) {
	t.Parallel()

	valueDup := &policy.RegisteredResourceValue{
		Id:    "resource-dup-value-1",
		Value: "prod",
		Metadata: &common.Metadata{
			Labels: map[string]string{
				"owner": "policy-team",
			},
		},
	}
	handler := &pagedRetrieveTestHandler{
		registeredResourcePages: map[int32]*registeredresources.ListRegisteredResourcesResponse{
			0: {
				Resources: []*policy.RegisteredResource{
					{Id: "resource-dup", Name: "documents", Values: []*policy.RegisteredResourceValue{{Value: "inline"}}},
					{
						Id:        "resource-namespaced",
						Name:      "contracts",
						Namespace: &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"},
					},
				},
				Pagination: pageResponse(1),
			},
			1: {
				Resources: []*policy.RegisteredResource{
					{Id: "resource-dup", Name: "documents"},
					{Id: "resource-new", Name: "reports"},
					{Id: "", Name: "missing-id"},
				},
				Pagination: emptyPageResponse(),
			},
		},
		registeredResourceValuePages: map[string]map[int32]*registeredresources.ListRegisteredResourceValuesResponse{
			"resource-dup": {
				0: {
					Values:     []*policy.RegisteredResourceValue{valueDup},
					Pagination: emptyPageResponse(),
				},
			},
			"resource-new": {
				0: {
					Values:     []*policy.RegisteredResourceValue{{Id: "resource-new-value-1", Value: "reports"}},
					Pagination: emptyPageResponse(),
				},
			},
		},
	}

	resources, err := newRetriever(handler, 25).retrieveRegisteredResources(t.Context())
	require.NoError(t, err)

	assert.Equal(t, []string{"resource-dup", "resource-new"}, policyObjectIDs(resources))
	require.Len(t, resources[0].GetValues(), 1)
	assert.Equal(t, "prod", resources[0].GetValues()[0].GetValue())
	assert.Equal(t, map[string]string{"owner": "policy-team"}, resources[0].GetValues()[0].GetMetadata().GetLabels())
	assert.Equal(t, []string{"resource-dup", "resource-new"}, handler.registeredResourceValueCalls)
}

func TestRetrieverListExistingTargetsFiltersObligationTriggersByNamespacedActionIDs(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	handler := &plannerTestHandler{
		actionsByNamespace: map[string]*actions.ListActionsResponse{
			namespace.GetId(): {
				ActionsCustom: []*policy.Action{
					{
						Id:        "action-target",
						Name:      "decrypt",
						Namespace: namespace,
					},
				},
				Pagination: emptyPageResponse(),
			},
		},
		obligationTriggersByNamespace: map[string]*obligations.ListObligationTriggersResponse{
			namespace.GetId(): {
				Triggers: []*policy.ObligationTrigger{
					{
						Id: "trigger-legacy-action",
						Action: &policy.Action{
							Id:   "action-legacy",
							Name: "decrypt-2",
						},
					},
					{
						Id: "trigger-target-action",
						Action: &policy.Action{
							Id:   "action-target",
							Name: "decrypt",
						},
					},
				},
				Pagination: emptyPageResponse(),
			},
		},
	}

	scopes, err := normalizeScopes([]Scope{ScopeActions, ScopeObligationTriggers})
	require.NoError(t, err)

	existing, err := newRetriever(handler, 25).listExistingTargets(t.Context(), scopes, &DerivedTargets{
		Actions: []*DerivedAction{
			{Targets: []*policy.Namespace{namespace}},
		},
		ObligationTriggers: []*DerivedObligationTrigger{
			{Target: namespace},
		},
	})
	require.NoError(t, err)

	require.Contains(t, existing.ObligationTriggers, namespace.GetId())
	assert.Equal(t, []string{"trigger-target-action"}, policyObjectIDs(existing.ObligationTriggers[namespace.GetId()]))
	assert.Equal(t, []string{namespace.GetId()}, handler.actionCalls)
	assert.Equal(t, []string{namespace.GetId()}, handler.obligationTriggerCalls)
}

func TestRetrieverListObligationTriggersForNamespacesFailsWhenNamespaceMissingFromActionMap(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}

	_, err := newRetriever(&pagedRetrieveTestHandler{}, 25).listObligationTriggersForNamespaces(
		context.Background(),
		[]*policy.Namespace{namespace},
		map[string]map[string]struct{}{},
	)
	require.Error(t, err)
	assert.EqualError(t, err, `obligation trigger existing-target lookup for namespace "ns-1" is missing action candidates`)
}

func TestRetrieverRetrieveObligationTriggersUsesListActionsToFilterLegacyActionIDs(t *testing.T) {
	t.Parallel()

	handler := &pagedRetrieveTestHandler{
		actionPages: map[int32]*actions.ListActionsResponse{
			0: {
				ActionsCustom: []*policy.Action{
					{Id: "action-1", Name: "decrypt"},
					{Id: "action-3", Name: "encrypt"},
				},
				ActionsStandard: []*policy.Action{
					{
						Id:        "action-2",
						Name:      "decrypt",
						Namespace: &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"},
					},
				},
				Pagination: emptyPageResponse(),
			},
		},
		obligationTriggerPages: map[int32]*obligations.ListObligationTriggersResponse{
			0: {
				Triggers: []*policy.ObligationTrigger{
					{
						Id:     "trigger-dup",
						Action: &policy.Action{Id: "action-1", Name: "decrypt"},
					},
					{
						Id:     "trigger-non-legacy",
						Action: &policy.Action{Id: "action-2", Name: "decrypt"},
					},
				},
				Pagination: pageResponse(1),
			},
			1: {
				Triggers: []*policy.ObligationTrigger{
					{
						Id:     "trigger-dup",
						Action: &policy.Action{Id: "action-1", Name: "decrypt"},
					},
					{
						Id:     "trigger-new",
						Action: &policy.Action{Id: "action-3", Name: "encrypt"},
					},
					{
						Id:     "",
						Action: &policy.Action{Id: "action-4", Name: "read"},
					},
				},
				Pagination: emptyPageResponse(),
			},
		},
	}

	scopes, err := normalizeScopes([]Scope{ScopeObligationTriggers})
	require.NoError(t, err)

	retrieved, err := newRetriever(handler, 25).retrieve(t.Context(), scopes)
	require.NoError(t, err)

	assert.Equal(t, []string{"action-1", "action-3"}, policyObjectIDs(retrieved.Candidates.Actions))
	assert.Equal(t, []string{"trigger-dup", "trigger-new"}, policyObjectIDs(retrieved.Candidates.ObligationTriggers))
}

func policyObjectIDs[T interface{ GetId() string }](items []T) []string {
	ids := make([]string, 0, len(items))
	for _, item := range items {
		if item.GetId() == "" {
			continue
		}
		ids = append(ids, item.GetId())
	}

	return ids
}

type pagedRetrieveTestHandler struct {
	actionPages                  map[int32]*actions.ListActionsResponse
	subjectMappingPages          map[int32]*subjectmapping.ListSubjectMappingsResponse
	registeredResourcePages      map[int32]*registeredresources.ListRegisteredResourcesResponse
	registeredResourceValuePages map[string]map[int32]*registeredresources.ListRegisteredResourceValuesResponse
	obligationTriggerPages       map[int32]*obligations.ListObligationTriggersResponse
	registeredResourceValueCalls []string
}

func (h *pagedRetrieveTestHandler) ListActions(_ context.Context, limit, offset int32, namespace string) (*actions.ListActionsResponse, error) {
	if resp, ok := h.actionPages[offset]; ok {
		return resp, nil
	}
	return &actions.ListActionsResponse{Pagination: emptyPageResponse()}, nil
}

func (h *pagedRetrieveTestHandler) ListSubjectConditionSets(_ context.Context, limit, offset int32, namespace string) (*subjectmapping.ListSubjectConditionSetsResponse, error) {
	return &subjectmapping.ListSubjectConditionSetsResponse{Pagination: emptyPageResponse()}, nil
}

func (h *pagedRetrieveTestHandler) ListSubjectMappings(_ context.Context, limit, offset int32, namespace string) (*subjectmapping.ListSubjectMappingsResponse, error) {
	if resp, ok := h.subjectMappingPages[offset]; ok {
		return resp, nil
	}
	return &subjectmapping.ListSubjectMappingsResponse{Pagination: emptyPageResponse()}, nil
}

func (h *pagedRetrieveTestHandler) ListRegisteredResources(_ context.Context, limit, offset int32, namespace string) (*registeredresources.ListRegisteredResourcesResponse, error) {
	if resp, ok := h.registeredResourcePages[offset]; ok {
		return resp, nil
	}
	return &registeredresources.ListRegisteredResourcesResponse{Pagination: emptyPageResponse()}, nil
}

func (h *pagedRetrieveTestHandler) ListRegisteredResourceValues(_ context.Context, resourceID string, limit, offset int32) (*registeredresources.ListRegisteredResourceValuesResponse, error) {
	h.registeredResourceValueCalls = append(h.registeredResourceValueCalls, resourceID)
	if pages, ok := h.registeredResourceValuePages[resourceID]; ok {
		if resp, exists := pages[offset]; exists {
			return resp, nil
		}
	}

	for _, resp := range h.registeredResourcePages {
		for _, resource := range resp.GetResources() {
			if resource.GetId() != resourceID {
				continue
			}
			return &registeredresources.ListRegisteredResourceValuesResponse{
				Values:     resource.GetValues(),
				Pagination: emptyPageResponse(),
			}, nil
		}
	}

	return &registeredresources.ListRegisteredResourceValuesResponse{Pagination: emptyPageResponse()}, nil
}

func (h *pagedRetrieveTestHandler) ListObligationTriggers(_ context.Context, namespace string, limit, offset int32) (*obligations.ListObligationTriggersResponse, error) {
	if resp, ok := h.obligationTriggerPages[offset]; ok {
		return resp, nil
	}
	return &obligations.ListObligationTriggersResponse{Pagination: emptyPageResponse()}, nil
}

func (h *pagedRetrieveTestHandler) ListNamespaces(_ context.Context, state common.ActiveStateEnum, limit, offset int32) (*namespaces.ListNamespacesResponse, error) {
	return &namespaces.ListNamespacesResponse{Pagination: emptyPageResponse()}, nil
}

func pageResponse(nextOffset int32) *policy.PageResponse {
	return &policy.PageResponse{NextOffset: nextOffset}
}
