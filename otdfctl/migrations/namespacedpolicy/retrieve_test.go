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

func TestRetrieverListRegisteredResourcesForNamespacesDedupesNamespacesAndUsesInlineValues(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	value := testRegisteredResourceValue(
		"prod",
		testActionAttributeValue(
			"action-1",
			"decrypt",
			testAttributeValue("https://example.com/attr/classification/value/secret", nil),
		),
	)
	resource := &policy.RegisteredResource{
		Id:     "resource-1",
		Name:   "documents",
		Values: []*policy.RegisteredResourceValue{value},
	}
	handler := &plannerTestHandler{
		registeredResourcesByNamespace: map[string]*registeredresources.ListRegisteredResourcesResponse{
			namespace.GetId(): {
				Resources:  []*policy.RegisteredResource{resource},
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
	assert.Equal(t, []string{namespace.GetId()}, handler.registeredResourceCalls)
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

	handler := &pagedRetrieveTestHandler{
		registeredResourcePages: map[int32]*registeredresources.ListRegisteredResourcesResponse{
			0: {
				Resources: []*policy.RegisteredResource{
					{Id: "resource-dup", Name: "documents"},
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
	}

	resources, err := newRetriever(handler, 25).retrieveRegisteredResources(t.Context())
	require.NoError(t, err)

	assert.Equal(t, []string{"resource-dup", "resource-new"}, policyObjectIDs(resources))
}

func TestRetrieverRetrieveObligationTriggersDedupesAcrossPages(t *testing.T) {
	t.Parallel()

	handler := &pagedRetrieveTestHandler{
		obligationTriggerPages: map[int32]*obligations.ListObligationTriggersResponse{
			0: {
				Triggers: []*policy.ObligationTrigger{
					{
						Id:     "trigger-dup",
						Action: &policy.Action{Id: "action-1", Name: "decrypt"},
					},
					{
						Id:     "trigger-namespaced",
						Action: &policy.Action{Id: "action-2", Name: "decrypt", Namespace: &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"}},
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

	triggers, err := newRetriever(handler, 25).retrieveObligationTriggers(t.Context())
	require.NoError(t, err)

	assert.Equal(t, []string{"trigger-dup", "trigger-new"}, policyObjectIDs(triggers))
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
	subjectMappingPages     map[int32]*subjectmapping.ListSubjectMappingsResponse
	registeredResourcePages map[int32]*registeredresources.ListRegisteredResourcesResponse
	obligationTriggerPages  map[int32]*obligations.ListObligationTriggersResponse
}

func (h *pagedRetrieveTestHandler) ListActions(_ context.Context, limit, offset int32, namespace string) (*actions.ListActionsResponse, error) {
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
