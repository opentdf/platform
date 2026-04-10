package namespacedpolicy

import (
	"context"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
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
