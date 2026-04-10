package namespacedpolicy

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReduceDependenciesKeepsOnlySubjectMappingDependencies(t *testing.T) {
	t.Parallel()

	scopes, err := normalizeScopes([]Scope{ScopeSubjectMappings})
	require.NoError(t, err)

	retrieved := &Retrieved{
		Candidates: Candidates{
			Actions: []*policy.Action{
				{Id: "action-keep", Name: "decrypt"},
				{Id: "action-drop", Name: "upload"},
			},
			SubjectConditionSets: []*policy.SubjectConditionSet{
				{Id: "scs-keep"},
				{Id: "scs-drop"},
			},
			SubjectMappings: []*policy.SubjectMapping{
				{
					Id: "mapping-1",
					Actions: []*policy.Action{
						{Id: "action-keep"},
					},
					SubjectConditionSet: &policy.SubjectConditionSet{Id: "scs-keep"},
				},
			},
		},
	}

	reduced := reduceDependencies(retrieved, scopes)
	require.NotNil(t, reduced)

	require.Len(t, reduced.Candidates.Actions, 1)
	assert.Equal(t, "action-keep", reduced.Candidates.Actions[0].GetId())
	require.Len(t, reduced.Candidates.SubjectConditionSets, 1)
	assert.Equal(t, "scs-keep", reduced.Candidates.SubjectConditionSets[0].GetId())
}

func TestReduceActionsIgnoresRegisteredResourcesWithoutSingleNamespace(t *testing.T) {
	t.Parallel()

	scopes, err := normalizeScopes([]Scope{ScopeRegisteredResources})
	require.NoError(t, err)

	resourceWithSingleNamespace := testRegisteredResource(
		"resource-keep",
		"keep",
		testRegisteredResourceValue(
			"value-1",
			testActionAttributeValue(
				"action-keep",
				"decrypt",
				testAttributeValue("https://example.com/attr/classification/value/secret", testNamespace("https://example.com")),
			),
		),
	)
	resourceWithConflictingNamespaces := testRegisteredResource(
		"resource-drop",
		"drop",
		testRegisteredResourceValue(
			"value-2",
			testActionAttributeValue(
				"action-drop",
				"decrypt",
				testAttributeValue("https://example.com/attr/classification/value/secret", testNamespace("https://example.com")),
			),
		),
		testRegisteredResourceValue(
			"value-3",
			testActionAttributeValue(
				"action-drop",
				"decrypt",
				testAttributeValue("https://other.example.com/attr/classification/value/secret", testNamespace("https://other.example.com")),
			),
		),
	)

	actions := reduceActions(scopes, Candidates{
		Actions: []*policy.Action{
			{Id: "action-keep", Name: "decrypt"},
			{Id: "action-drop", Name: "decrypt"},
		},
		RegisteredResources: []*policy.RegisteredResource{
			resourceWithSingleNamespace,
			resourceWithConflictingNamespaces,
		},
	})

	require.Len(t, actions, 1)
	assert.Equal(t, "action-keep", actions[0].GetId())
}

func TestRegisteredResourceNamespaceRefAcceptsEquivalentFQNs(t *testing.T) {
	t.Parallel()

	resource := testRegisteredResource(
		"resource-1",
		"resource",
		testRegisteredResourceValue(
			"value-1",
			testActionAttributeValue(
				"action-1",
				"read",
				testAttributeValue("", testNamespace(" https://Example.COM ")),
			),
		),
		testRegisteredResourceValue(
			"value-2",
			testActionAttributeValue(
				"action-2",
				"read",
				testAttributeValue("", testNamespace("https://example.com")),
			),
		),
	)

	namespace, ok := registeredResourceNamespaceRef(resource)
	require.True(t, ok)
	require.NotNil(t, namespace)
	assert.Equal(t, " https://Example.COM ", namespace.GetFqn())
}

// TODO: Add obligation trigger tests.
