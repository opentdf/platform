package namespacedpolicy

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeriveTargetsCollectsTargetsAndReferencesFromDependencies(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	retrieved := &Retrieved{
		Scopes: []Scope{
			ScopeActions,
			ScopeSubjectConditionSets,
			ScopeSubjectMappings,
			ScopeRegisteredResources,
			ScopeObligationTriggers,
		},
		Candidates: Candidates{
			Actions: []*policy.Action{
				{Id: "action-1", Name: "decrypt"},
			},
			SubjectConditionSets: []*policy.SubjectConditionSet{
				{Id: "scs-1"},
			},
			SubjectMappings: []*policy.SubjectMapping{
				{
					Id: "mapping-1",
					AttributeValue: testAttributeValue(
						"https://example.com/attr/classification/value/secret",
						namespace,
					),
					SubjectConditionSet: &policy.SubjectConditionSet{Id: "scs-1"},
					Actions: []*policy.Action{
						{Id: "action-1", Name: "decrypt"},
					},
				},
			},
			RegisteredResources: []*policy.RegisteredResource{
				testRegisteredResource(
					"resource-1",
					"documents",
					testRegisteredResourceValue(
						"prod",
						testActionAttributeValue(
							"action-1",
							"decrypt",
							testAttributeValue("https://example.com/attr/classification/value/secret", namespace),
						),
					),
				),
			},
			ObligationTriggers: []*policy.ObligationTrigger{
				{
					Id:     "trigger-1",
					Action: &policy.Action{Id: "action-1", Name: "decrypt"},
					ObligationValue: &policy.ObligationValue{
						Id:         "ov-1",
						Fqn:        "https://example.com/obl/notify/value/email",
						Obligation: &policy.Obligation{Namespace: namespace},
					},
				},
			},
		},
	}

	derived, err := deriveTargets(retrieved, []*policy.Namespace{namespace})
	require.NoError(t, err)

	require.Len(t, derived.Actions, 1)
	require.Len(t, derived.Actions[0].Targets, 1)
	assert.Equal(t, namespace.GetId(), derived.Actions[0].Targets[0].GetId())
	assert.ElementsMatch(t, []string{
		"subject_mapping|mapping-1",
		"registered_resource|resource-1",
		"obligation_trigger|trigger-1",
	}, actionReferenceKindsAndIDs(derived.Actions[0].References))

	require.Len(t, derived.SubjectConditionSets, 1)
	require.Len(t, derived.SubjectConditionSets[0].Targets, 1)
	assert.Equal(t, namespace.GetId(), derived.SubjectConditionSets[0].Targets[0].GetId())
	require.Len(t, derived.SubjectMappings, 1)
	assert.Equal(t, namespace.GetId(), derived.SubjectMappings[0].Target.GetId())
	require.Len(t, derived.RegisteredResources, 1)
	assert.Equal(t, namespace.GetId(), derived.RegisteredResources[0].Target.GetId())
	require.Len(t, derived.ObligationTriggers, 1)
	assert.Equal(t, namespace.GetId(), derived.ObligationTriggers[0].Target.GetId())
}

func TestDeriveTargetsFailsWhenSubjectMappingNamespaceCannotBeDerived(t *testing.T) {
	t.Parallel()

	retrieved := &Retrieved{
		Scopes: []Scope{ScopeSubjectMappings},
		Candidates: Candidates{
			SubjectMappings: []*policy.SubjectMapping{
				{
					Id:             "mapping-1",
					AttributeValue: &policy.Value{},
				},
			},
		},
	}

	derived, err := deriveTargets(retrieved, nil)
	require.Error(t, err)
	assert.Nil(t, derived)
	assert.EqualError(t, err, `subject mapping "mapping-1": could not determine target namespace: empty namespace reference`)
}

func TestDeriveTargetsKeepsRegisteredResourceNamespaceConflictUnresolved(t *testing.T) {
	t.Parallel()

	leftNamespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	rightNamespace := &policy.Namespace{
		Id:  "ns-2",
		Fqn: "https://other.example.com",
	}
	retrieved := &Retrieved{
		Scopes: []Scope{ScopeRegisteredResources},
		Candidates: Candidates{
			RegisteredResources: []*policy.RegisteredResource{
				testRegisteredResource(
					"resource-1",
					"documents",
					testRegisteredResourceValue(
						"prod",
						testActionAttributeValue(
							"action-1",
							"decrypt",
							testAttributeValue("https://example.com/attr/classification/value/secret", leftNamespace),
						),
						testActionAttributeValue(
							"action-2",
							"encrypt",
							testAttributeValue("https://other.example.com/attr/classification/value/secret", rightNamespace),
						),
					),
				),
			},
		},
	}

	derived, err := deriveTargets(retrieved, []*policy.Namespace{leftNamespace, rightNamespace})
	require.NoError(t, err)
	require.Len(t, derived.RegisteredResources, 1)
	require.NotNil(t, derived.RegisteredResources[0].Unresolved)
	assert.Equal(t, UnresolvedReasonRegisteredResourceConflictingNamespaces, derived.RegisteredResources[0].Unresolved.Reason)
	assert.Equal(
		t,
		"could not determine target namespace: registered resource spans multiple target namespaces",
		derived.RegisteredResources[0].Unresolved.Message,
	)
	assert.Nil(t, derived.RegisteredResources[0].Target)
}

func TestDeriveTargetsSkipsRegisteredResourceWithoutActionAttributeValues(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	retrieved := &Retrieved{
		Scopes: []Scope{ScopeRegisteredResources},
		Candidates: Candidates{
			RegisteredResources: []*policy.RegisteredResource{
				testRegisteredResource(
					"resource-1",
					"documents",
					&policy.RegisteredResourceValue{
						Value: "prod",
					},
				),
			},
		},
	}

	derived, err := deriveTargets(retrieved, []*policy.Namespace{namespace})
	require.NoError(t, err)
	assert.Empty(t, derived.RegisteredResources)
}

func actionReferenceKindsAndIDs(references []*ActionReference) []string {
	keys := make([]string, 0, len(references))
	for _, reference := range references {
		if reference == nil {
			continue
		}
		keys = append(keys, string(reference.Kind)+"|"+reference.ID)
	}

	return keys
}
