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
