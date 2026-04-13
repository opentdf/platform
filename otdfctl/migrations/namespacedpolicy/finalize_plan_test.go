package namespacedpolicy

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFinalizePlanBuildsBindingsForDependentObjects(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}

	plan, err := finalizePlan(&ResolvedTargets{
		Scopes: []Scope{
			ScopeActions,
			ScopeSubjectConditionSets,
			ScopeSubjectMappings,
			ScopeRegisteredResources,
			ScopeObligationTriggers,
		},
		Actions: []*ResolvedAction{
			{
				Source: &policy.Action{Id: "action-1", Name: "decrypt"},
				Results: []*ResolvedActionResult{
					{Namespace: namespace, NeedsCreate: true},
				},
			},
		},
		SubjectConditionSets: []*ResolvedSubjectConditionSet{
			{
				Source: &policy.SubjectConditionSet{Id: "scs-1"},
				Results: []*ResolvedSubjectConditionSetResult{
					{
						Namespace:       namespace,
						AlreadyMigrated: &policy.SubjectConditionSet{Id: "scs-target"},
					},
				},
			},
		},
		SubjectMappings: []*ResolvedSubjectMapping{
			{
				Source: &policy.SubjectMapping{
					Id: "mapping-1",
					Actions: []*policy.Action{
						{Id: "action-1", Name: "decrypt"},
					},
					SubjectConditionSet: &policy.SubjectConditionSet{Id: "scs-1"},
				},
				Namespace:   namespace,
				NeedsCreate: true,
			},
		},
		RegisteredResources: []*ResolvedRegisteredResource{
			{
				Source: testRegisteredResource(
					"resource-1",
					"documents",
					testRegisteredResourceValue(
						"prod",
						testActionAttributeValue(
							"action-1",
							"decrypt",
							testAttributeValue("https://example.com/attr/classification/value/secret", nil),
						),
					),
				),
				Namespace:   namespace,
				NeedsCreate: true,
			},
		},
		ObligationTriggers: []*ResolvedObligationTrigger{
			{
				Source: &policy.ObligationTrigger{
					Id:     "trigger-1",
					Action: &policy.Action{Id: "action-1", Name: "decrypt"},
				},
				Namespace:   namespace,
				NeedsCreate: true,
			},
		},
	}, []*policy.Namespace{namespace})
	require.NoError(t, err)

	require.Len(t, plan.SubjectMappings, 1)
	require.Len(t, plan.SubjectMappings[0].Targets, 1)
	assert.Equal(t, TargetStatusCreate, plan.SubjectMappings[0].Targets[0].Status)
	require.Len(t, plan.SubjectMappings[0].Targets[0].Actions, 1)
	assert.Equal(t, TargetStatusCreate, plan.SubjectMappings[0].Targets[0].Actions[0].Status)
	assert.Equal(t, "action-1", plan.SubjectMappings[0].Targets[0].Actions[0].SourceID)
	require.NotNil(t, plan.SubjectMappings[0].Targets[0].SubjectConditionSet)
	assert.Equal(t, TargetStatusAlreadyMigrated, plan.SubjectMappings[0].Targets[0].SubjectConditionSet.Status)
	assert.Equal(t, "scs-target", plan.SubjectMappings[0].Targets[0].SubjectConditionSet.TargetID)

	require.Len(t, plan.RegisteredResources, 1)
	require.Len(t, plan.RegisteredResources[0].Targets, 1)
	require.Len(t, plan.RegisteredResources[0].Targets[0].Values, 1)
	require.Len(t, plan.RegisteredResources[0].Targets[0].Values[0].ActionBindings, 1)
	assert.Equal(t, TargetStatusCreate, plan.RegisteredResources[0].Targets[0].Values[0].ActionBindings[0].ActionTargetRef.Status)

	require.Len(t, plan.ObligationTriggers, 1)
	require.Len(t, plan.ObligationTriggers[0].Targets, 1)
	require.NotNil(t, plan.ObligationTriggers[0].Targets[0].Action)
	assert.Equal(t, TargetStatusCreate, plan.ObligationTriggers[0].Targets[0].Action.Status)

	require.Len(t, plan.Namespaces, 1)
	assert.Equal(t, []string{"mapping-1"}, plan.Namespaces[0].SubjectMappings)
	assert.Equal(t, []string{"resource-1"}, plan.Namespaces[0].RegisteredResources)
	assert.Equal(t, []string{"trigger-1"}, plan.Namespaces[0].ObligationTriggers)
}
