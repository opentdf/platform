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
	require.NotNil(t, plan.SubjectMappings[0].Target)
	assert.Equal(t, TargetStatusCreate, plan.SubjectMappings[0].Target.Status)
	assert.Equal(t, []string{"action-1"}, plan.SubjectMappings[0].Target.ActionSourceIDs)
	assert.Equal(t, "scs-1", plan.SubjectMappings[0].Target.SubjectConditionSetSourceID)

	require.Len(t, plan.RegisteredResources, 1)
	require.NotNil(t, plan.RegisteredResources[0].Target)
	require.Len(t, plan.RegisteredResources[0].Target.Values, 1)
	require.Len(t, plan.RegisteredResources[0].Target.Values[0].ActionBindings, 1)
	assert.Equal(t, "action-1", plan.RegisteredResources[0].Target.Values[0].ActionBindings[0].SourceActionID)

	require.Len(t, plan.ObligationTriggers, 1)
	require.NotNil(t, plan.ObligationTriggers[0].Target)
	assert.Equal(t, "action-1", plan.ObligationTriggers[0].Target.ActionSourceID)

	require.Len(t, plan.Namespaces, 1)
	assert.Equal(t, []string{"mapping-1"}, plan.Namespaces[0].SubjectMappings)
	assert.Equal(t, []string{"resource-1"}, plan.Namespaces[0].RegisteredResources)
	assert.Equal(t, []string{"trigger-1"}, plan.Namespaces[0].ObligationTriggers)
}

func TestFinalizePlanOmitsCreateOnlyBindingsForAlreadyMigratedTargets(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}

	plan, err := finalizePlan(&ResolvedTargets{
		Scopes: []Scope{
			ScopeSubjectMappings,
			ScopeRegisteredResources,
			ScopeObligationTriggers,
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
				Namespace:       namespace,
				AlreadyMigrated: &policy.SubjectMapping{Id: "mapping-target"},
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
				Namespace:       namespace,
				AlreadyMigrated: &policy.RegisteredResource{Id: "resource-target"},
			},
		},
		ObligationTriggers: []*ResolvedObligationTrigger{
			{
				Source: &policy.ObligationTrigger{
					Id:     "trigger-1",
					Action: &policy.Action{Id: "action-1", Name: "decrypt"},
				},
				Namespace:       namespace,
				AlreadyMigrated: &policy.ObligationTrigger{Id: "trigger-target"},
			},
		},
	}, []*policy.Namespace{namespace})
	require.NoError(t, err)

	require.Len(t, plan.SubjectMappings, 1)
	require.NotNil(t, plan.SubjectMappings[0].Target)
	assert.Equal(t, TargetStatusAlreadyMigrated, plan.SubjectMappings[0].Target.Status)
	assert.Equal(t, "mapping-target", plan.SubjectMappings[0].Target.ExistingID)
	assert.Nil(t, plan.SubjectMappings[0].Target.ActionSourceIDs)
	assert.Empty(t, plan.SubjectMappings[0].Target.SubjectConditionSetSourceID)

	require.Len(t, plan.RegisteredResources, 1)
	require.NotNil(t, plan.RegisteredResources[0].Target)
	assert.Equal(t, TargetStatusAlreadyMigrated, plan.RegisteredResources[0].Target.Status)
	assert.Equal(t, "resource-target", plan.RegisteredResources[0].Target.ExistingID)
	assert.Nil(t, plan.RegisteredResources[0].Target.Values)

	require.Len(t, plan.ObligationTriggers, 1)
	require.NotNil(t, plan.ObligationTriggers[0].Target)
	assert.Equal(t, TargetStatusAlreadyMigrated, plan.ObligationTriggers[0].Target.Status)
	assert.Equal(t, "trigger-target", plan.ObligationTriggers[0].Target.ExistingID)
	assert.Empty(t, plan.ObligationTriggers[0].Target.ActionSourceID)
}
