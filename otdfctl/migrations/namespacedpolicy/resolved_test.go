package namespacedpolicy

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveExistingUsesExistingStandardAction(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	existing := newExistingTargets()
	existing.StandardActions[namespace.GetId()] = []*policy.Action{
		{Id: "read-target", Name: "read", Namespace: namespace},
	}

	resolved := resolveExisting(
		&DerivedTargets{
			Scopes: []Scope{ScopeActions},
			Actions: []*DerivedAction{
				{
					Source:  &policy.Action{Id: "legacy-read", Name: "read"},
					Targets: []*policy.Namespace{namespace},
				},
			},
		},
		existing,
	)

	require.Len(t, resolved.Actions, 1)
	require.Len(t, resolved.Actions[0].Results, 1)
	assert.Equal(t, "read-target", resolved.Actions[0].Results[0].ExistingStandard.GetId())
	assert.False(t, resolved.Actions[0].Results[0].NeedsCreate)
	assert.Empty(t, resolved.Actions[0].Results[0].Unresolved)
}

func TestResolveExistingMarksSubjectMappingUnresolvedWhenActionDependencyMissing(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}

	resolved := resolveExisting(
		&DerivedTargets{
			Scopes: []Scope{ScopeActions, ScopeSubjectConditionSets, ScopeSubjectMappings},
			SubjectConditionSets: []*DerivedSubjectConditionSet{
				{
					Source:  &policy.SubjectConditionSet{Id: "scs-1"},
					Targets: []*policy.Namespace{namespace},
				},
			},
			SubjectMappings: []*DerivedSubjectMapping{
				{
					Source: &policy.SubjectMapping{
						Id: "mapping-1",
						Actions: []*policy.Action{
							{Id: "action-1", Name: "decrypt"},
						},
						SubjectConditionSet: &policy.SubjectConditionSet{Id: "scs-1"},
					},
					Target: namespace,
				},
			},
		},
		nil,
	)

	require.Len(t, resolved.SubjectMappings, 1)
	assert.Equal(
		t,
		`subject mapping dependency action "action-1" is not resolved in namespace "ns-1"`,
		resolved.SubjectMappings[0].Unresolved,
	)
	assert.False(t, resolved.SubjectMappings[0].NeedsCreate)
}
