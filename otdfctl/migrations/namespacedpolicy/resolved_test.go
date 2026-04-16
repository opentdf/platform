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

	resolved, err := resolveExisting(
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
	require.NoError(t, err)

	require.Len(t, resolved.Actions, 1)
	require.Len(t, resolved.Actions[0].Results, 1)
	assert.Equal(t, "read-target", resolved.Actions[0].Results[0].ExistingStandard.GetId())
	assert.False(t, resolved.Actions[0].Results[0].NeedsCreate)
}

func TestResolveExistingFailsWhenActionCandidateIsNil(t *testing.T) {
	t.Parallel()

	resolved, err := resolveExisting(
		&DerivedTargets{
			Scopes:  []Scope{ScopeActions},
			Actions: []*DerivedAction{nil},
		},
		nil,
	)
	require.Error(t, err)
	assert.Nil(t, resolved)
	assert.EqualError(t, err, "could not determine target namespace: empty action candidate")
}

func TestResolveExistingFailsWhenSubjectConditionSetCandidateIsNil(t *testing.T) {
	t.Parallel()

	resolved, err := resolveExisting(
		&DerivedTargets{
			Scopes:               []Scope{ScopeSubjectConditionSets},
			SubjectConditionSets: []*DerivedSubjectConditionSet{nil},
		},
		nil,
	)
	require.Error(t, err)
	assert.Nil(t, resolved)
	assert.EqualError(t, err, "could not determine target namespace: empty subject condition set candidate")
}

func TestResolveExistingFailsWhenSubjectMappingCandidateIsNil(t *testing.T) {
	t.Parallel()

	resolved, err := resolveExisting(
		&DerivedTargets{
			Scopes:          []Scope{ScopeSubjectMappings},
			SubjectMappings: []*DerivedSubjectMapping{nil},
		},
		nil,
	)
	require.Error(t, err)
	assert.Nil(t, resolved)
	assert.EqualError(t, err, "could not determine target namespace: empty subject mapping candidate")
}

func TestResolveExistingFailsWhenSubjectMappingActionDependencyMissing(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}

	resolved, err := resolveExisting(
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
	require.Error(t, err)
	assert.Nil(t, resolved)
	assert.EqualError(
		t,
		err,
		`subject mapping "mapping-1": subject mapping dependency action "action-1" is not resolved in namespace "ns-1"`,
	)
}

func TestResolveExistingKeepsRegisteredResourceConflictUnresolved(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}

	resolved, err := resolveExisting(
		&DerivedTargets{
			Scopes: []Scope{ScopeRegisteredResources},
			RegisteredResources: []*DerivedRegisteredResource{
				{
					Source: &policy.RegisteredResource{Id: "resource-1", Name: "documents"},
					Target: namespace,
					Unresolved: &Unresolved{
						Reason:  UnresolvedReasonRegisteredResourceConflictingNamespaces,
						Message: "could not determine target namespace: registered resource spans multiple target namespaces",
					},
				},
			},
		},
		nil,
	)
	require.NoError(t, err)
	require.Len(t, resolved.RegisteredResources, 1)
	require.NotNil(t, resolved.RegisteredResources[0].Unresolved)
	assert.Equal(t, UnresolvedReasonRegisteredResourceConflictingNamespaces, resolved.RegisteredResources[0].Unresolved.Reason)
	assert.Equal(
		t,
		"could not determine target namespace: registered resource spans multiple target namespaces",
		resolved.RegisteredResources[0].Unresolved.Message,
	)
	assert.False(t, resolved.RegisteredResources[0].NeedsCreate)
}
