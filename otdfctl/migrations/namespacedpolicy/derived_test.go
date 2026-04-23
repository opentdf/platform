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

func TestDeriveTargetsSkipsNilSubjectMappingCandidate(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"}
	// A nil entry in Candidates.SubjectMappings is a retrieval artifact and
	// must be silently dropped, not halt the whole loop.
	derived, err := deriveTargets(
		&Retrieved{
			Scopes: []Scope{ScopeSubjectMappings},
			Candidates: Candidates{
				SubjectMappings: []*policy.SubjectMapping{
					nil,
					{
						Id: "mapping-1",
						AttributeValue: testAttributeValue(
							"https://example.com/attr/classification/value/secret",
							namespace,
						),
						SubjectConditionSet: &policy.SubjectConditionSet{Id: "scs-1"},
						Actions:             []*policy.Action{{Id: "action-1", Name: "decrypt"}},
					},
				},
			},
		},
		[]*policy.Namespace{namespace},
	)
	require.NoError(t, err)
	require.Len(t, derived.SubjectMappings, 1)
	assert.Equal(t, "mapping-1", derived.SubjectMappings[0].Source.GetId())
}

func TestDeriveTargetsSkipsNilObligationTriggerCandidate(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"}
	// A nil entry in Candidates.ObligationTriggers is a retrieval artifact
	// and must be silently dropped, not halt the whole loop.
	derived, err := deriveTargets(
		&Retrieved{
			Scopes: []Scope{ScopeObligationTriggers},
			Candidates: Candidates{
				ObligationTriggers: []*policy.ObligationTrigger{
					nil,
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
		},
		[]*policy.Namespace{namespace},
	)
	require.NoError(t, err)
	require.Len(t, derived.ObligationTriggers, 1)
	assert.Equal(t, "trigger-1", derived.ObligationTriggers[0].Source.GetId())
}

func TestDeriveTargetsSkipsNilActionCandidate(t *testing.T) {
	t.Parallel()

	// A nil entry in Candidates.Actions is treated as a retrieval artifact and
	// silently dropped rather than aborting the loop.
	derived, err := deriveTargets(
		&Retrieved{
			Scopes: []Scope{ScopeActions},
			Candidates: Candidates{
				Actions: []*policy.Action{
					nil,
					{Id: "action-1", Name: "decrypt"},
				},
			},
		},
		nil,
	)
	require.NoError(t, err)
	require.Len(t, derived.Actions, 1)
	assert.Equal(t, "action-1", derived.Actions[0].Source.GetId())
}

func TestDeriveTargetsSkipsNilSubjectConditionSetCandidate(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"}
	// Include a surviving SCS referenced by a subject mapping so the slice
	// isn't empty — the nil must be dropped in place, not abort the loop.
	derived, err := deriveTargets(
		&Retrieved{
			Scopes: []Scope{ScopeSubjectConditionSets, ScopeSubjectMappings},
			Candidates: Candidates{
				SubjectConditionSets: []*policy.SubjectConditionSet{
					nil,
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
						Actions:             []*policy.Action{{Id: "action-1", Name: "decrypt"}},
					},
				},
			},
		},
		[]*policy.Namespace{namespace},
	)
	require.NoError(t, err)
	require.Len(t, derived.SubjectConditionSets, 1)
	assert.Equal(t, "scs-1", derived.SubjectConditionSets[0].Source.GetId())
}

func TestDeriveTargetsSkipsSubjectConditionSetWithNoReferencingDependency(t *testing.T) {
	t.Parallel()

	// A legacy SCS that no in-scope subject mapping points at has no
	// derivable target. Treat it as "nothing to migrate" and drop it, rather
	// than erroring and halting the whole plan.
	derived, err := deriveTargets(
		&Retrieved{
			Scopes: []Scope{ScopeSubjectConditionSets},
			Candidates: Candidates{
				SubjectConditionSets: []*policy.SubjectConditionSet{
					{Id: "scs-1"},
				},
			},
		},
		nil,
	)
	require.NoError(t, err)
	assert.Empty(t, derived.SubjectConditionSets)
}

func TestDeriveTargetsSkipsNilRegisteredResourceCandidate(t *testing.T) {
	t.Parallel()

	derived, err := deriveTargets(
		&Retrieved{
			Scopes: []Scope{ScopeRegisteredResources},
			Candidates: Candidates{
				RegisteredResources: []*policy.RegisteredResource{nil},
			},
		},
		nil,
	)
	require.NoError(t, err)
	assert.Empty(t, derived.RegisteredResources)
}

func TestDeriveTargetsResolvesNamespaceByFQNWhenIDMissing(t *testing.T) {
	t.Parallel()

	targetNamespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	// AttributeValue has no nested Attribute.Namespace, forcing
	// namespaceFromAttributeValue to produce an {Fqn-only} reference from
	// the parsed FQN. resolveNamespace must fall back from the empty ID
	// lookup to the FQN lookup and return the full namespace record.
	derived, err := deriveTargets(
		&Retrieved{
			Scopes: []Scope{ScopeSubjectMappings},
			Candidates: Candidates{
				SubjectMappings: []*policy.SubjectMapping{
					{
						Id: "mapping-1",
						AttributeValue: &policy.Value{
							Fqn: "https://example.com/attr/classification/value/secret",
						},
					},
				},
			},
		},
		[]*policy.Namespace{targetNamespace},
	)
	require.NoError(t, err)
	require.Len(t, derived.SubjectMappings, 1)
	assert.Equal(t, targetNamespace.GetId(), derived.SubjectMappings[0].Target.GetId())
	assert.Equal(t, targetNamespace.GetFqn(), derived.SubjectMappings[0].Target.GetFqn())
}

func TestDeriveTargetsFailsWhenNamespaceRefNotFound(t *testing.T) {
	t.Parallel()

	derived, err := deriveTargets(
		&Retrieved{
			Scopes: []Scope{ScopeSubjectMappings},
			Candidates: Candidates{
				SubjectMappings: []*policy.SubjectMapping{
					{
						Id: "mapping-1",
						AttributeValue: &policy.Value{
							Fqn: "https://missing.example.com/attr/foo/value/bar",
						},
					},
				},
			},
		},
		[]*policy.Namespace{
			{Id: "ns-1", Fqn: "https://example.com"},
		},
	)
	require.Error(t, err)
	assert.Nil(t, derived)
	require.ErrorIs(t, err, ErrMissingTargetNamespace)
	assert.Contains(t, err.Error(), `subject mapping "mapping-1"`)
	assert.Contains(t, err.Error(), "missing.example.com")
}

func TestNamespaceAccumulatorDeduplicatesByRef(t *testing.T) {
	t.Parallel()

	// Dedup is load-bearing: an action referenced from multiple observers
	// targeting the same namespace must resolve to a single target, not N —
	// this drives single-vs-multi-namespace branching downstream.
	acc := newNamespaceAccumulator()
	acc.add(&policy.Namespace{Id: "ns-1", Fqn: "https://example.com"})
	acc.add(&policy.Namespace{Id: "ns-1", Fqn: "https://example.com"}) // same identifier, different struct
	acc.add(&policy.Namespace{Id: "ns-2", Fqn: "https://other.example.com"})
	acc.add(nil)
	acc.add(&policy.Namespace{}) // empty key — must be skipped

	got := acc.slice()
	require.Len(t, got, 2)
	assert.Equal(t, "ns-1", got[0].GetId())
	assert.Equal(t, "ns-2", got[1].GetId())
}
