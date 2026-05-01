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
	require.ErrorIs(t, err, ErrUnresolvedActionDependency)
	assert.Contains(t, err.Error(), `subject mapping "mapping-1" in namespace "ns-1"`)
	assert.Contains(t, err.Error(), `action "action-1"`)
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

func TestResolveExistingCustomActionReturnsFirstCanonicalMatch(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	existing := newExistingTargets()
	// Two canonically-equal custom actions. Pinning first-match-wins here
	// guards against a future refactor silently reintroducing ambiguous
	// ordering (e.g. switching to map iteration).
	existing.CustomActions[namespace.GetId()] = []*policy.Action{
		{Id: "first-match", Name: "decrypt-custom"},
		{Id: "second-match", Name: "DECRYPT-CUSTOM"},
	}

	resolved, err := resolveExisting(
		&DerivedTargets{
			Scopes: []Scope{ScopeActions},
			Actions: []*DerivedAction{
				{
					Source:  &policy.Action{Id: "legacy", Name: "decrypt-custom"},
					Targets: []*policy.Namespace{namespace},
				},
			},
		},
		existing,
	)
	require.NoError(t, err)
	require.Len(t, resolved.Actions, 1)
	require.Len(t, resolved.Actions[0].Results, 1)
	assert.Equal(t, "first-match", resolved.Actions[0].Results[0].AlreadyMigrated.GetId())
	assert.False(t, resolved.Actions[0].Results[0].NeedsCreate)
}

func TestResolveExistingStandardActionReturnsFirstCanonicalMatch(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	existing := newExistingTargets()
	existing.StandardActions[namespace.GetId()] = []*policy.Action{
		{Id: "first-match", Name: "read", Namespace: namespace},
		{Id: "second-match", Name: "READ", Namespace: namespace},
	}

	resolved, err := resolveExisting(
		&DerivedTargets{
			Scopes: []Scope{ScopeActions},
			Actions: []*DerivedAction{
				{
					Source:  &policy.Action{Id: "legacy", Name: "read"},
					Targets: []*policy.Namespace{namespace},
				},
			},
		},
		existing,
	)
	require.NoError(t, err)
	require.Len(t, resolved.Actions, 1)
	require.Len(t, resolved.Actions[0].Results, 1)
	assert.Equal(t, "first-match", resolved.Actions[0].Results[0].ExistingStandard.GetId())
	assert.False(t, resolved.Actions[0].Results[0].NeedsCreate)
}

func TestResolveExistingStandardActionFailsWhenNoMatchInTargetNamespace(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	existing := newExistingTargets()
	existing.StandardActions[namespace.GetId()] = []*policy.Action{
		{Id: "non-matching", Name: "write", Namespace: namespace},
	}

	resolved, err := resolveExisting(
		&DerivedTargets{
			Scopes: []Scope{ScopeActions},
			Actions: []*DerivedAction{
				{
					Source:  &policy.Action{Id: "legacy", Name: "read"},
					Targets: []*policy.Namespace{namespace},
				},
			},
		},
		existing,
	)
	require.Error(t, err)
	assert.Nil(t, resolved)
	assert.EqualError(
		t,
		err,
		`action "legacy" in namespace "ns-1": matching standard action not found in target namespace`,
	)
}

func TestResolveExistingRoutesStandardActionsByName(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		sourceName string
	}{
		{name: "create", sourceName: "create"},
		{name: "read", sourceName: "read"},
		{name: "update", sourceName: "update"},
		{name: "delete", sourceName: "delete"},
		{name: "uppercase routes to standard path", sourceName: "CREATE"},
		{name: "whitespace-padded routes to standard path", sourceName: "  read  "},
		{name: "mixed case routes to standard path", sourceName: "UpDaTe"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			namespace := &policy.Namespace{
				Id:  "ns-1",
				Fqn: "https://example.com",
			}
			existing := newExistingTargets()
			// Populating only StandardActions forces this to fail if the
			// source is misrouted through the custom-action matcher.
			existing.StandardActions[namespace.GetId()] = []*policy.Action{
				{Id: "standard-target", Name: tc.sourceName, Namespace: namespace},
			}

			resolved, err := resolveExisting(
				&DerivedTargets{
					Scopes: []Scope{ScopeActions},
					Actions: []*DerivedAction{
						{
							Source:  &policy.Action{Id: "legacy", Name: tc.sourceName},
							Targets: []*policy.Namespace{namespace},
						},
					},
				},
				existing,
			)
			require.NoError(t, err)
			require.Len(t, resolved.Actions, 1)
			require.Len(t, resolved.Actions[0].Results, 1)
			assert.Equal(t, "standard-target", resolved.Actions[0].Results[0].ExistingStandard.GetId())
			assert.False(t, resolved.Actions[0].Results[0].NeedsCreate)
		})
	}
}

func TestResolveExistingRoutesStandardActionsByEnumRegardlessOfName(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	existing := newExistingTargets()
	// Source name is not one of create/read/update/delete, so routing relies
	// entirely on the proto Standard enum to reach the standard-action path.
	existing.StandardActions[namespace.GetId()] = []*policy.Action{
		{
			Id:        "standard-target",
			Name:      "decrypt",
			Value:     &policy.Action_Standard{Standard: policy.Action_STANDARD_ACTION_DECRYPT},
			Namespace: namespace,
		},
	}

	resolved, err := resolveExisting(
		&DerivedTargets{
			Scopes: []Scope{ScopeActions},
			Actions: []*DerivedAction{
				{
					Source: &policy.Action{
						Id:    "legacy",
						Name:  "decrypt",
						Value: &policy.Action_Standard{Standard: policy.Action_STANDARD_ACTION_DECRYPT},
					},
					Targets: []*policy.Namespace{namespace},
				},
			},
		},
		existing,
	)
	require.NoError(t, err)
	require.Len(t, resolved.Actions, 1)
	require.Len(t, resolved.Actions[0].Results, 1)
	assert.Equal(t, "standard-target", resolved.Actions[0].Results[0].ExistingStandard.GetId())
}

func TestResolveExistingSubjectMappingFailsWhenDerivedTargetIsNil(t *testing.T) {
	t.Parallel()

	resolved, err := resolveExisting(
		&DerivedTargets{
			Scopes: []Scope{ScopeSubjectMappings},
			SubjectMappings: []*DerivedSubjectMapping{
				{Source: &policy.SubjectMapping{Id: "mapping-1"}},
			},
		},
		nil,
	)
	require.Error(t, err)
	assert.Nil(t, resolved)
	require.ErrorIs(t, err, ErrUndeterminedTargetMapping)
	assert.EqualError(t, err, "could not determine target namespace: empty namespace reference")
}

func TestResolveExistingRegisteredResourceFailsWhenSourceIsNil(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	resolved, err := resolveExisting(
		&DerivedTargets{
			Scopes: []Scope{ScopeRegisteredResources},
			RegisteredResources: []*DerivedRegisteredResource{
				{Target: namespace},
			},
		},
		nil,
	)
	require.Error(t, err)
	assert.Nil(t, resolved)
	require.ErrorIs(t, err, ErrUndeterminedTargetMapping)
	assert.EqualError(t, err, "could not determine target namespace: registered resource is empty")
}

func TestResolveExistingRegisteredResourceFailsWhenNamespaceIsNil(t *testing.T) {
	t.Parallel()

	resolved, err := resolveExisting(
		&DerivedTargets{
			Scopes: []Scope{ScopeRegisteredResources},
			RegisteredResources: []*DerivedRegisteredResource{
				{Source: &policy.RegisteredResource{Id: "resource-1", Name: "documents"}},
			},
		},
		nil,
	)
	require.Error(t, err)
	assert.Nil(t, resolved)
	require.ErrorIs(t, err, ErrUndeterminedTargetMapping)
	assert.EqualError(t, err, "could not determine target namespace: empty namespace reference")
}

func TestResolveExistingObligationTriggerFailsWhenDerivedTargetIsNil(t *testing.T) {
	t.Parallel()

	resolved, err := resolveExisting(
		&DerivedTargets{
			Scopes: []Scope{ScopeObligationTriggers},
			ObligationTriggers: []*DerivedObligationTrigger{
				{Source: &policy.ObligationTrigger{Id: "trigger-1"}},
			},
		},
		nil,
	)
	require.Error(t, err)
	assert.Nil(t, resolved)
	require.ErrorIs(t, err, ErrUndeterminedTargetMapping)
	assert.EqualError(t, err, "could not determine target namespace: empty namespace reference")
}

func TestResolveExistingSubjectMappingFailsWhenSubjectConditionSetHasNoID(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	// Mapping has no actions (skipping the action dependency loop) and no
	// SubjectConditionSet, so GetSubjectConditionSet().GetId() is "".
	resolved, err := resolveExisting(
		&DerivedTargets{
			Scopes: []Scope{ScopeSubjectMappings},
			SubjectMappings: []*DerivedSubjectMapping{
				{
					Source: &policy.SubjectMapping{Id: "mapping-1"},
					Target: namespace,
				},
			},
		},
		nil,
	)
	require.Error(t, err)
	assert.Nil(t, resolved)
	require.ErrorIs(t, err, ErrMissingSubjectConditionSetID)
	assert.Contains(t, err.Error(), `subject mapping "mapping-1" in namespace "ns-1"`)
}

func TestResolveExistingSubjectMappingFailsWhenSubjectConditionSetNotResolvedInNamespace(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	otherNamespace := &policy.Namespace{
		Id:  "ns-2",
		Fqn: "https://other.example.com",
	}

	resolved, err := resolveExisting(
		&DerivedTargets{
			Scopes: []Scope{ScopeActions, ScopeSubjectConditionSets, ScopeSubjectMappings},
			Actions: []*DerivedAction{
				{
					Source:  &policy.Action{Id: "action-1", Name: "decrypt"},
					Targets: []*policy.Namespace{namespace},
				},
			},
			SubjectConditionSets: []*DerivedSubjectConditionSet{
				// SCS is resolved only against otherNamespace, so the mapping's
				// lookup against "scs-1|ns-1" comes back nil.
				{
					Source:  &policy.SubjectConditionSet{Id: "scs-1"},
					Targets: []*policy.Namespace{otherNamespace},
				},
			},
			SubjectMappings: []*DerivedSubjectMapping{
				{
					Source: &policy.SubjectMapping{
						Id:                  "mapping-1",
						Actions:             []*policy.Action{{Id: "action-1", Name: "decrypt"}},
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
	require.ErrorIs(t, err, ErrUnresolvedSubjectConditionSetDependency)
	assert.Contains(t, err.Error(), `subject mapping "mapping-1" in namespace "ns-1"`)
	assert.Contains(t, err.Error(), `subject condition set "scs-1"`)
}

func TestResolveExistingDropsSubjectMappingsOutsideScope(t *testing.T) {
	t.Parallel()

	// Scopes omit ScopeSubjectMappings. A mapping that would otherwise fail
	// validation (missing SCS id) must be dropped rather than surfaced.
	resolved, err := resolveExisting(
		&DerivedTargets{
			Scopes: []Scope{ScopeActions},
			SubjectMappings: []*DerivedSubjectMapping{
				{
					Source: &policy.SubjectMapping{Id: "mapping-1"},
					Target: &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"},
				},
			},
		},
		nil,
	)
	require.NoError(t, err)
	assert.Empty(t, resolved.SubjectMappings)
}

func TestResolveExistingDropsRegisteredResourcesOutsideScope(t *testing.T) {
	t.Parallel()

	// An empty derived resource would error on nil source if reached; clean
	// NoError proves the scope gate drops it before validation.
	resolved, err := resolveExisting(
		&DerivedTargets{
			Scopes:              []Scope{ScopeActions},
			RegisteredResources: []*DerivedRegisteredResource{{}},
		},
		nil,
	)
	require.NoError(t, err)
	assert.Empty(t, resolved.RegisteredResources)
}

func TestResolveExistingDropsObligationTriggersOutsideScope(t *testing.T) {
	t.Parallel()

	resolved, err := resolveExisting(
		&DerivedTargets{
			Scopes: []Scope{ScopeActions},
			ObligationTriggers: []*DerivedObligationTrigger{
				{Source: &policy.ObligationTrigger{Id: "trigger-1"}},
			},
		},
		nil,
	)
	require.NoError(t, err)
	assert.Empty(t, resolved.ObligationTriggers)
}

func TestResolveExistingRegisteredResourceFailsWhenActionDependencyMissingID(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	// AAV references an action with no ID — planner cannot wire the RR create
	// to a specific action target, so the plan must fail here rather than
	// surface the error at execution time.
	resolved, err := resolveExisting(
		&DerivedTargets{
			Scopes: []Scope{ScopeRegisteredResources},
			RegisteredResources: []*DerivedRegisteredResource{
				{
					Source: testRegisteredResource(
						"rr-1",
						"documents",
						testRegisteredResourceValue(
							"prod",
							testActionAttributeValue("", "decrypt", testAttributeValue("https://example.com/attr/foo/value/bar", namespace)),
						),
					),
					Target: namespace,
				},
			},
		},
		nil,
	)
	require.Error(t, err)
	assert.Nil(t, resolved)
	require.ErrorIs(t, err, ErrMissingActionID)
	assert.Contains(t, err.Error(), `registered resource "rr-1" in namespace "ns-1"`)
}

func TestResolveExistingRegisteredResourceFailsWhenActionDependencyNotResolvedInNamespace(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	otherNamespace := &policy.Namespace{
		Id:  "ns-2",
		Fqn: "https://other.example.com",
	}
	// Action resolves only against otherNamespace, so the RR's lookup at
	// "action-1|ns-1" comes back nil — catch this at plan time rather than
	// letting the executor fail on a missing action at create time.
	resolved, err := resolveExisting(
		&DerivedTargets{
			Scopes: []Scope{ScopeActions, ScopeRegisteredResources},
			Actions: []*DerivedAction{
				{
					Source:  &policy.Action{Id: "action-1", Name: "decrypt"},
					Targets: []*policy.Namespace{otherNamespace},
				},
			},
			RegisteredResources: []*DerivedRegisteredResource{
				{
					Source: testRegisteredResource(
						"rr-1",
						"documents",
						testRegisteredResourceValue(
							"prod",
							testActionAttributeValue("action-1", "decrypt", testAttributeValue("https://example.com/attr/foo/value/bar", namespace)),
						),
					),
					Target: namespace,
				},
			},
		},
		nil,
	)
	require.Error(t, err)
	assert.Nil(t, resolved)
	require.ErrorIs(t, err, ErrUnresolvedActionDependency)
	assert.Contains(t, err.Error(), `registered resource "rr-1" in namespace "ns-1"`)
	assert.Contains(t, err.Error(), `action "action-1"`)
}

func TestResolveExistingObligationTriggerFailsWhenActionDependencyMissingID(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	resolved, err := resolveExisting(
		&DerivedTargets{
			Scopes: []Scope{ScopeObligationTriggers},
			ObligationTriggers: []*DerivedObligationTrigger{
				{
					Source: &policy.ObligationTrigger{
						Id:     "trigger-1",
						Action: &policy.Action{Name: "decrypt"},
					},
					Target: namespace,
				},
			},
		},
		nil,
	)
	require.Error(t, err)
	assert.Nil(t, resolved)
	require.ErrorIs(t, err, ErrMissingActionID)
	assert.Contains(t, err.Error(), `obligation trigger "trigger-1" in namespace "ns-1"`)
}

func TestResolveExistingObligationTriggerFailsWhenActionDependencyNotResolvedInNamespace(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	otherNamespace := &policy.Namespace{
		Id:  "ns-2",
		Fqn: "https://other.example.com",
	}
	resolved, err := resolveExisting(
		&DerivedTargets{
			Scopes: []Scope{ScopeActions, ScopeObligationTriggers},
			Actions: []*DerivedAction{
				{
					Source:  &policy.Action{Id: "action-1", Name: "decrypt"},
					Targets: []*policy.Namespace{otherNamespace},
				},
			},
			ObligationTriggers: []*DerivedObligationTrigger{
				{
					Source: &policy.ObligationTrigger{
						Id:     "trigger-1",
						Action: &policy.Action{Id: "action-1", Name: "decrypt"},
					},
					Target: namespace,
				},
			},
		},
		nil,
	)
	require.Error(t, err)
	assert.Nil(t, resolved)
	require.ErrorIs(t, err, ErrUnresolvedActionDependency)
	assert.Contains(t, err.Error(), `obligation trigger "trigger-1" in namespace "ns-1"`)
	assert.Contains(t, err.Error(), `action "action-1"`)
}

func TestResolveExistingReusesAlreadyMigratedSubjectConditionSet(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}

	scs := func(id string, values ...string) *policy.SubjectConditionSet {
		return &policy.SubjectConditionSet{
			Id: id,
			SubjectSets: []*policy.SubjectSet{
				{ConditionGroups: []*policy.ConditionGroup{
					{
						Conditions: []*policy.Condition{
							{
								SubjectExternalSelectorValue: ".role",
								Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								SubjectExternalValues:        values,
							},
						},
						BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
					},
				}},
			},
		}
	}

	existing := newExistingTargets()
	// Existing SCS differs only in condition-value order — canonical equality
	// must match so the resolver routes to AlreadyMigrated instead of create.
	existing.SubjectConditionSets[namespace.GetId()] = []*policy.SubjectConditionSet{
		scs("existing-scs", "editor", "admin"),
	}

	resolved, err := resolveExisting(
		&DerivedTargets{
			Scopes: []Scope{ScopeSubjectConditionSets},
			SubjectConditionSets: []*DerivedSubjectConditionSet{
				{
					Source:  scs("legacy-scs", "admin", "editor"),
					Targets: []*policy.Namespace{namespace},
				},
			},
		},
		existing,
	)
	require.NoError(t, err)
	require.Len(t, resolved.SubjectConditionSets, 1)
	require.Len(t, resolved.SubjectConditionSets[0].Results, 1)
	result := resolved.SubjectConditionSets[0].Results[0]
	require.NotNil(t, result.AlreadyMigrated)
	assert.Equal(t, "existing-scs", result.AlreadyMigrated.GetId())
	assert.False(t, result.NeedsCreate)
}

func TestResolveExistingReusesAlreadyMigratedSubjectMapping(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	sourceSCS := &policy.SubjectConditionSet{
		Id: "scs-1",
		SubjectSets: []*policy.SubjectSet{
			{ConditionGroups: []*policy.ConditionGroup{
				{
					Conditions: []*policy.Condition{
						{
							SubjectExternalSelectorValue: ".role",
							Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
							SubjectExternalValues:        []string{"admin"},
						},
					},
					BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
				},
			}},
		},
	}
	attributeFQN := "https://example.com/attr/classification/value/secret"

	existing := newExistingTargets()
	// Existing SM differs only in case/whitespace on the attribute value FQN and
	// action names — canonical equality must still identify it as a match.
	existing.SubjectMappings[namespace.GetId()] = []*policy.SubjectMapping{
		{
			Id:                  "existing-mapping",
			AttributeValue:      &policy.Value{Fqn: " " + attributeFQN + " "},
			Actions:             []*policy.Action{{Id: "action-1", Name: "DECRYPT"}},
			SubjectConditionSet: sourceSCS,
		},
	}

	resolved, err := resolveExisting(
		&DerivedTargets{
			Scopes: []Scope{ScopeActions, ScopeSubjectConditionSets, ScopeSubjectMappings},
			Actions: []*DerivedAction{
				{
					Source:  &policy.Action{Id: "action-1", Name: "decrypt"},
					Targets: []*policy.Namespace{namespace},
				},
			},
			SubjectConditionSets: []*DerivedSubjectConditionSet{
				{
					Source:  sourceSCS,
					Targets: []*policy.Namespace{namespace},
				},
			},
			SubjectMappings: []*DerivedSubjectMapping{
				{
					Source: &policy.SubjectMapping{
						Id:                  "legacy-mapping",
						AttributeValue:      &policy.Value{Fqn: attributeFQN},
						Actions:             []*policy.Action{{Id: "action-1", Name: "decrypt"}},
						SubjectConditionSet: sourceSCS,
					},
					Target: namespace,
				},
			},
		},
		existing,
	)
	require.NoError(t, err)
	require.Len(t, resolved.SubjectMappings, 1)
	require.NotNil(t, resolved.SubjectMappings[0].AlreadyMigrated)
	assert.Equal(t, "existing-mapping", resolved.SubjectMappings[0].AlreadyMigrated.GetId())
	assert.False(t, resolved.SubjectMappings[0].NeedsCreate)
}

func TestResolveExistingReusesAlreadyMigratedObligationTrigger(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	attributeFQN := "https://example.com/attr/classification/value/secret"
	obligationFQN := "https://example.com/obligation/notify/value/default"

	existing := newExistingTargets()
	// Existing trigger differs only in case and whitespace — canonical equality
	// must still identify it as a match.
	existing.ObligationTriggers[namespace.GetId()] = []*policy.ObligationTrigger{
		{
			Id:              "existing-trigger",
			Action:          &policy.Action{Id: "action-1", Name: "DECRYPT"},
			AttributeValue:  &policy.Value{Fqn: " " + attributeFQN + " "},
			ObligationValue: &policy.ObligationValue{Fqn: obligationFQN},
		},
	}

	resolved, err := resolveExisting(
		&DerivedTargets{
			Scopes: []Scope{ScopeActions, ScopeObligationTriggers},
			Actions: []*DerivedAction{
				{
					Source:  &policy.Action{Id: "action-1", Name: "decrypt"},
					Targets: []*policy.Namespace{namespace},
				},
			},
			ObligationTriggers: []*DerivedObligationTrigger{
				{
					Source: &policy.ObligationTrigger{
						Id:              "legacy-trigger",
						Action:          &policy.Action{Id: "action-1", Name: "decrypt"},
						AttributeValue:  &policy.Value{Fqn: attributeFQN},
						ObligationValue: &policy.ObligationValue{Fqn: obligationFQN},
					},
					Target: namespace,
				},
			},
		},
		existing,
	)
	require.NoError(t, err)
	require.Len(t, resolved.ObligationTriggers, 1)
	require.NotNil(t, resolved.ObligationTriggers[0].AlreadyMigrated)
	assert.Equal(t, "existing-trigger", resolved.ObligationTriggers[0].AlreadyMigrated.GetId())
	assert.False(t, resolved.ObligationTriggers[0].NeedsCreate)
}
