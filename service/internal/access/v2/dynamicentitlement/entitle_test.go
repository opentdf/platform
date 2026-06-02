package dynamicentitlement

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCrossDefinitionNoLeak verifies entitlement is scoped to the value's parent
// definition: the same pass-through segment under a different definition is NOT granted.
// This is the cross-definition/namespace collision concern raised by @jakedoublev.
func TestCrossDefinitionNoLeak(t *testing.T) {
	er := entityRep(t, map[string]interface{}{"assignments": []interface{}{"shared-1"}})
	mA := &DefinitionValueEntitlementMapping{
		AttributeDefinitionFQN: "https://a.co/attr/x",
		Selector:               ".assignments[]",
		Operator:               ResourceValueIn,
		Actions:                actions("read"),
	}

	got, err := Entitle([]Mapping{mA}, er, "https://a.co/attr/x/value/shared-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"read"}, actionNames(got))

	// same value segment, different definition -> no entitlement (no leak)
	got, err = Entitle([]Mapping{mA}, er, "https://b.co/attr/y/value/shared-1")
	require.NoError(t, err)
	assert.Empty(t, got)
}

// TestDecideMultiValue exercises a single resource carrying multiple values under one
// definition (ADR decision-flow step 6), across the ANY_OF / ALL_OF combination rules.
func TestDecideMultiValue(t *testing.T) {
	const def = "https://hospital.co/attr/mrn"
	er := entityRep(t, map[string]interface{}{"patientAssignments": []interface{}{"mrn-123"}})
	m := &DefinitionValueEntitlementMapping{
		AttributeDefinitionFQN: def, Selector: ".patientAssignments[]",
		Operator: ResourceValueIn, Actions: actions("read"),
	}
	values := []string{def + "/value/mrn-123", def + "/value/mrn-999"} // entity has only mrn-123

	anyOf, err := Decide([]Mapping{m}, er, RuleAnyOf, "read", values)
	require.NoError(t, err)
	assert.True(t, anyOf, "ANY_OF: one matched value suffices")

	allOf, err := Decide([]Mapping{m}, er, RuleAllOf, "read", values)
	require.NoError(t, err)
	assert.False(t, allOf, "ALL_OF: mrn-999 is not entitled")

	dynamic, err := Decide([]Mapping{m}, er, RuleDynamic, "read", values)
	require.NoError(t, err)
	assert.True(t, dynamic, "RuleDynamic combines as ANY_OF by default")

	_, err = Decide([]Mapping{m}, er, RuleHierarchy, "read", values)
	require.ErrorIs(t, err, ErrHierarchyUnsupported)
}

// TestValidators covers the two API-enforcement findings: no coexistence with
// value-level subject mappings, and HIERARCHY rejection.
func TestValidators(t *testing.T) {
	const def = "https://hospital.co/attr/mrn"
	m := &DefinitionValueEntitlementMapping{AttributeDefinitionFQN: def, Selector: ".x", Operator: ResourceValueIn}

	require.ErrorIs(t, ValidateNoCoexistence(def, true, []Mapping{m}), ErrCoexistence)
	require.NoError(t, ValidateNoCoexistence(def, false, []Mapping{m}))
	require.NoError(t, ValidateNoCoexistence("https://other.co/attr/z", true, []Mapping{m}))

	require.ErrorIs(t, ValidateRule(RuleHierarchy), ErrHierarchyUnsupported)
	require.NoError(t, ValidateRule(RuleAnyOf))
}

// TestEntitleRejectsBadResourceFQN ensures a non-value or character-unsafe FQN is
// rejected before evaluation.
func TestEntitleRejectsBadResourceFQN(t *testing.T) {
	er := entityRep(t, map[string]interface{}{"a": "b"})

	_, err := Entitle(nil, er, "https://acme.co/attr/owner/value/user@acme.co")
	require.Error(t, err)

	_, err = Entitle(nil, er, "https://acme.co/attr/owner") // not a value FQN
	require.ErrorIs(t, err, ErrNotValueFQN)
}

// TestDirectEntitlementOverlap demonstrates the migration story (@biscoe916 Q1): a
// direct entitlement is effectively a (value FQN, actions) pair sourced from ERS at
// decision time. The dynamic mapping reproduces the identical grant from a single
// policy artifact, without per-value records.
func TestDirectEntitlementOverlap(t *testing.T) {
	const def = "https://acme.co/attr/account"
	const valueFQN = def + "/value/acct-42"
	er := entityRep(t, map[string]interface{}{"accounts": []interface{}{"acct-42"}})

	m := &DefinitionValueEntitlementMapping{
		AttributeDefinitionFQN: def, Selector: ".accounts[]",
		Operator: ResourceValueIn, Actions: actions("read"),
	}
	got, err := Entitle([]Mapping{m}, er, valueFQN)
	require.NoError(t, err)
	// equivalent to a direct entitlement record {attribute_value_fqn: valueFQN, actions:[read]}
	assert.Equal(t, []string{"read"}, actionNames(got))
}
