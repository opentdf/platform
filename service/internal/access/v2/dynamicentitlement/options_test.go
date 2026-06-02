package dynamicentitlement

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dynamicSCS builds a reused SubjectConditionSet with a single dynamic condition: one
// subject set, one AND condition group, one condition whose subject_external_values
// carries the ResourceValuePlaceholder sentinel.
func dynamicSCS(selector string) *policy.SubjectConditionSet {
	return &policy.SubjectConditionSet{
		SubjectSets: []*policy.SubjectSet{{
			ConditionGroups: []*policy.ConditionGroup{{
				BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
				Conditions: []*policy.Condition{{
					SubjectExternalSelectorValue: selector,
					Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
					SubjectExternalValues:        []string{ResourceValuePlaceholder},
				}},
			}},
		}},
	}
}

// shapeFactory builds each option shape from the same inputs so the identical scenarios
// can be replayed across all three, which is what makes the options directly comparable.
type shapeFactory struct {
	name string
	make func(defFQN, selector string, op DynamicOperator, acts []*policy.Action) Mapping
}

func allShapes() []shapeFactory {
	return []shapeFactory{
		{"new_primitive", func(def, sel string, op DynamicOperator, acts []*policy.Action) Mapping {
			return &DefinitionValueEntitlementMapping{
				AttributeDefinitionFQN: def, Selector: sel, Operator: op, Actions: acts,
			}
		}},
		{"attribute_rule", func(def, sel string, op DynamicOperator, acts []*policy.Action) Mapping {
			return &DynamicRuleDefinition{
				AttributeDefinitionFQN: def, Rule: RuleDynamic, Selector: sel, Operator: op, Actions: acts,
			}
		}},
		{"reuse_subjectmapping", func(def, sel string, op DynamicOperator, acts []*policy.Action) Mapping {
			return &DefinitionScopedSubjectMapping{
				AttributeDefinitionFQN: def, Operator: op, Actions: acts, SubjectConditionSet: dynamicSCS(sel),
			}
		}},
	}
}

// TestMRNExampleAcrossAllShapes replays the ADR#266 worked example (patient / provider /
// nurse rows) against every option shape, proving they produce identical decisioning.
func TestMRNExampleAcrossAllShapes(t *testing.T) {
	const def = "https://hospital.co/attr/mrn"
	const resource = "https://hospital.co/attr/mrn/value/mrn-123"

	cases := []struct {
		name      string
		selector  string
		props     map[string]interface{}
		acts      []string
		wantMatch bool
	}{
		{
			name:      "patient",
			selector:  ".medicalRecordNumber",
			props:     map[string]interface{}{"medicalRecordNumber": "mrn-123"},
			acts:      []string{"read", "update_profile"},
			wantMatch: true,
		},
		{
			name:      "provider",
			selector:  ".patientAssignments[]",
			props:     map[string]interface{}{"patientAssignments": []interface{}{"mrn-123", "mrn-789"}},
			acts:      []string{"read", "write_order", "update_chart"},
			wantMatch: true,
		},
		{
			name:      "nurse",
			selector:  ".careTeamAssignments[]",
			props:     map[string]interface{}{"careTeamAssignments": []interface{}{"mrn-123"}},
			acts:      []string{"read", "update_chart"},
			wantMatch: true,
		},
		{
			name:      "unassigned provider",
			selector:  ".patientAssignments[]",
			props:     map[string]interface{}{"patientAssignments": []interface{}{"mrn-456"}},
			acts:      []string{"read"},
			wantMatch: false,
		},
	}

	for _, shape := range allShapes() {
		for _, tc := range cases {
			t.Run(shape.name+"/"+tc.name, func(t *testing.T) {
				m := shape.make(def, tc.selector, ResourceValueIn, actions(tc.acts...))
				got, err := Entitle([]Mapping{m}, entityRep(t, tc.props), resource)
				require.NoError(t, err)
				if tc.wantMatch {
					assert.ElementsMatch(t, tc.acts, actionNames(got))
				} else {
					assert.Empty(t, got)
				}
			})
		}
	}
}

// TestCanonicalization exercises the normalization concern (@biscoe916): the external
// system reports a differently-cased ID. The default canonicalizer matches; a no-op
// canonicalizer does not.
func TestCanonicalization(t *testing.T) {
	const def = "https://hospital.co/attr/mrn"
	const resource = "https://hospital.co/attr/mrn/value/mrn-123"
	er := entityRep(t, map[string]interface{}{"medicalRecordNumber": "MRN-123"})

	m := &DefinitionValueEntitlementMapping{
		AttributeDefinitionFQN: def, Selector: ".medicalRecordNumber",
		Operator: ResourceValueIn, Actions: actions("read"),
	}
	got, err := Entitle([]Mapping{m}, er, resource)
	require.NoError(t, err)
	assert.Equal(t, []string{"read"}, actionNames(got))

	m.Canonicalizer = func(s string) string { return s } // no-op: case now matters
	got, err = Entitle([]Mapping{m}, er, resource)
	require.NoError(t, err)
	assert.Empty(t, got)
}

// TestReuseStaticAndDynamicConditions shows Option A's distinguishing capability: a
// reused SubjectConditionSet can mix a STATIC condition (department check, evaluated by
// the existing subjectmappingbuiltin leaf evaluator) with a DYNAMIC condition (resource
// MRN in the entity's assignments).
func TestReuseStaticAndDynamicConditions(t *testing.T) {
	const def = "https://hospital.co/attr/mrn"
	const resource = def + "/value/mrn-123"

	scs := &policy.SubjectConditionSet{
		SubjectSets: []*policy.SubjectSet{{
			ConditionGroups: []*policy.ConditionGroup{{
				BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
				Conditions: []*policy.Condition{
					{
						SubjectExternalSelectorValue: ".department",
						Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
						SubjectExternalValues:        []string{"cardiology"},
					},
					{
						SubjectExternalSelectorValue: ".patientAssignments[]",
						Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
						SubjectExternalValues:        []string{ResourceValuePlaceholder},
					},
				},
			}},
		}},
	}
	m := &DefinitionScopedSubjectMapping{AttributeDefinitionFQN: def, SubjectConditionSet: scs, Actions: actions("read")}

	// cardiology provider assigned to mrn-123 -> both conditions pass
	got, err := Entitle([]Mapping{m}, entityRep(t, map[string]interface{}{
		"department":         "cardiology",
		"patientAssignments": []interface{}{"mrn-123"},
	}), resource)
	require.NoError(t, err)
	assert.Equal(t, []string{"read"}, actionNames(got))

	// wrong department -> static condition fails -> no entitlement
	got, err = Entitle([]Mapping{m}, entityRep(t, map[string]interface{}{
		"department":         "oncology",
		"patientAssignments": []interface{}{"mrn-123"},
	}), resource)
	require.NoError(t, err)
	assert.Empty(t, got)
}
