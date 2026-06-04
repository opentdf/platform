package subjectmappingbuiltin

import (
	"log/slog"
	"testing"

	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func dvemEntityRep(t *testing.T, props map[string]interface{}) *entityresolutionV2.EntityRepresentation {
	t.Helper()
	s, err := structpb.NewStruct(props)
	require.NoError(t, err)
	return &entityresolutionV2.EntityRepresentation{
		OriginalId:      "entity-1",
		AdditionalProps: []*structpb.Struct{s},
	}
}

func dvemActions(names ...string) []*policy.Action {
	out := make([]*policy.Action, 0, len(names))
	for _, n := range names {
		out = append(out, &policy.Action{Name: n})
	}
	return out
}

func dvemActionNames(acts []*policy.Action) []string {
	out := make([]string, 0, len(acts))
	for _, a := range acts {
		out = append(out, a.GetName())
	}
	return out
}

func dvemDecisionable(defFQN, valueFQN, segment string) map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue {
	return map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{
		valueFQN: {
			Value:     &policy.Value{Fqn: valueFQN, Value: segment},
			Attribute: &policy.Attribute{Fqn: defFQN},
		},
	}
}

func dvemMapping(defFQN, selector string, op policy.DynamicValueOperatorEnum, scs *policy.SubjectConditionSet, actionNames ...string) *policy.DefinitionValueEntitlementMapping {
	return &policy.DefinitionValueEntitlementMapping{
		AttributeDefinition: &policy.Attribute{Fqn: defFQN},
		ValueResolver: &policy.DefinitionValueResolver{
			SubjectExternalSelectorValue: selector,
			Operator:                     op,
		},
		SubjectConditionSet: scs,
		Actions:             dvemActions(actionNames...),
	}
}

// TestEvaluateDefinitionValueEntitlementMappings_MRNExample replays the ADR#266 worked
// example (patient / provider / nurse) against the production evaluator.
func TestEvaluateDefinitionValueEntitlementMappings_MRNExample(t *testing.T) {
	const def = "https://hospital.co/attr/mrn"
	const valueFQN = "https://hospital.co/attr/mrn/value/mrn-123"

	cases := []struct {
		name      string
		selector  string
		props     map[string]interface{}
		acts      []string
		wantMatch bool
	}{
		{"patient", ".medicalRecordNumber", map[string]interface{}{"medicalRecordNumber": "mrn-123"}, []string{"read", "update_profile"}, true},
		{"provider", ".patientAssignments[]", map[string]interface{}{"patientAssignments": []interface{}{"mrn-123", "mrn-789"}}, []string{"read", "write_order", "update_chart"}, true},
		{"nurse", ".careTeamAssignments[]", map[string]interface{}{"careTeamAssignments": []interface{}{"mrn-123"}}, []string{"read", "update_chart"}, true},
		{"unassigned", ".patientAssignments[]", map[string]interface{}{"patientAssignments": []interface{}{"mrn-456"}}, []string{"read"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mapping := dvemMapping(def, tc.selector, policy.DynamicValueOperatorEnum_DYNAMIC_VALUE_OPERATOR_ENUM_RESOURCE_VALUE_IN, nil, tc.acts...)
			byDef := DefinitionValueEntitlementMappingsByDefinitionFQN{def: {mapping}}

			got, err := EvaluateDefinitionValueEntitlementMappingsWithActions(byDef, dvemDecisionable(def, valueFQN, "mrn-123"), dvemEntityRep(t, tc.props), slog.Default())
			require.NoError(t, err)
			if tc.wantMatch {
				assert.ElementsMatch(t, tc.acts, dvemActionNames(got[valueFQN]))
			} else {
				assert.Empty(t, got[valueFQN])
			}
		})
	}
}

// TestEvaluateDefinitionValueEntitlementMappings_Canonicalization covers the external
// system case-mismatch concern: the IdP reports MRN-123, policy stores mrn-123.
func TestEvaluateDefinitionValueEntitlementMappings_Canonicalization(t *testing.T) {
	const def = "https://hospital.co/attr/mrn"
	const valueFQN = "https://hospital.co/attr/mrn/value/mrn-123"
	mapping := dvemMapping(def, ".medicalRecordNumber", policy.DynamicValueOperatorEnum_DYNAMIC_VALUE_OPERATOR_ENUM_RESOURCE_VALUE_IN, nil, "read")
	byDef := DefinitionValueEntitlementMappingsByDefinitionFQN{def: {mapping}}

	got, err := EvaluateDefinitionValueEntitlementMappingsWithActions(byDef, dvemDecisionable(def, valueFQN, "mrn-123"), dvemEntityRep(t, map[string]interface{}{"medicalRecordNumber": "MRN-123"}), slog.Default())
	require.NoError(t, err)
	assert.Equal(t, []string{"read"}, dvemActionNames(got[valueFQN]))
}

// TestEvaluateDefinitionValueEntitlementMappings_InContains covers the substring operator.
func TestEvaluateDefinitionValueEntitlementMappings_InContains(t *testing.T) {
	const def = "https://acme.co/attr/group"
	const valueFQN = "https://acme.co/attr/group/value/team"
	mapping := dvemMapping(def, ".groups[]", policy.DynamicValueOperatorEnum_DYNAMIC_VALUE_OPERATOR_ENUM_RESOURCE_VALUE_IN_CONTAINS, nil, "read")
	byDef := DefinitionValueEntitlementMappingsByDefinitionFQN{def: {mapping}}

	got, err := EvaluateDefinitionValueEntitlementMappingsWithActions(byDef, dvemDecisionable(def, valueFQN, "team"), dvemEntityRep(t, map[string]interface{}{"groups": []interface{}{"prefix-team-suffix"}}), slog.Default())
	require.NoError(t, err)
	assert.Equal(t, []string{"read"}, dvemActionNames(got[valueFQN]))
}

// TestEvaluateDefinitionValueEntitlementMappings_StaticGate covers the optional static
// SubjectConditionSet pre-gate combined with the dynamic resolver.
func TestEvaluateDefinitionValueEntitlementMappings_StaticGate(t *testing.T) {
	const def = "https://hospital.co/attr/mrn"
	const valueFQN = "https://hospital.co/attr/mrn/value/mrn-123"

	scs := &policy.SubjectConditionSet{
		SubjectSets: []*policy.SubjectSet{{
			ConditionGroups: []*policy.ConditionGroup{{
				BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
				Conditions: []*policy.Condition{{
					SubjectExternalSelectorValue: ".department",
					Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
					SubjectExternalValues:        []string{"cardiology"},
				}},
			}},
		}},
	}
	mapping := dvemMapping(def, ".patientAssignments[]", policy.DynamicValueOperatorEnum_DYNAMIC_VALUE_OPERATOR_ENUM_RESOURCE_VALUE_IN, scs, "read")
	byDef := DefinitionValueEntitlementMappingsByDefinitionFQN{def: {mapping}}

	// cardiology provider assigned to mrn-123 -> gate + resolver pass
	got, err := EvaluateDefinitionValueEntitlementMappingsWithActions(byDef, dvemDecisionable(def, valueFQN, "mrn-123"), dvemEntityRep(t, map[string]interface{}{
		"department":         "cardiology",
		"patientAssignments": []interface{}{"mrn-123"},
	}), slog.Default())
	require.NoError(t, err)
	assert.Equal(t, []string{"read"}, dvemActionNames(got[valueFQN]))

	// wrong department -> static gate fails -> no entitlement
	got, err = EvaluateDefinitionValueEntitlementMappingsWithActions(byDef, dvemDecisionable(def, valueFQN, "mrn-123"), dvemEntityRep(t, map[string]interface{}{
		"department":         "oncology",
		"patientAssignments": []interface{}{"mrn-123"},
	}), slog.Default())
	require.NoError(t, err)
	assert.Empty(t, got[valueFQN])
}

// TestEvaluateDefinitionValueEntitlementMappings_CrossDefinitionNoLeak verifies a mapping
// only applies to its own definition: the same value segment under a different definition
// is not entitled.
func TestEvaluateDefinitionValueEntitlementMappings_CrossDefinitionNoLeak(t *testing.T) {
	const defA = "https://a.co/attr/x"
	const defB = "https://b.co/attr/y"
	mapping := dvemMapping(defA, ".assignments[]", policy.DynamicValueOperatorEnum_DYNAMIC_VALUE_OPERATOR_ENUM_RESOURCE_VALUE_IN, nil, "read")
	byDef := DefinitionValueEntitlementMappingsByDefinitionFQN{defA: {mapping}}
	entity := dvemEntityRep(t, map[string]interface{}{"assignments": []interface{}{"shared-1"}})

	// under definition A -> entitled
	gotA, err := EvaluateDefinitionValueEntitlementMappingsWithActions(byDef, dvemDecisionable(defA, defA+"/value/shared-1", "shared-1"), entity, slog.Default())
	require.NoError(t, err)
	assert.Equal(t, []string{"read"}, dvemActionNames(gotA[defA+"/value/shared-1"]))

	// same segment under definition B -> not entitled
	gotB, err := EvaluateDefinitionValueEntitlementMappingsWithActions(byDef, dvemDecisionable(defB, defB+"/value/shared-1", "shared-1"), entity, slog.Default())
	require.NoError(t, err)
	assert.Empty(t, gotB[defB+"/value/shared-1"])
}
