package celeval_test

import (
	"testing"

	"github.com/opentdf/platform/lib/flattening"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/internal/subjectmappingbuiltin"
	"github.com/opentdf/platform/service/internal/subjectmappingbuiltin/celeval"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const selector = ".attributes.testing[]"

func flatten(t *testing.T, values ...string) flattening.Flattened {
	t.Helper()
	vals := make([]any, len(values))
	for i, v := range values {
		vals[i] = v
	}
	flat, err := flattening.Flatten(map[string]interface{}{
		"attributes": map[string]interface{}{"testing": vals},
	})
	require.NoError(t, err)
	return flat
}

func legacyCondition(op policy.SubjectMappingOperatorEnum, targets ...string) *policy.Condition {
	return &policy.Condition{
		SubjectExternalSelectorValue: selector,
		Operator:                     op,
		SubjectExternalValues:        targets,
	}
}

func group(boolOp policy.ConditionBooleanTypeEnum, conditions ...*policy.Condition) *policy.ConditionGroup {
	return &policy.ConditionGroup{BooleanOperator: boolOp, Conditions: conditions}
}

func subjectSet(groups ...*policy.ConditionGroup) *policy.SubjectSet {
	return &policy.SubjectSet{ConditionGroups: groups}
}

// TestEquivalenceWithNative proves the CEL lowering produces the same result as the native
// EvaluateSubjectSet across legacy operators, both boolean group operators, and multiple groups.
// This is the correctness backbone for the go_cel benchmark arm.
func TestEquivalenceWithNative(t *testing.T) {
	const (
		in       = policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN
		notIn    = policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN
		contains = policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS
		andOp    = policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND
		orOp     = policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR
	)

	entities := map[string]flattening.Flattened{
		"opt1_opt3": flatten(t, "option1", "option3"),
		"opt4_opt3": flatten(t, "option4", "option3"),
		"email":     flatten(t, "user@acme.com"),
		"empty":     flatten(t),
	}

	subjectSets := map[string]*policy.SubjectSet{
		"single IN":          subjectSet(group(andOp, legacyCondition(in, "option1", "option2"))),
		"single NOT_IN":      subjectSet(group(andOp, legacyCondition(notIn, "option1"))),
		"single IN_CONTAINS": subjectSet(group(andOp, legacyCondition(contains, "acme.com"))),
		"AND group": subjectSet(group(andOp,
			legacyCondition(in, "option1"),
			legacyCondition(notIn, "option9"),
		)),
		"OR group": subjectSet(group(orOp,
			legacyCondition(in, "option9"),
			legacyCondition(in, "option3"),
		)),
		"multi group AND": subjectSet(
			group(andOp, legacyCondition(in, "option1")),
			group(orOp, legacyCondition(in, "option9"), legacyCondition(contains, "option")),
		),
	}

	for ssName, ss := range subjectSets {
		prog, err := celeval.CompileSubjectSet(ss)
		require.NoError(t, err, "compile %s", ssName)

		for entityName, flat := range entities {
			native, err := subjectmappingbuiltin.EvaluateSubjectSet(ss, flat)
			require.NoError(t, err)

			celResult, err := prog.Eval(flat)
			require.NoError(t, err)

			assert.Equalf(t, native, celResult,
				"subjectSet=%q entity=%q src=%q", ssName, entityName, prog.Source())
		}
	}
}

// TestDecomposedOperators covers the #3335 axes the legacy enum cannot express. The native
// evaluator does not support them, so results are checked against expected values.
func TestDecomposedOperators(t *testing.T) {
	decomposed := func(cmp policy.ConditionComparisonOperatorEnum, q policy.ConditionQuantifierEnum, caseInsensitive bool, targets ...string) *policy.SubjectSet {
		return subjectSet(group(policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
			&policy.Condition{
				SubjectExternalSelectorValue: selector,
				Comparison:                   cmp,
				Quantifier:                   q,
				CaseInsensitive:              wrapperspb.Bool(caseInsensitive),
				SubjectExternalValues:        targets,
			},
		))
	}

	const (
		equals   = policy.ConditionComparisonOperatorEnum_CONDITION_COMPARISON_OPERATOR_ENUM_EQUALS
		endsWith = policy.ConditionComparisonOperatorEnum_CONDITION_COMPARISON_OPERATOR_ENUM_ENDS_WITH
		anyQ     = policy.ConditionQuantifierEnum_CONDITION_QUANTIFIER_ENUM_ANY
		allQ     = policy.ConditionQuantifierEnum_CONDITION_QUANTIFIER_ENUM_ALL
		noneQ    = policy.ConditionQuantifierEnum_CONDITION_QUANTIFIER_ENUM_NONE
	)

	cases := []struct {
		name   string
		ss     *policy.SubjectSet
		entity flattening.Flattened
		want   bool
	}{
		{"ALL present", decomposed(equals, allQ, false, "option1", "option2"), flatten(t, "option1", "option2"), true},
		{"ALL missing one", decomposed(equals, allQ, false, "option1", "option9"), flatten(t, "option1", "option2"), false},
		{"NONE match", decomposed(equals, noneQ, false, "option9"), flatten(t, "option1"), true},
		{"case-insensitive ANY", decomposed(equals, anyQ, true, "OPTION1"), flatten(t, "option1"), true},
		{"ENDS_WITH safe domain", decomposed(endsWith, anyQ, false, "@acme.com"), flatten(t, "user@acme.com"), true},
		{"ENDS_WITH rejects spoofed", decomposed(endsWith, anyQ, false, "@acme.com"), flatten(t, "user@acme.com.evil.ru"), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prog, err := celeval.CompileSubjectSet(tc.ss)
			require.NoError(t, err)
			got, err := prog.Eval(tc.entity)
			require.NoError(t, err)
			assert.Equalf(t, tc.want, got, "src=%q", prog.Source())
		})
	}
}
