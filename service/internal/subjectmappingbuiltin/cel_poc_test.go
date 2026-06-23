package subjectmappingbuiltin_test

// Spike POC for DSPX-3673: evaluate whether CEL (https://cel.dev, cel-go) can express the
// Subject Mapping / Subject Condition Set operators currently implemented as a hand-written
// switch in subject_mapping_builtin.go (EvaluateCondition), plus the decomposed operators
// proposed in https://github.com/opentdf/platform/issues/3335.
//
// The tests below build a CEL environment, extract entity values with the existing
// flattening helper, and assert that a CEL expression produces the SAME result as the native
// EvaluateCondition for the legacy operators (IN, NOT_IN, IN_CONTAINS), and the expected
// result for the decomposed cases (ALL quantifier, case-insensitive match).
//
// Findings and the recommendation are written up in
// service/policy/adr/0005-dspx-3673-cel-condition-evaluation-spike.md. This file is a spike
// artifact: it is test-only and touches no production evaluation path.

import (
	"fmt"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	"github.com/opentdf/platform/lib/flattening"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/internal/subjectmappingbuiltin"
	"github.com/opentdf/platform/service/internal/subjectmappingbuiltin/celeval"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const celPOCSelector = ".attributes.testing[]"

// celPOCEntities are the entity representations the conditions are evaluated against. Names are
// prefixed celPOC to avoid colliding with the shared vars in subject_mapping_builtin_test.go.
var celPOCEntities = map[string]flattening.Flattened{
	"has_option1_option3": celPOCFlatten(map[string]interface{}{
		"attributes": map[string]interface{}{"testing": []any{"option1", "option3"}},
	}),
	"has_option4_option3": celPOCFlatten(map[string]interface{}{
		"attributes": map[string]interface{}{"testing": []any{"option4", "option3"}},
	}),
	"has_option1_option2": celPOCFlatten(map[string]interface{}{
		"attributes": map[string]interface{}{"testing": []any{"option1", "option2"}},
	}),
	"has_email_domain": celPOCFlatten(map[string]interface{}{
		"attributes": map[string]interface{}{"testing": []any{"user@acme.com"}},
	}),
}

func celPOCFlatten(m map[string]interface{}) flattening.Flattened {
	f, err := flattening.Flatten(m)
	if err != nil {
		panic(err)
	}
	return f
}

// celPOCSelectStrings mirrors how EvaluateCondition reads entity values: it pulls everything at
// the selector and stringifies it (the native IN_CONTAINS path does the same with fmt.Sprintf).
func celPOCSelectStrings(flat flattening.Flattened) []string {
	raw := flattening.GetFromFlattened(flat, celPOCSelector)
	out := make([]string, len(raw))
	for i, v := range raw {
		out[i] = fmt.Sprintf("%v", v)
	}
	return out
}

// celPOCEnv builds the CEL environment used for every expression in this spike. The two inputs
// model exactly what EvaluateCondition works with: `values` are the entity values resolved by
// the selector, `targets` are condition.SubjectExternalValues. ext.Strings provides
// lowerAscii() for the case-insensitive case.
func celPOCEnv(t *testing.T) *cel.Env {
	t.Helper()
	env, err := cel.NewEnv(
		cel.Variable("values", cel.ListType(cel.StringType)),
		cel.Variable("targets", cel.ListType(cel.StringType)),
		ext.Strings(),
	)
	require.NoError(t, err)
	return env
}

func celPOCEval(t *testing.T, env *cel.Env, expr string, values, targets []string) bool {
	t.Helper()
	astChecked, iss := env.Compile(expr)
	require.NoError(t, iss.Err(), "compile %q", expr)
	prg, err := env.Program(astChecked)
	require.NoError(t, err)
	out, _, err := prg.Eval(map[string]any{"values": values, "targets": targets})
	require.NoError(t, err)
	result, ok := out.Value().(bool)
	require.True(t, ok, "expression %q did not return a bool", expr)
	return result
}

// TestCEL_LegacyOperatorEquivalence asserts that, for every legacy operator across a matrix of
// target sets and entities, a condition lowered to CEL by celeval evaluates to the same result as
// the native EvaluateCondition. This is acceptance criterion #1; celeval is the real lowering used
// by the benchmarks, so this exercises production-shaped code rather than hand-written expressions.
func TestCEL_LegacyOperatorEquivalence(t *testing.T) {
	operators := []policy.SubjectMappingOperatorEnum{
		policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
		policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN,
		policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS,
	}
	targetSets := [][]string{
		{"option1", "option2"},
		{"option3"},
		{"option9"},
		{"acme.com"},
	}

	for _, op := range operators {
		for _, targets := range targetSets {
			condition := &policy.Condition{
				SubjectExternalSelectorValue: celPOCSelector,
				Operator:                     op,
				SubjectExternalValues:        targets,
			}
			// Wrap in a single-condition AND group so EvaluateSubjectSet(ss) == EvaluateCondition(c).
			ss := &policy.SubjectSet{ConditionGroups: []*policy.ConditionGroup{{
				BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
				Conditions:      []*policy.Condition{condition},
			}}}
			prog, err := celeval.CompileSubjectSet(ss)
			require.NoError(t, err)

			for entityName, flat := range celPOCEntities {
				native, err := subjectmappingbuiltin.EvaluateCondition(condition, flat)
				require.NoError(t, err)

				celResult, err := prog.Eval(flat)
				require.NoError(t, err)

				assert.Equalf(t, native, celResult,
					"operator=%s entity=%s targets=%v src=%q", op, entityName, targets, prog.Source())
			}
		}
	}
}

// TestCEL_DecomposedOperators covers operators from issue #3335 that the legacy enum cannot
// express: the ALL quantifier and a case-insensitive comparison. EvaluateCondition has no
// native equivalent, so results are checked against expected values.
func TestCEL_DecomposedOperators(t *testing.T) {
	env := celPOCEnv(t)

	t.Run("ALL quantifier with EQUALS", func(t *testing.T) {
		// "every target value is present in the entity values"
		const expr = `targets.all(t, t in values)`
		values := celPOCSelectStrings(celPOCEntities["has_option1_option2"])

		assert.True(t, celPOCEval(t, env, expr, values, []string{"option1", "option2"}))
		assert.False(t, celPOCEval(t, env, expr, values, []string{"option1", "option9"}))
	})

	t.Run("case-insensitive EQUALS via ANY", func(t *testing.T) {
		const expr = `targets.exists(t, values.exists(v, v.lowerAscii() == t.lowerAscii()))`
		values := celPOCSelectStrings(celPOCEntities["has_option1_option3"])

		assert.True(t, celPOCEval(t, env, expr, values, []string{"OPTION1"}))
		assert.False(t, celPOCEval(t, env, expr, values, []string{"OPTION9"}))
	})

	t.Run("ENDS_WITH for safe domain matching", func(t *testing.T) {
		// #3335 motivation: IN_CONTAINS unsafely matches user@acme.com.attacker.ru;
		// ENDS_WITH is the correct operator. CEL expresses it directly.
		const expr = `targets.exists(t, values.exists(v, v.endsWith(t)))`
		values := celPOCSelectStrings(celPOCEntities["has_email_domain"])

		assert.True(t, celPOCEval(t, env, expr, values, []string{"@acme.com"}))
		assert.False(t, celPOCEval(t, env, expr, values, []string{"@evil.com"}))
	})
}

// TestCEL_CompileErrorsAreCaught documents a key safety property for the ADR: invalid
// expressions fail at compile time, before any evaluation, so a malformed policy cannot reach
// the hot path.
func TestCEL_CompileErrorsAreCaught(t *testing.T) {
	env := celPOCEnv(t)
	_, iss := env.Compile(`targets.exists(t, t in nonexistent)`)
	require.Error(t, iss.Err())
}
