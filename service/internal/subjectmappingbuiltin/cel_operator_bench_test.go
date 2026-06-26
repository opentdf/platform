//go:build celbench

// Layer 1 of the CEL performance deliverable: operator-engine micro-benchmark. Compares the
// per-evaluation cost of a native Go operator switch against a precompiled CEL program (celeval),
// and reports the one-time CEL compile cost, for two operator sets:
//
//   - legacy:     the shipped SubjectMappingOperatorEnum (IN / NOT_IN / IN_CONTAINS), evaluated by
//     the production EvaluateSubjectSet.
//   - decomposed: the merged #3335 axes (comparison + quantifier + case_insensitive). The production
//     evaluator does not implement these yet, so this file includes a representative Go
//     switch (evalNativeDecomposedSubjectSet) standing in for what the "keep bespoke"
//     option would have to add. celeval already lowers them.
//
// Build-tagged (celbench) so it never runs in the default suite, mirroring the entpdpbench /
// entbench gating in the existing perf deliverables. Driven by
// docs/performance/cel-condition-evaluation/run.sh, which sets CEL_BENCH_OP_OUT.
//
//	go test -tags celbench -run TestCELOperatorBenchmark ./internal/subjectmappingbuiltin/
package subjectmappingbuiltin_test

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/opentdf/platform/lib/flattening"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/internal/subjectmappingbuiltin"
	"github.com/opentdf/platform/service/internal/subjectmappingbuiltin/celeval"
	"github.com/stretchr/testify/require"
)

type opSize struct {
	name   string
	groups int
	conds  int
}

// buildLegacyFixture builds a SubjectSet of groups x conds legacy-operator conditions (mixed
// IN / NOT_IN / IN_CONTAINS, AND within each group, groups AND-ed) and an entity crafted so every
// condition evaluates true, forcing full traversal rather than short-circuit.
func buildLegacyFixture(groups, conds int) (*policy.SubjectSet, flattening.Flattened) {
	attrs := map[string]interface{}{}
	cgs := make([]*policy.ConditionGroup, 0, groups)
	for g := 0; g < groups; g++ {
		conditions := make([]*policy.Condition, 0, conds)
		for j := 0; j < conds; j++ {
			key := fmt.Sprintf("a%d_%d", g, j)
			selector := "." + key + "[]"
			var op policy.SubjectMappingOperatorEnum
			var targets []string
			var entityVal string
			switch j % 3 {
			case 0:
				op = policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN
				targets, entityVal = []string{"match"}, "match"
			case 1:
				op = policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN
				targets, entityVal = []string{"absent"}, "present"
			default:
				op = policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS
				targets, entityVal = []string{"sub"}, "xxsubxx"
			}
			attrs[key] = []any{entityVal}
			conditions = append(conditions, &policy.Condition{
				SubjectExternalSelectorValue: selector,
				Operator:                     op,
				SubjectExternalValues:        targets,
			})
		}
		cgs = append(cgs, &policy.ConditionGroup{
			BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
			Conditions:      conditions,
		})
	}
	return mustFlattenSet(attrs, cgs)
}

// buildDecomposedFixture builds the same shape using the #3335 decomposed axes (comparison +
// quantifier + case_insensitive), again crafted so every condition is true.
func buildDecomposedFixture(groups, conds int) (*policy.SubjectSet, flattening.Flattened) {
	attrs := map[string]interface{}{}
	cgs := make([]*policy.ConditionGroup, 0, groups)
	for g := 0; g < groups; g++ {
		conditions := make([]*policy.Condition, 0, conds)
		for j := 0; j < conds; j++ {
			key := fmt.Sprintf("a%d_%d", g, j)
			selector := "." + key + "[]"
			var cmp policy.ConditionComparisonOperatorEnum
			var targets []string
			var entityVal string
			switch j % 4 {
			case 0:
				cmp = policy.ConditionComparisonOperatorEnum_CONDITION_COMPARISON_OPERATOR_ENUM_EQUALS
				targets, entityVal = []string{"match"}, "match"
			case 1:
				cmp = policy.ConditionComparisonOperatorEnum_CONDITION_COMPARISON_OPERATOR_ENUM_CONTAINS
				targets, entityVal = []string{"sub"}, "xxsubxx"
			case 2:
				cmp = policy.ConditionComparisonOperatorEnum_CONDITION_COMPARISON_OPERATOR_ENUM_STARTS_WITH
				targets, entityVal = []string{"pre"}, "preval"
			default:
				cmp = policy.ConditionComparisonOperatorEnum_CONDITION_COMPARISON_OPERATOR_ENUM_ENDS_WITH
				targets, entityVal = []string{"fix"}, "valfix"
			}
			attrs[key] = []any{entityVal}
			conditions = append(conditions, &policy.Condition{
				SubjectExternalSelectorValue: selector,
				Comparison:                   cmp,
				Quantifier:                   policy.ConditionQuantifierEnum_CONDITION_QUANTIFIER_ENUM_ANY,
				SubjectExternalValues:        targets,
			})
		}
		cgs = append(cgs, &policy.ConditionGroup{
			BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
			Conditions:      conditions,
		})
	}
	return mustFlattenSet(attrs, cgs)
}

func mustFlattenSet(attrs map[string]interface{}, cgs []*policy.ConditionGroup) (*policy.SubjectSet, flattening.Flattened) {
	flat, err := flattening.Flatten(attrs)
	if err != nil {
		panic(err)
	}
	return &policy.SubjectSet{ConditionGroups: cgs}, flat
}

// evalNativeDecomposedSubjectSet is a representative hand-written Go evaluator for the decomposed
// axes, mirroring EvaluateSubjectSet/EvaluateConditionGroup semantics (groups AND-ed; conditions by
// the group's boolean operator). It stands in for the production code the "keep bespoke" option
// would have to write to honor the merged #3335 protos.
func evalNativeDecomposedSubjectSet(ss *policy.SubjectSet, flat flattening.Flattened) bool {
	for _, cg := range ss.GetConditionGroups() {
		if !nativeDecomposedGroup(cg, flat) {
			return false
		}
	}
	return true
}

func nativeDecomposedGroup(cg *policy.ConditionGroup, flat flattening.Flattened) bool {
	if cg.GetBooleanOperator() == policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR {
		for _, c := range cg.GetConditions() {
			if nativeDecomposedCondition(c, flat) {
				return true
			}
		}
		return false
	}
	for _, c := range cg.GetConditions() {
		if !nativeDecomposedCondition(c, flat) {
			return false
		}
	}
	return true
}

func nativeDecomposedCondition(c *policy.Condition, flat flattening.Flattened) bool {
	mapped := flattening.GetFromFlattened(flat, c.GetSubjectExternalSelectorValue())
	ci := c.GetCaseInsensitive().GetValue()
	match := func(v, t string) bool {
		if ci {
			v, t = strings.ToLower(v), strings.ToLower(t)
		}
		//nolint:exhaustive // default handles unspecified/unsupported comparisons
		switch c.GetComparison() {
		case policy.ConditionComparisonOperatorEnum_CONDITION_COMPARISON_OPERATOR_ENUM_EQUALS:
			return v == t
		case policy.ConditionComparisonOperatorEnum_CONDITION_COMPARISON_OPERATOR_ENUM_CONTAINS:
			return strings.Contains(v, t)
		case policy.ConditionComparisonOperatorEnum_CONDITION_COMPARISON_OPERATOR_ENUM_STARTS_WITH:
			return strings.HasPrefix(v, t)
		case policy.ConditionComparisonOperatorEnum_CONDITION_COMPARISON_OPERATOR_ENUM_ENDS_WITH:
			return strings.HasSuffix(v, t)
		default:
			return false
		}
	}
	anyMatch := func() bool {
		for _, t := range c.GetSubjectExternalValues() {
			for _, mv := range mapped {
				if match(fmt.Sprintf("%v", mv), t) {
					return true
				}
			}
		}
		return false
	}
	//nolint:exhaustive // default handles unspecified/unsupported quantifiers
	switch c.GetQuantifier() {
	case policy.ConditionQuantifierEnum_CONDITION_QUANTIFIER_ENUM_ANY:
		return anyMatch()
	case policy.ConditionQuantifierEnum_CONDITION_QUANTIFIER_ENUM_ALL:
		for _, t := range c.GetSubjectExternalValues() {
			found := false
			for _, mv := range mapped {
				if match(fmt.Sprintf("%v", mv), t) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	case policy.ConditionQuantifierEnum_CONDITION_QUANTIFIER_ENUM_NONE:
		return !anyMatch()
	default:
		return false
	}
}

type opVariant struct {
	ops        string
	build      func(groups, conds int) (*policy.SubjectSet, flattening.Flattened)
	nativeEval func(ss *policy.SubjectSet, flat flattening.Flattened) (bool, error)
}

func TestCELOperatorBenchmark(t *testing.T) {
	out := os.Getenv("CEL_BENCH_OP_OUT")
	if out == "" {
		out = "operator_results.csv"
	}

	sizes := []opSize{
		{"small", 1, 1},
		{"medium", 3, 3},
		{"large", 10, 5},
	}
	variants := []opVariant{
		{
			ops:        "legacy",
			build:      buildLegacyFixture,
			nativeEval: subjectmappingbuiltin.EvaluateSubjectSet,
		},
		{
			ops:   "decomposed",
			build: buildDecomposedFixture,
			nativeEval: func(ss *policy.SubjectSet, flat flattening.Flattened) (bool, error) {
				return evalNativeDecomposedSubjectSet(ss, flat), nil
			},
		},
	}

	f, err := os.Create(out)
	require.NoError(t, err)
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	require.NoError(t, w.Write([]string{"layer", "arm", "ops", "groups", "conds", "ns_op", "allocs_op", "bytes_op"}))

	for _, v := range variants {
		for _, s := range sizes {
			ss, flat := v.build(s.groups, s.conds)

			prog, err := celeval.CompileSubjectSet(ss)
			require.NoError(t, err)
			nativeRes, err := v.nativeEval(ss, flat)
			require.NoError(t, err)
			celRes, err := prog.Eval(flat)
			require.NoError(t, err)
			require.Equalf(t, nativeRes, celRes, "ops=%s size=%s native and cel disagree", v.ops, s.name)

			native := testing.Benchmark(func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					_, _ = v.nativeEval(ss, flat)
				}
			})
			cel := testing.Benchmark(func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					_, _ = prog.Eval(flat)
				}
			})
			compile := testing.Benchmark(func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					_, _ = celeval.CompileSubjectSet(ss)
				}
			})

			writeOpRow(t, w, "native", v.ops, s, native)
			writeOpRow(t, w, "cel", v.ops, s, cel)
			writeOpRow(t, w, "cel_compile", v.ops, s, compile)

			t.Logf("%-10s %-7s groups=%2d conds=%2d  native=%8.1f ns/op  cel=%8.1f ns/op  compile=%10.1f ns/op  (cel/native=%.2fx)",
				v.ops, s.name, s.groups, s.conds,
				float64(native.NsPerOp()), float64(cel.NsPerOp()), float64(compile.NsPerOp()),
				float64(cel.NsPerOp())/float64(native.NsPerOp()))
		}
	}
}

func writeOpRow(t *testing.T, w *csv.Writer, arm, ops string, s opSize, r testing.BenchmarkResult) {
	t.Helper()
	require.NoError(t, w.Write([]string{
		"operator", arm, ops,
		strconv.Itoa(s.groups), strconv.Itoa(s.conds),
		strconv.FormatInt(r.NsPerOp(), 10),
		strconv.FormatInt(r.AllocsPerOp(), 10),
		strconv.FormatInt(r.AllocedBytesPerOp(), 10),
	}))
}
