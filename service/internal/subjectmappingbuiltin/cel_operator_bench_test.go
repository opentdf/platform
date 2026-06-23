//go:build celbench

// Layer 1 of the DSPX-3673 performance deliverable: operator-engine micro-benchmark. Compares the
// per-evaluation cost of the native operator switch (EvaluateSubjectSet) against a precompiled CEL
// program (celeval), and reports the one-time CEL compile cost separately.
//
// Build-tagged (celbench) so it never runs in the default suite, mirroring the entpdpbench /
// entbench gating in the existing perf deliverables. Driven by
// docs/performance/DSPX-3673-cel-condition-evaluation/run.sh, which sets CEL_BENCH_OP_OUT.
//
//	go test -tags celbench -run TestCELOperatorBenchmark ./internal/subjectmappingbuiltin/
package subjectmappingbuiltin_test

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
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

// buildOperatorFixture builds a SubjectSet of groups x conds conditions (mixed legacy operators,
// AND within each group, groups AND-ed) and an entity crafted so every condition evaluates true,
// forcing full traversal rather than short-circuit.
func buildOperatorFixture(groups, conds int) (*policy.SubjectSet, flattening.Flattened) {
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
				targets = []string{"match"}
				entityVal = "match" // present -> IN true
			case 1:
				op = policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN
				targets = []string{"absent"}
				entityVal = "present" // target absent -> NOT_IN true
			default:
				op = policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS
				targets = []string{"sub"}
				entityVal = "xxsubxx" // contains -> IN_CONTAINS true
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

	flat, err := flattening.Flatten(attrs)
	if err != nil {
		panic(err)
	}
	return &policy.SubjectSet{ConditionGroups: cgs}, flat
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

	f, err := os.Create(out)
	require.NoError(t, err)
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	require.NoError(t, w.Write([]string{"layer", "arm", "groups", "conds", "ns_op", "allocs_op", "bytes_op"}))

	for _, s := range sizes {
		ss, flat := buildOperatorFixture(s.groups, s.conds)

		// Sanity: native and CEL agree before timing.
		prog, err := celeval.CompileSubjectSet(ss)
		require.NoError(t, err)
		nativeRes, err := subjectmappingbuiltin.EvaluateSubjectSet(ss, flat)
		require.NoError(t, err)
		celRes, err := prog.Eval(flat)
		require.NoError(t, err)
		require.Equal(t, nativeRes, celRes, "size=%s native and cel disagree", s.name)

		native := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = subjectmappingbuiltin.EvaluateSubjectSet(ss, flat)
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

		writeOpRow(t, w, "native", s, native)
		writeOpRow(t, w, "cel", s, cel)
		writeOpRow(t, w, "cel_compile", s, compile)

		t.Logf("%-7s groups=%2d conds=%2d  native=%8.1f ns/op  cel=%8.1f ns/op  compile=%10.1f ns/op  (cel/native=%.2fx)",
			s.name, s.groups, s.conds,
			fns(native.NsPerOp()), fns(cel.NsPerOp()), fns(compile.NsPerOp()),
			float64(cel.NsPerOp())/float64(native.NsPerOp()))
	}
}

func writeOpRow(t *testing.T, w *csv.Writer, arm string, s opSize, r testing.BenchmarkResult) {
	t.Helper()
	require.NoError(t, w.Write([]string{
		"operator", arm,
		strconv.Itoa(s.groups), strconv.Itoa(s.conds),
		strconv.FormatInt(r.NsPerOp(), 10),
		strconv.FormatInt(r.AllocsPerOp(), 10),
		strconv.FormatInt(r.AllocedBytesPerOp(), 10),
	}))
}

func fns(v int64) float64 { return float64(v) }
