//go:build celbench

// Layer 2 of the DSPX-3673 performance deliverable: full entitlements-path benchmark. Measures the
// per-request cost of three ways to compute entitlements over the same policy + entity:
//
//   - rego:      the status quo. OpaInput (protojson marshal) + the prepared OPA query, which calls
//     the subjectmapping.resolve builtin -> EvaluateSubjectMappingMultipleEntities.
//   - go_switch: EvaluateSubjectMappingMultipleEntities directly, no OPA.
//   - go_cel:    the same orchestration with condition evaluation via precompiled CEL (celeval).
//
// rego vs go_switch isolates the OPA + serialization overhead; go_switch vs go_cel isolates the
// operator-engine difference at full granularity. Build-tagged (celbench) and driven by
// docs/performance/DSPX-3673-cel-condition-evaluation/run.sh (sets CEL_BENCH_FP_OUT, CEL_BENCH_MAX_N).
//
//	go test -tags celbench -run TestCELFullPathBenchmark ./authorization/
package authorization_test

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"strconv"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/opentdf/platform/lib/flattening"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/service/authorization/policies"
	"github.com/opentdf/platform/service/internal/entitlements"
	"github.com/opentdf/platform/service/internal/subjectmappingbuiltin"
	"github.com/opentdf/platform/service/internal/subjectmappingbuiltin/celeval"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

const fpSelector = ".attributes.role[]"

// buildFullPathFixture builds n attribute mappings, each with one subject mapping whose condition
// set matches an entity carrying role "analyst", plus the single matching entity.
func buildFullPathFixture(t *testing.T, n int) (map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue, *entityresolution.ResolveEntitiesResponse) {
	t.Helper()
	sms := make(map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue, n)
	for i := 0; i < n; i++ {
		fqn := fmt.Sprintf("https://example.com/attr/role/value/v%d", i)
		sms[fqn] = &attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{
			Value: &policy.Value{
				Fqn: fqn,
				SubjectMappings: []*policy.SubjectMapping{{
					SubjectConditionSet: &policy.SubjectConditionSet{
						SubjectSets: []*policy.SubjectSet{{
							ConditionGroups: []*policy.ConditionGroup{{
								BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
								Conditions: []*policy.Condition{{
									SubjectExternalSelectorValue: fpSelector,
									Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
									SubjectExternalValues:        []string{"analyst"},
								}},
							}},
						}},
					},
				}},
			},
		}
	}

	props, err := structpb.NewStruct(map[string]interface{}{
		"attributes": map[string]interface{}{"role": []interface{}{"analyst"}},
	})
	require.NoError(t, err)
	ers := &entityresolution.ResolveEntitiesResponse{
		EntityRepresentations: []*entityresolution.EntityRepresentation{{
			OriginalId:      "entity-1",
			AdditionalProps: []*structpb.Struct{props},
		}},
	}
	return sms, ers
}

// compiledMapping holds the precompiled CEL programs for one attribute mapping's subject mappings
// (outer slice: subject mappings; inner slice: that mapping's subject sets).
type compiledMapping struct {
	attr            string
	subjectMappings [][]*celeval.Program
}

func compileMappings(t *testing.T, sms map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue) []compiledMapping {
	t.Helper()
	out := make([]compiledMapping, 0, len(sms))
	for attr, av := range sms {
		cm := compiledMapping{attr: attr}
		for _, sm := range av.GetValue().GetSubjectMappings() {
			programs := make([]*celeval.Program, 0)
			for _, ss := range sm.GetSubjectConditionSet().GetSubjectSets() {
				prog, err := celeval.CompileSubjectSet(ss)
				require.NoError(t, err)
				programs = append(programs, prog)
			}
			cm.subjectMappings = append(cm.subjectMappings, programs)
		}
		out = append(out, cm)
	}
	return out
}

// evalCELMultipleEntities mirrors EvaluateSubjectMappingMultipleEntities (subject mappings OR-ed,
// subject sets AND-ed) but evaluates conditions with precompiled CEL programs.
func evalCELMultipleEntities(compiled []compiledMapping, ers *entityresolution.ResolveEntitiesResponse) (map[string][]string, error) {
	results := make(map[string][]string)
	for _, er := range ers.GetEntityRepresentations() {
		set := make(map[string]bool)
		for _, entity := range er.GetAdditionalProps() {
			flat, err := flattening.Flatten(entity.AsMap())
			if err != nil {
				return nil, err
			}
			for _, cm := range compiled {
				matched := false
				for _, programs := range cm.subjectMappings {
					smResult := true
					for _, prog := range programs {
						r, err := prog.Eval(flat)
						if err != nil {
							return nil, err
						}
						smResult = smResult && r
						if !smResult {
							break
						}
					}
					matched = matched || smResult
					if matched {
						break
					}
				}
				if matched {
					set[cm.attr] = true
				}
			}
		}
		entitlements := make([]string, 0, len(set))
		for k := range set {
			entitlements = append(entitlements, k)
		}
		results[er.GetOriginalId()] = entitlements
	}
	return results, nil
}

func TestCELFullPathBenchmark(t *testing.T) {
	out := os.Getenv("CEL_BENCH_FP_OUT")
	if out == "" {
		out = "fullpath_results.csv"
	}
	maxN := 5000
	if v := os.Getenv("CEL_BENCH_MAX_N"); v != "" {
		parsed, err := strconv.Atoi(v)
		require.NoError(t, err)
		maxN = parsed
	}

	allSizes := []int{100, 1000, 5000}
	sizes := make([]int, 0, len(allSizes))
	for _, n := range allSizes {
		if n <= maxN {
			sizes = append(sizes, n)
		}
	}

	// Prepare the OPA query once (mirrors authorization.go loadRegoAndBuiltins).
	subjectmappingbuiltin.SubjectMappingBuiltin()
	regoModule, err := policies.EntitlementsRego.ReadFile("entitlements/entitlements.rego")
	require.NoError(t, err)
	prepared, err := rego.New(
		rego.Query("data.opentdf.entitlements.attributes"),
		rego.Module("entitlements.rego", string(regoModule)),
		rego.SetRegoVersion(ast.RegoV0),
		rego.StrictBuiltinErrors(true),
	).PrepareForEval(context.Background())
	require.NoError(t, err)

	f, err := os.Create(out)
	require.NoError(t, err)
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	require.NoError(t, w.Write([]string{"layer", "arm", "mappings", "ns_op", "allocs_op", "bytes_op"}))

	ctx := context.Background()
	for _, n := range sizes {
		sms, ers := buildFullPathFixture(t, n)
		compiled := compileMappings(t, sms)

		// Sanity: all three arms agree on the entitlement set before timing.
		goRes, err := subjectmappingbuiltin.EvaluateSubjectMappingMultipleEntities(sms, ers.GetEntityRepresentations())
		require.NoError(t, err)
		celRes, err := evalCELMultipleEntities(compiled, ers)
		require.NoError(t, err)
		requireSameEntitlements(t, goRes, celRes)

		regoB := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				in, _ := entitlements.OpaInput(sms, ers)
				_, _ = prepared.Eval(ctx, rego.EvalInput(in))
			}
		})
		goB := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = subjectmappingbuiltin.EvaluateSubjectMappingMultipleEntities(sms, ers.GetEntityRepresentations())
			}
		})
		celB := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = evalCELMultipleEntities(compiled, ers)
			}
		})

		writeFPRow(t, w, "rego", n, regoB)
		writeFPRow(t, w, "go_switch", n, goB)
		writeFPRow(t, w, "go_cel", n, celB)

		t.Logf("mappings=%5d  rego=%10.1f µs  go_switch=%8.1f µs  go_cel=%8.1f µs  (rego/go_switch=%.1fx)",
			n,
			float64(regoB.NsPerOp())/1000, float64(goB.NsPerOp())/1000, float64(celB.NsPerOp())/1000,
			float64(regoB.NsPerOp())/float64(goB.NsPerOp()))
	}
}

func writeFPRow(t *testing.T, w *csv.Writer, arm string, n int, r testing.BenchmarkResult) {
	t.Helper()
	require.NoError(t, w.Write([]string{
		"fullpath", arm, strconv.Itoa(n),
		strconv.FormatInt(r.NsPerOp(), 10),
		strconv.FormatInt(r.AllocsPerOp(), 10),
		strconv.FormatInt(r.AllocedBytesPerOp(), 10),
	}))
}

func requireSameEntitlements(t *testing.T, a, b map[string][]string) {
	t.Helper()
	require.Len(t, b, len(a))
	for k, av := range a {
		bv, ok := b[k]
		require.True(t, ok)
		sort.Strings(av)
		sort.Strings(bv)
		require.Equal(t, av, bv)
	}
}
