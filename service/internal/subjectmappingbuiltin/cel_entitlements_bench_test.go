//go:build celbench

// Layer 2 of the CEL performance deliverable: entitlements-evaluation benchmark for the v2 path.
// The v2 PDP evaluates subject mappings in pure Go via
// EvaluateSubjectMappingMultipleEntitiesWithActions (service/internal/access/v2/pdp.go:460); there
// is no OPA/rego in v2 (that lives only in the legacy v1 authorization service). This benchmark
// isolates the operator engine on the step the v2 PDP performs, comparing the native Go evaluator
// against precompiled CEL across the number of subject mappings on the decision.
//
// End-to-end v2 decision cost (policy fetch, PDP construction, attribute-rule layer) is covered by
// the existing v2 PDP performance work and is not re-measured here.
//
// Build-tagged (celbench); driven by docs/performance/cel-condition-evaluation/run.sh, which sets
// CEL_BENCH_ENT_OUT.
//
//	go test -tags celbench -run TestCELEntitlementsBenchmark ./internal/subjectmappingbuiltin/
package subjectmappingbuiltin_test

import (
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"strconv"
	"testing"

	"github.com/opentdf/platform/lib/flattening"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/service/internal/subjectmappingbuiltin"
	"github.com/opentdf/platform/service/internal/subjectmappingbuiltin/celeval"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

const entSelector = ".attributes.role[]"

// buildEntitlementsFixture builds n attribute mappings, each with one subject mapping whose
// condition set matches an entity carrying role "analyst", plus the single matching entity.
func buildEntitlementsFixture(t *testing.T, n int) (map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue, *entityresolution.ResolveEntitiesResponse) {
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
									SubjectExternalSelectorValue: entSelector,
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

// entCompiledMapping holds the precompiled CEL programs for one attribute mapping's subject mappings
// (outer slice: subject mappings; inner slice: that mapping's subject sets).
type entCompiledMapping struct {
	attr            string
	subjectMappings [][]*celeval.Program
}

func compileEntitlementsMappings(t *testing.T, sms map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue) []entCompiledMapping {
	t.Helper()
	out := make([]entCompiledMapping, 0, len(sms))
	for attr, av := range sms {
		cm := entCompiledMapping{attr: attr}
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

// evalCELEntitlements mirrors EvaluateSubjectMappingMultipleEntities (subject mappings OR-ed,
// subject sets AND-ed) but evaluates conditions with precompiled CEL programs.
func evalCELEntitlements(compiled []entCompiledMapping, ers *entityresolution.ResolveEntitiesResponse) (map[string][]string, error) {
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

func TestCELEntitlementsBenchmark(t *testing.T) {
	out := os.Getenv("CEL_BENCH_ENT_OUT")
	if out == "" {
		out = "entitlements_results.csv"
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

	f, err := os.Create(out)
	require.NoError(t, err)
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	require.NoError(t, w.Write([]string{"layer", "arm", "mappings", "ns_op", "allocs_op", "bytes_op"}))

	for _, n := range sizes {
		sms, ers := buildEntitlementsFixture(t, n)
		compiled := compileEntitlementsMappings(t, sms)

		// Sanity: both arms agree on the entitlement set before timing.
		nativeRes, err := subjectmappingbuiltin.EvaluateSubjectMappingMultipleEntities(sms, ers.GetEntityRepresentations())
		require.NoError(t, err)
		celRes, err := evalCELEntitlements(compiled, ers)
		require.NoError(t, err)
		requireSameEntitlements(t, nativeRes, celRes)

		native := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = subjectmappingbuiltin.EvaluateSubjectMappingMultipleEntities(sms, ers.GetEntityRepresentations())
			}
		})
		cel := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = evalCELEntitlements(compiled, ers)
			}
		})

		writeEntRow(t, w, "native", n, native)
		writeEntRow(t, w, "cel", n, cel)

		t.Logf("mappings=%5d  native=%8.1f µs  cel=%8.1f µs  (cel/native=%.1fx)",
			n, float64(native.NsPerOp())/1000, float64(cel.NsPerOp())/1000,
			float64(cel.NsPerOp())/float64(native.NsPerOp()))
	}
}

func writeEntRow(t *testing.T, w *csv.Writer, arm string, n int, r testing.BenchmarkResult) {
	t.Helper()
	require.NoError(t, w.Write([]string{
		"entitlements", arm, strconv.Itoa(n),
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
