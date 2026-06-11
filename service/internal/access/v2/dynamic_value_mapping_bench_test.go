//go:build dvmbench

// Package access benchmark harness for DSPX-2754.
//
// This file compiles only under `-tags dvmbench`, so it never runs in normal
// `go test ./...` or CI. It measures the cost asymmetry between the two
// entitlement paths at NG SAP scale (see
// docs/performance/dspx-2754-dynamic-value-mappings/README.md):
//
//   - Static subject mappings: NewPolicyDecisionPoint retains every one of the N
//     subject mappings, so construction and memory grow O(N) and a single
//     decision evaluates every mapping attached to the requested value (~N/5000).
//   - Dynamic value mappings: one definition-level DynamicValueMapping replaces
//     the per-(user, value) explosion, so construction and memory are O(1) in N
//     and a decision cost depends only on the entity's cleared-set size.
//
// It reuses the unexported helpers from pdp_test.go (createAttrFQN,
// createAttrValueFQN, createSimpleSubjectMapping, createAttributeValueResource,
// testActionRead, PDPTestSuite.createEntityWithProps) which are always in the
// test binary.
//
// Run:
//
//	DVM_BENCH_OUT=docs/performance/dspx-2754-dynamic-value-mappings/results.csv \
//	  go test -tags dvmbench -run TestDVMScaleBenchmark -timeout 60m \
//	  ./service/internal/access/v2/
package access

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"testing"
	"time"

	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/logger"
)

const (
	// numCompartments is the fixed count of NTK compartment values, matching the
	// NG SAP "~5,000 compartment values" parameter. The static subject-mapping
	// count N is spread across these values, so a single value carries ~N/5000
	// mappings.
	numCompartments = 5000
	// dynamicClearedSetSize is the number of compartments a representative analyst
	// is cleared for, carried on the entity as a selector-resolved set. The dynamic
	// decision cost scales with this, not with N.
	dynamicClearedSetSize = 50
	// decisionIters is the number of timed GetDecision calls per scale point.
	decisionIters = 2000
	// decisionWarmup is the number of untimed warm-up decisions.
	decisionWarmup = 200
)

// benchScalePoints is the set of total subject-mapping counts (N) measured.
// Override the ceiling with DVM_BENCH_MAX_N to fit the host's memory.
var benchScalePoints = []int{5_000, 20_000, 100_000, 500_000, 1_000_000, 2_000_000, 5_000_000}

// benchNamespace is the policy namespace used for both corpora.
var benchNamespace = &policy.Namespace{Name: "sap.gov", Fqn: "https://sap.gov"}

// benchRow is one measured (mode, N) data point written to the CSV.
type benchRow struct {
	mode         string
	n            int
	constructMS  float64
	heapMB       float64
	decisionMean float64 // microseconds
	decisionP50  float64 // microseconds
	decisionP99  float64 // microseconds
	permitted    bool
}

// TestDVMScaleBenchmark builds the static and dynamic corpora at each scale point,
// measures construction time, retained heap, and decision latency, and writes a CSV.
func TestDVMScaleBenchmark(t *testing.T) {
	l, err := logger.NewLogger(logger.Config{Level: "error", Type: "json", Output: "stdout"})
	if err != nil {
		t.Fatalf("failed to build quiet logger: %v", err)
	}

	points := scalePoints(t)
	out := os.Getenv("DVM_BENCH_OUT")
	if out == "" {
		out = "results.csv"
	}

	rows := make([]benchRow, 0, len(points)*2)
	for _, n := range points {
		t.Logf("measuring static  N=%d ...", n)
		rows = append(rows, measureStatic(t, l, n))
		t.Logf("measuring dynamic N=%d ...", n)
		rows = append(rows, measureDynamic(t, l, n))
	}

	writeCSV(t, out, rows)
	t.Logf("wrote %d rows to %s", len(rows), out)
}

// scalePoints returns the scale points to measure, capped by DVM_BENCH_MAX_N.
func scalePoints(t *testing.T) []int {
	maxN := 0
	if raw := os.Getenv("DVM_BENCH_MAX_N"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			t.Fatalf("invalid DVM_BENCH_MAX_N %q: %v", raw, err)
		}
		maxN = parsed
	}
	points := make([]int, 0, len(benchScalePoints))
	for _, n := range benchScalePoints {
		if maxN > 0 && n > maxN {
			continue
		}
		points = append(points, n)
	}
	if len(points) == 0 {
		t.Fatalf("no scale points to measure (DVM_BENCH_MAX_N=%d too small)", maxN)
	}
	return points
}

// measureStatic builds a static-subject-mapping PDP at scale N and times it.
func measureStatic(t *testing.T, l *logger.Logger, n int) benchRow {
	row := benchRow{mode: "static", n: n}

	// Baseline heap BEFORE building the corpus, so the delta captures the full
	// retained policy footprint: the N subject-mapping protos plus the PDP index.
	runtime.GC()
	var m0 runtime.MemStats
	runtime.ReadMemStats(&m0)

	defValues := make([]*policy.Value, numCompartments)
	for i := 0; i < numCompartments; i++ {
		defValues[i] = &policy.Value{
			Fqn:   compartmentValueFQN(i),
			Value: compartmentName(i),
		}
	}
	def := &policy.Attribute{
		Fqn:       createAttrFQN("sap.gov", "ntk"),
		Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Namespace: benchNamespace,
		Values:    defValues,
	}

	// N subject mappings, each pinning one synthetic user to one compartment value.
	// This models the user x compartment cross-product the static design forces.
	subjectMappings := make([]*policy.SubjectMapping, n)
	for i := 0; i < n; i++ {
		comp := i % numCompartments
		subjectMappings[i] = createSimpleSubjectMapping(
			compartmentValueFQN(comp),
			compartmentName(comp),
			[]*policy.Action{testActionRead},
			".properties.userId",
			[]string{fmt.Sprintf("user-%d", i)},
			benchNamespace,
		)
	}

	// The analyst is user-0, who is cleared for compartment-0 via subject mapping 0.
	entity := (&PDPTestSuite{}).createEntityWithProps("analyst", map[string]interface{}{
		"userId": "user-0",
	})
	resources := []*authz.Resource{createAttributeValueResource("doc", compartmentValueFQN(0))}

	start := time.Now()
	pdp, err := NewPolicyDecisionPoint(
		t.Context(),
		l,
		[]*policy.Attribute{def},
		subjectMappings,
		nil,
		false,
		false,
	)
	row.constructMS = float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil {
		t.Fatalf("static NewPolicyDecisionPoint N=%d: %v", n, err)
	}

	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	row.heapMB = heapDeltaMB(m0, m1)

	row.permitted = measureDecisionLatency(t, pdp, entity, resources, &row)

	// Keep the corpus alive until after measurement, then drop it for the next point.
	runtime.KeepAlive(subjectMappings)
	runtime.KeepAlive(pdp)
	return row
}

// measureDynamic builds a dynamic-value-mapping PDP at scale N and times it.
// The dynamic corpus is O(1) in N: one definition-level mapping regardless of N.
func measureDynamic(t *testing.T, l *logger.Logger, n int) benchRow {
	row := benchRow{mode: "dynamic", n: n}

	// Baseline heap BEFORE building the corpus, measured the same way as static.
	runtime.GC()
	var m0 runtime.MemStats
	runtime.ReadMemStats(&m0)

	// A dynamic definition carries no statically provisioned values.
	def := &policy.Attribute{
		Fqn:       createAttrFQN("sap.gov", "ntk"),
		Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Namespace: benchNamespace,
	}
	mapping := &policy.DynamicValueMapping{
		AttributeDefinition: def,
		ValueResolver: &policy.DynamicValueResolver{
			SubjectExternalSelectorValue: ".properties.compartments[]",
			Operator:                     policy.DynamicValueOperatorEnum_DYNAMIC_VALUE_OPERATOR_ENUM_RESOURCE_VALUE_IN,
		},
		Actions:   []*policy.Action{testActionRead},
		Namespace: benchNamespace,
	}

	// The analyst carries the compartments they are cleared for, resolved from the
	// IdP/ERS at decision time. compartment-0 is in the set, so the resource permits.
	cleared := make([]interface{}, dynamicClearedSetSize)
	for i := 0; i < dynamicClearedSetSize; i++ {
		cleared[i] = compartmentName(i)
	}
	entity := (&PDPTestSuite{}).createEntityWithProps("analyst", map[string]interface{}{
		"compartments": cleared,
	})
	resources := []*authz.Resource{createAttributeValueResource("doc", compartmentValueFQN(0))}

	start := time.Now()
	pdp, err := NewPolicyDecisionPointWithDynamicValueMappings(
		t.Context(),
		l,
		[]*policy.Attribute{def},
		[]*policy.SubjectMapping{},
		[]*policy.DynamicValueMapping{mapping},
		nil,
		false,
		false,
	)
	row.constructMS = float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil {
		t.Fatalf("dynamic NewPolicyDecisionPointWithDynamicValueMappings N=%d: %v", n, err)
	}

	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	row.heapMB = heapDeltaMB(m0, m1)

	row.permitted = measureDecisionLatency(t, pdp, entity, resources, &row)

	runtime.KeepAlive(pdp)
	return row
}

// measureDecisionLatency warms up, then times decisionIters GetDecision calls,
// recording mean/p50/p99 (microseconds) onto row. It returns whether the decision
// permitted, which the caller asserts so we never time a misconfigured deny path.
func measureDecisionLatency(
	t *testing.T,
	pdp *PolicyDecisionPoint,
	er *entityresolutionV2.EntityRepresentation,
	resources []*authz.Resource,
	row *benchRow,
) bool {
	ctx := t.Context()

	permitted := false
	for i := 0; i < decisionWarmup; i++ {
		decision, _, err := pdp.GetDecision(ctx, er, testActionRead, resources)
		if err != nil {
			t.Fatalf("%s N=%d GetDecision warmup: %v", row.mode, row.n, err)
		}
		permitted = decision.AllPermitted
	}

	durs := make([]time.Duration, decisionIters)
	for i := 0; i < decisionIters; i++ {
		start := time.Now()
		decision, _, err := pdp.GetDecision(ctx, er, testActionRead, resources)
		durs[i] = time.Since(start)
		if err != nil {
			t.Fatalf("%s N=%d GetDecision: %v", row.mode, row.n, err)
		}
		permitted = permitted && decision.AllPermitted
	}

	sort.Slice(durs, func(a, b int) bool { return durs[a] < durs[b] })
	var total time.Duration
	for _, d := range durs {
		total += d
	}
	row.decisionMean = usPerOp(total, len(durs))
	row.decisionP50 = usDur(durs[len(durs)*50/100])
	row.decisionP99 = usDur(durs[len(durs)*99/100])
	return permitted
}

func compartmentName(i int) string { return "compartment-" + strconv.Itoa(i) }

func compartmentValueFQN(i int) string {
	return createAttrValueFQN("sap.gov", "ntk", compartmentName(i))
}

func heapDeltaMB(m0, m1 runtime.MemStats) float64 {
	delta := int64(m1.HeapInuse) - int64(m0.HeapInuse)
	if delta < 0 {
		delta = 0
	}
	return float64(delta) / (1024.0 * 1024.0)
}

func usDur(d time.Duration) float64 { return float64(d.Nanoseconds()) / 1000.0 }

func usPerOp(total time.Duration, n int) float64 {
	if n == 0 {
		return 0
	}
	return float64(total.Nanoseconds()) / float64(n) / 1000.0
}

// writeCSV writes all rows, after asserting every decision permitted.
func writeCSV(t *testing.T, path string, rows []benchRow) {
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()

	if _, err := fmt.Fprintln(f, "mode,n,construct_ms,heap_mb,decision_mean_us,decision_p50_us,decision_p99_us,permitted"); err != nil {
		t.Fatalf("write header: %v", err)
	}
	for _, r := range rows {
		if !r.permitted {
			t.Fatalf("%s N=%d did not permit; corpus is misconfigured, refusing to record timings", r.mode, r.n)
		}
		if _, err := fmt.Fprintf(f, "%s,%d,%.3f,%.3f,%.3f,%.3f,%.3f,%t\n",
			r.mode, r.n, r.constructMS, r.heapMB, r.decisionMean, r.decisionP50, r.decisionP99, r.permitted); err != nil {
			t.Fatalf("write row: %v", err)
		}
	}
}
