//go:build entpdpbench

// In-memory PDP benchmark for DSPX-2541: GetDecision and GetEntitlements.
//
// This file compiles only under `-tags entpdpbench`, so it never runs in normal
// `go test ./...` or CI. It needs no Docker/DB/server — it drives the PDP
// in-memory, mirroring origin/dspx-2754-perf-test's dynamic_value_mapping_bench_test.go.
//
// For each scale point N (total subject mappings) it measures two modes per
// operation, building a fresh corpus each time so the heap delta reflects the
// retained footprint:
//
//   - *_full: NewPolicyDecisionPoint over ALL policy (today's per-request load),
//     then GetDecision / GetEntitlements. Construction time + heap grow O(N).
//   - *_scoped: NewPolicyDecisionPoint over only the subset the operation needs
//     (the resource's value+SMs for a decision; the entity's matched values+SMs
//     for entitlements). Projects the optimized fetch the migration would realize.
//     It is shape-independent (operates on in-memory protos via the existing PDP)
//     and uses an ANY_OF corpus so the needed subset is unambiguous.
//
// Run:
//
//	ENT_PDP_OUT=docs/performance/DSPX-2541-entitleable-attributes/pdp_results.csv \
//	  go test -tags entpdpbench -run TestEntitleablePDPBenchmark -timeout 60m -v \
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
	// entPDPNumValues is the count of attribute values N subject mappings are
	// spread across, matching the NG SAP ~5,000 compartments.
	entPDPNumValues = 5000
	// entPDPMatches is the number of compartments a representative entity is
	// cleared for; GetEntitlements' scoped cost tracks this, not N.
	entPDPMatches = 50
	// decision iters/warmup: GetDecision is cheap, so time many.
	decIters  = 500
	decWarmup = 50
	// entitlements iters/warmup: GetEntitlements_full is O(N), so time fewer.
	entIters  = 50
	entWarmup = 5
)

var (
	benchNamespaceName = "sap.gov"
	benchNamespace     = &policy.Namespace{Name: benchNamespaceName, Fqn: "https://sap.gov"}
	pdpScalePoints     = []int{10_000, 50_000, 100_000, 500_000, 1_000_000}
)

type pdpRow struct {
	op          string
	mode        string
	n           int
	constructMS float64
	heapMB      float64
	mean        float64
	p50         float64
	p99         float64
	ok          bool
}

// TestEntitleablePDPBenchmark builds full and scoped corpora per scale point and
// measures GetDecision and GetEntitlements construction, heap, and latency.
func TestEntitleablePDPBenchmark(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in-memory PDP benchmark in short mode")
	}
	l, err := logger.NewLogger(logger.Config{Level: "error", Type: "json", Output: "stdout"})
	if err != nil {
		t.Fatalf("build quiet logger: %v", err)
	}

	// Entities: a decision entity cleared for one compartment, and an entitlements
	// entity cleared for entPDPMatches compartments.
	decisionEntity := newClearedEntity(1)
	entitlementsEntity := newClearedEntity(entPDPMatches)
	resource := createAttributeValueResource("doc", compartmentValueFQN(0))

	points := pdpScalePoints
	if maxN := pdpEnvInt(t, "ENT_PDP_MAX_N"); maxN > 0 {
		filtered := points[:0:0]
		for _, n := range points {
			if n <= maxN {
				filtered = append(filtered, n)
			}
		}
		points = filtered
	}
	if len(points) == 0 {
		t.Fatal("no scale points to measure (ENT_PDP_MAX_N too small)")
	}

	rows := make([]pdpRow, 0, len(points)*4)
	for _, n := range points {
		// decision_full: PDP over all policy; decision over one resource value.
		t.Logf("decision full N=%d ...", n)
		rows = append(rows, measurePDP(t, l, "decision", "full", n, decIters, decWarmup,
			func() (*policy.Attribute, []*policy.SubjectMapping) { return buildStaticCorpus(entPDPNumValues, n) },
			func(pdp *PolicyDecisionPoint, _ []*policy.SubjectMapping) (bool, error) {
				d, _, err := pdp.GetDecision(t.Context(), decisionEntity, testActionRead, []*authz.Resource{resource})
				if err != nil {
					return false, err
				}
				return d.AllPermitted, nil
			}))

		// decision_scoped: PDP over only the resource value + its SMs (N/numValues).
		t.Logf("decision scoped N=%d ...", n)
		rows = append(rows, measurePDP(t, l, "decision", "scoped", n, decIters, decWarmup,
			func() (*policy.Attribute, []*policy.SubjectMapping) { return buildStaticCorpus(1, n/entPDPNumValues) },
			func(pdp *PolicyDecisionPoint, _ []*policy.SubjectMapping) (bool, error) {
				d, _, err := pdp.GetDecision(t.Context(), decisionEntity, testActionRead, []*authz.Resource{resource})
				if err != nil {
					return false, err
				}
				return d.AllPermitted, nil
			}))

		// entitlements_full: PDP over all policy; entitlements evaluates all N SMs.
		t.Logf("entitlements full N=%d ...", n)
		rows = append(rows, measurePDP(t, l, "entitlements", "full", n, entIters, entWarmup,
			func() (*policy.Attribute, []*policy.SubjectMapping) { return buildStaticCorpus(entPDPNumValues, n) },
			func(pdp *PolicyDecisionPoint, _ []*policy.SubjectMapping) (bool, error) {
				ents, err := pdp.GetEntitlements(t.Context(), []*entityresolutionV2.EntityRepresentation{entitlementsEntity}, nil, false)
				if err != nil {
					return false, err
				}
				return entitledCount(ents) >= entPDPMatches, nil
			}))

		// entitlements_scoped: PDP over only the entity's matched values + SMs
		// (numValues=entPDPMatches, numSMs=N*entPDPMatches/numValues), and pass the
		// matched SMs to GetEntitlements (projects MatchSubjectMappings -> fetch).
		t.Logf("entitlements scoped N=%d ...", n)
		rows = append(rows, measurePDP(t, l, "entitlements", "scoped", n, entIters, entWarmup,
			func() (*policy.Attribute, []*policy.SubjectMapping) {
				return buildStaticCorpus(entPDPMatches, n*entPDPMatches/entPDPNumValues)
			},
			func(pdp *PolicyDecisionPoint, sms []*policy.SubjectMapping) (bool, error) {
				ents, err := pdp.GetEntitlements(t.Context(), []*entityresolutionV2.EntityRepresentation{entitlementsEntity}, sms, false)
				if err != nil {
					return false, err
				}
				return entitledCount(ents) >= entPDPMatches, nil
			}))
	}

	writePDPCSV(t, rows)
}

// measurePDP builds a corpus, times PDP construction and retained heap, then times
// the operation (warmup + iters → mean/p50/p99). build runs inside the measured
// region so heap captures the corpus plus the PDP index.
func measurePDP(
	t *testing.T,
	l *logger.Logger,
	op, mode string,
	n, iters, warmup int,
	build func() (*policy.Attribute, []*policy.SubjectMapping),
	run func(pdp *PolicyDecisionPoint, sms []*policy.SubjectMapping) (bool, error),
) pdpRow {
	row := pdpRow{op: op, mode: mode, n: n}

	runtime.GC()
	var m0 runtime.MemStats
	runtime.ReadMemStats(&m0)

	def, sms := build()

	start := time.Now()
	pdp, err := NewPolicyDecisionPoint(t.Context(), l, []*policy.Attribute{def}, sms, nil, false, false)
	row.constructMS = float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil {
		t.Fatalf("%s/%s N=%d NewPolicyDecisionPoint: %v", op, mode, n, err)
	}

	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	row.heapMB = heapDeltaMB(m0, m1)

	ok := false
	for i := 0; i < warmup; i++ {
		ok, err = run(pdp, sms)
		if err != nil {
			t.Fatalf("%s/%s N=%d warmup: %v", op, mode, n, err)
		}
	}
	durs := make([]time.Duration, iters)
	for i := 0; i < iters; i++ {
		s := time.Now()
		o, err := run(pdp, sms)
		durs[i] = time.Since(s)
		if err != nil {
			t.Fatalf("%s/%s N=%d op: %v", op, mode, n, err)
		}
		ok = ok && o
	}
	row.ok = ok

	sort.Slice(durs, func(a, b int) bool { return durs[a] < durs[b] })
	var total time.Duration
	for _, d := range durs {
		total += d
	}
	row.mean = usPerOp(total, len(durs))
	row.p50 = usDur(durs[len(durs)*50/100])
	row.p99 = usDur(durs[len(durs)*99/100])

	runtime.KeepAlive(sms)
	runtime.KeepAlive(pdp)
	return row
}

// buildStaticCorpus builds one ANY_OF definition with numValues values and numSMs
// subject mappings spread across them (SM i on value i%numValues, condition
// `.properties.clearances[] IN [compartment-(i%numValues)]`).
func buildStaticCorpus(numValues, numSMs int) (*policy.Attribute, []*policy.SubjectMapping) {
	if numSMs < 1 {
		numSMs = 1
	}
	vals := make([]*policy.Value, numValues)
	for i := 0; i < numValues; i++ {
		vals[i] = &policy.Value{Fqn: compartmentValueFQN(i), Value: compartmentName(i)}
	}
	def := &policy.Attribute{
		Fqn:       createAttrFQN(benchNamespaceName, "ntk"),
		Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Namespace: benchNamespace,
		Values:    vals,
	}
	sms := make([]*policy.SubjectMapping, numSMs)
	for i := 0; i < numSMs; i++ {
		c := i % numValues
		sms[i] = createSimpleSubjectMapping(
			compartmentValueFQN(c),
			compartmentName(c),
			[]*policy.Action{testActionRead},
			".properties.clearances[]",
			[]string{compartmentName(c)},
			benchNamespace,
		)
	}
	return def, sms
}

// newClearedEntity builds an entity cleared for the first m compartments.
func newClearedEntity(m int) *entityresolutionV2.EntityRepresentation {
	cleared := make([]interface{}, m)
	for i := 0; i < m; i++ {
		cleared[i] = compartmentName(i)
	}
	return (&PDPTestSuite{}).createEntityWithProps("analyst", map[string]interface{}{
		"clearances": cleared,
	})
}

func entitledCount(ents []*authz.EntityEntitlements) int {
	count := 0
	for _, e := range ents {
		count += len(e.GetActionsPerAttributeValueFqn())
	}
	return count
}

func compartmentName(i int) string { return "compartment-" + strconv.Itoa(i) }

func compartmentValueFQN(i int) string {
	return createAttrValueFQN(benchNamespaceName, "ntk", compartmentName(i))
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

func pdpEnvInt(t *testing.T, name string) int {
	raw := os.Getenv(name)
	if raw == "" {
		return 0
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatalf("invalid %s %q: %v", name, raw, err)
	}
	return parsed
}

func writePDPCSV(t *testing.T, rows []pdpRow) {
	out := os.Getenv("ENT_PDP_OUT")
	if out == "" {
		out = "pdp_results.csv"
	}
	f, err := os.Create(out)
	if err != nil {
		t.Fatalf("create %s: %v", out, err)
	}
	defer f.Close()

	if _, err := fmt.Fprintln(f, "op,mode,n,construct_ms,heap_mb,op_mean_us,op_p50_us,op_p99_us"); err != nil {
		t.Fatalf("write header: %v", err)
	}
	for _, r := range rows {
		if !r.ok {
			t.Fatalf("%s/%s N=%d did not satisfy its assertion; corpus misconfigured, refusing to record", r.op, r.mode, r.n)
		}
		if _, err := fmt.Fprintf(f, "%s,%s,%d,%.3f,%.3f,%.3f,%.3f,%.3f\n",
			r.op, r.mode, r.n, r.constructMS, r.heapMB, r.mean, r.p50, r.p99); err != nil {
			t.Fatalf("write row: %v", err)
		}
	}
	t.Logf("wrote %d rows to %s", len(rows), out)
}
