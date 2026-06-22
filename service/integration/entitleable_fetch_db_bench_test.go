//go:build entbench

// Entitlements fetch-path benchmark for DSPX-2541.
//
// This file compiles only under `-tags entbench`, so it never runs in normal
// `go test ./...` or CI. It requires Docker (testcontainers Postgres, started by
// TestMain in this package).
//
// It measures the asymmetry between how the decisioning/entitlement path fetches
// policy today versus the new narrow API:
//
//   - fullload (before): the PDP loads the entire policy on every construction and
//     refresh. EntitlementPolicyRetriever.ListAllAttributes /
//     ListAllSubjectMappings (service/internal/access/v2/policy_store.go) page the
//     whole DB, then NewPolicyDecisionPoint builds a value-FQN -> (attr,value,SMs)
//     map over all of it. Cost grows O(total policy N).
//   - byfqns (after): GetEntitleableAttributesByFqns fetches only the value FQNs a
//     decision references. Cost depends on K (requested FQNs) and the subject
//     mappings on those values, not on total policy size.
//
// Corpus shape (mirrors the NG SAP reference): one ANY_OF definition, 5,000
// attribute values, N subject mappings spread across the values (~N/5000 each).
//
// Run:
//
//	ENT_BENCH_OUT=docs/performance/DSPX-2541-entitleable-attributes/results.csv \
//	  go test -tags entbench -run TestEntitleableFetchBenchmark -timeout 60m -v ./service/integration/
package integration

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
	svcpolicy "github.com/opentdf/platform/service/policy"
)

const (
	// entBenchNumValues is the count of attribute values the subject mappings are
	// spread across, matching the NG SAP ~5,000 compartments.
	entBenchNumValues = 5000
	// entBenchPageSize is the list page size used when loading, at the fixtures' max.
	entBenchPageSize = 5000
	// entBenchK is the number of attribute value FQNs a single decision references.
	entBenchK = 10
)

// entBenchScalePoints is the set of total subject-mapping counts (N) measured.
// Override the ceiling with ENT_BENCH_MAX_N to bound runtime and container disk.
var entBenchScalePoints = []int{10_000, 50_000, 100_000, 500_000, 1_000_000}

// entBenchRow is one measured (mode, N) data point written to the CSV.
type entBenchRow struct {
	mode  string
	n     int
	k     int
	ms    float64
	rows  int
	pages int
}

// TestEntitleableFetchBenchmark seeds each corpus against a real Postgres and
// measures the two fetch paths, writing a CSV.
func TestEntitleableFetchBenchmark(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping entitlements fetch benchmark in short mode")
	}
	ctx := context.Background()

	cfg := *Config
	cfg.DB.Schema = "test_entitleable_bench"
	dbi := fixtures.NewDBInterface(ctx, cfg)

	// Start from a clean schema so prior runs do not skew counts.
	if err := dbi.DropSchema(ctx); err != nil {
		t.Fatalf("drop schema: %v", err)
	}
	if _, err := dbi.Client.RunMigrations(ctx, svcpolicy.Migrations); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	t.Cleanup(func() { _ = dbi.DropSchema(ctx) })

	schema := dbi.Schema
	pc := dbi.PolicyClient
	pool := dbi.Client.Pgx

	// One namespace (seeds standard actions), one ANY_OF definition, 5,000 values.
	ns, err := pc.CreateNamespace(ctx, &namespaces.CreateNamespaceRequest{Name: "entbench.gov"})
	if err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	def, err := pc.CreateAttribute(ctx, &attributes.CreateAttributeRequest{
		Name:        "ntk",
		NamespaceId: ns.GetId(),
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
	})
	if err != nil {
		t.Fatalf("create definition: %v", err)
	}
	for i := 0; i < entBenchNumValues; i++ {
		if _, err := pc.CreateAttributeValue(ctx, def.GetId(), &attributes.CreateAttributeValueRequest{
			Value: "compartment-" + strconv.Itoa(i),
		}); err != nil {
			t.Fatalf("create attribute value %d: %v", i, err)
		}
	}
	readActionID := entReadActionID(ctx, t, pool, schema)
	kFqns := entFirstValueFqns(ctx, t, &pc, def.GetId(), entBenchK)

	points := entScalePoints(t)
	rows := make([]entBenchRow, 0, len(points)*2)
	for _, n := range points {
		t.Logf("seeding N=%d subject mappings ...", n)
		entTruncateMappings(ctx, t, pool, schema)
		entSeedSubjectMappings(ctx, t, pool, schema, def.GetId(), readActionID, n)

		t.Logf("fullload N=%d ...", n)
		fullMS, pages, loaded := entFullLoad(ctx, t, &pc)
		if loaded != n {
			t.Fatalf("fullload N=%d loaded %d subject mappings; seed is wrong, refusing to record", n, loaded)
		}

		t.Logf("byfqns N=%d ...", n)
		byMS, smRows := entByFqns(ctx, t, &pc, kFqns)

		rows = append(rows,
			entBenchRow{mode: "fullload", n: n, k: entBenchK, ms: fullMS, rows: loaded, pages: pages},
			entBenchRow{mode: "byfqns", n: n, k: entBenchK, ms: byMS, rows: smRows, pages: 1},
		)
	}

	entWriteCSV(t, rows)
}

// entFullLoad mirrors the PDP cache build: page all attributes and all subject
// mappings to exhaustion, then index them by value FQN. Returns elapsed ms, total
// pages across both lists, and the number of subject mappings loaded.
func entFullLoad(ctx context.Context, t *testing.T, pc interface {
	ListAttributes(context.Context, *attributes.ListAttributesRequest) (*attributes.ListAttributesResponse, error)
	ListSubjectMappings(context.Context, *subjectmapping.ListSubjectMappingsRequest) (*subjectmapping.ListSubjectMappingsResponse, error)
},
) (float64, int, int) {
	start := time.Now()
	pages := 0

	// Page all attribute definitions (carry their values).
	byValueFQN := make(map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue)
	var offset int32
	for {
		resp, err := pc.ListAttributes(ctx, &attributes.ListAttributesRequest{
			Pagination: &policy.PageRequest{Limit: entBenchPageSize, Offset: offset},
		})
		if err != nil {
			t.Fatalf("list attributes at offset %d: %v", offset, err)
		}
		pages++
		for _, a := range resp.GetAttributes() {
			for _, v := range a.GetValues() {
				byValueFQN[v.GetFqn()] = &attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{Attribute: a, Value: v}
			}
		}
		offset = resp.GetPagination().GetNextOffset()
		if offset <= 0 {
			break
		}
	}

	// Page all subject mappings and attach them by value FQN.
	loaded := 0
	offset = 0
	for {
		resp, err := pc.ListSubjectMappings(ctx, &subjectmapping.ListSubjectMappingsRequest{
			Pagination: &policy.PageRequest{Limit: entBenchPageSize, Offset: offset},
		})
		if err != nil {
			t.Fatalf("list subject mappings at offset %d: %v", offset, err)
		}
		pages++
		for _, sm := range resp.GetSubjectMappings() {
			loaded++
			fqn := sm.GetAttributeValue().GetFqn()
			if entry, ok := byValueFQN[fqn]; ok && entry.GetValue() != nil {
				entry.Value.SubjectMappings = append(entry.Value.GetSubjectMappings(), sm)
			}
		}
		offset = resp.GetPagination().GetNextOffset()
		if offset <= 0 {
			break
		}
	}

	return entMsSince(start), pages, loaded
}

// entByFqns times GetEntitleableAttributesByFqns for the requested value FQNs and
// returns elapsed ms and the total subject mappings in the response.
func entByFqns(ctx context.Context, t *testing.T, pc interface {
	GetEntitleableAttributesByFqns(context.Context, *attributes.GetEntitleableAttributesByFqnsRequest) (map[string]*attributes.GetEntitleableAttributesByFqnsResponse_EntitleableAttribute, error)
}, fqns []string,
) (float64, int) {
	start := time.Now()
	resp, err := pc.GetEntitleableAttributesByFqns(ctx, &attributes.GetEntitleableAttributesByFqnsRequest{Fqns: fqns})
	if err != nil {
		t.Fatalf("get entitleable attributes by fqns: %v", err)
	}
	ms := entMsSince(start)
	smRows := 0
	for _, e := range resp {
		smRows += len(e.GetSubjectMappings())
	}
	return ms, smRows
}

// entSeedSubjectMappings inserts N subject condition sets, subject mappings, and
// action rows server-side via generate_series. This is the raw-insert floor: the
// production import path runs per-row through the API and is far slower.
func entSeedSubjectMappings(ctx context.Context, t *testing.T, pool db.PgxIface, schema, defID, readActionID string, n int) {
	scs := entQualified(schema, "subject_condition_set")
	sm := entQualified(schema, "subject_mappings")
	sma := entQualified(schema, "subject_mapping_actions")
	values := entQualified(schema, "attribute_values")

	// One subject condition set per synthetic user, in the subject-sets shape the
	// extract_selector_values trigger walks.
	if _, err := pool.Exec(ctx,
		"INSERT INTO "+scs+" (id, condition) "+
			"SELECT md5('scs' || g::text)::uuid, jsonb_build_array(jsonb_build_object("+
			"'conditionGroups', jsonb_build_array(jsonb_build_object("+
			"'booleanOperator', 1, "+
			"'conditions', jsonb_build_array(jsonb_build_object("+
			"'subjectExternalSelectorValue', '.properties.userId', "+
			"'operator', 1, "+
			"'subjectExternalValues', jsonb_build_array('user-' || g::text))))))) "+
			"FROM generate_series(1, $1) AS g", n); err != nil {
		t.Fatalf("seed subject_condition_set: %v", err)
	}

	// One subject mapping per user, its value cycled across the definition's values.
	if _, err := pool.Exec(ctx,
		"WITH vals AS ("+
			"SELECT id, (ROW_NUMBER() OVER (ORDER BY id) - 1) AS rn "+
			"FROM "+values+" WHERE attribute_definition_id = $1) "+
			"INSERT INTO "+sm+" (id, attribute_value_id, subject_condition_set_id) "+
			"SELECT md5('sm' || g::text)::uuid, v.id, md5('scs' || g::text)::uuid "+
			"FROM generate_series(1, $2) AS g "+
			"JOIN vals v ON v.rn = (g - 1) % $3", defID, n, entBenchNumValues); err != nil {
		t.Fatalf("seed subject_mappings: %v", err)
	}

	// One read action per subject mapping.
	if _, err := pool.Exec(ctx,
		"INSERT INTO "+sma+" (subject_mapping_id, action_id) "+
			"SELECT md5('sm' || g::text)::uuid, $1::uuid "+
			"FROM generate_series(1, $2) AS g", readActionID, n); err != nil {
		t.Fatalf("seed subject_mapping_actions: %v", err)
	}
}

func entTruncateMappings(ctx context.Context, t *testing.T, pool db.PgxIface, schema string) {
	q := "TRUNCATE " +
		entQualified(schema, "subject_mapping_actions") + ", " +
		entQualified(schema, "subject_mappings") + ", " +
		entQualified(schema, "subject_condition_set") + " CASCADE"
	if _, err := pool.Exec(ctx, q); err != nil {
		t.Fatalf("truncate mapping tables: %v", err)
	}
}

// entReadActionID returns the id of the standard "read" action.
func entReadActionID(ctx context.Context, t *testing.T, pool db.PgxIface, schema string) string {
	var id string
	q := "SELECT id::text FROM " + entQualified(schema, "actions") + " WHERE name = 'read' LIMIT 1"
	if err := pool.QueryRow(ctx, q).Scan(&id); err != nil {
		t.Fatalf("query read action id: %v", err)
	}
	return id
}

// entFirstValueFqns returns the FQNs of the first k values on the definition.
func entFirstValueFqns(ctx context.Context, t *testing.T, pc interface {
	GetAttribute(context.Context, any) (*policy.Attribute, error)
}, defID string, k int,
) []string {
	attr, err := pc.GetAttribute(ctx, defID)
	if err != nil {
		t.Fatalf("get attribute: %v", err)
	}
	vals := attr.GetValues()
	if len(vals) < k {
		t.Fatalf("definition has %d values; need at least %d", len(vals), k)
	}
	fqns := make([]string, 0, k)
	for i := 0; i < k; i++ {
		fqns = append(fqns, vals[i].GetFqn())
	}
	return fqns
}

func entScalePoints(t *testing.T) []int {
	maxN := entEnvInt(t, "ENT_BENCH_MAX_N")
	minN := entEnvInt(t, "ENT_BENCH_MIN_N")
	points := make([]int, 0, len(entBenchScalePoints))
	for _, n := range entBenchScalePoints {
		if maxN > 0 && n > maxN {
			continue
		}
		if minN > 0 && n < minN {
			continue
		}
		points = append(points, n)
	}
	if len(points) == 0 {
		t.Fatalf("no scale points to measure (ENT_BENCH_MIN_N=%d, ENT_BENCH_MAX_N=%d)", minN, maxN)
	}
	return points
}

func entEnvInt(t *testing.T, name string) int {
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

func entQualified(schema, table string) string {
	return pgx.Identifier{schema, table}.Sanitize()
}

func entMsSince(start time.Time) float64 {
	return float64(time.Since(start).Microseconds()) / 1000.0
}

func entWriteCSV(t *testing.T, rows []entBenchRow) {
	out := os.Getenv("ENT_BENCH_OUT")
	if out == "" {
		out = "results.csv"
	}
	f, err := os.Create(out)
	if err != nil {
		t.Fatalf("create %s: %v", out, err)
	}
	defer f.Close()

	if _, err := fmt.Fprintln(f, "mode,n,k,ms,rows,pages"); err != nil {
		t.Fatalf("write header: %v", err)
	}
	for _, r := range rows {
		if _, err := fmt.Fprintf(f, "%s,%d,%d,%.3f,%d,%d\n", r.mode, r.n, r.k, r.ms, r.rows, r.pages); err != nil {
			t.Fatalf("write row: %v", err)
		}
	}
	t.Logf("wrote %d rows to %s", len(rows), out)
}
