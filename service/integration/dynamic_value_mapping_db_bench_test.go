//go:build dvmdbbench

// DB load and seed benchmark for DSPX-3498.
//
// This file compiles only under `-tags dvmdbbench`, so it never runs in normal
// `go test ./...` or CI. It requires Docker (testcontainers Postgres, started by
// TestMain in this package).
//
// It measures the database costs the in-memory benchmark scopes out: seeding the
// corpus and the bulk load that feeds the PDP cache on every construction and
// refresh (see EntitlementPolicyRetriever.ListAllSubjectMappings in
// service/internal/access/v2/policy_store.go, which this load loop mirrors).
//
//   - Static: N subject mappings (one subject_condition_set + one
//     subject_mapping + one action row each), spread across 5,000 attribute
//     values on one definition.
//   - Dynamic: one definition-level dynamic value mapping, independent of N.
//
// Run:
//
//	DVM_DB_OUT=docs/performance/DSPX-3498-dynamic-value-mappings/db_results.csv \
//	  go test -tags dvmdbbench -run TestDVMDBBenchmark -timeout 60m -v ./service/integration/
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
	"github.com/opentdf/platform/protocol/go/policy/dynamicvaluemapping"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
	svcpolicy "github.com/opentdf/platform/service/policy"
)

const (
	// dbBenchNumValues is the fixed count of attribute values the static subject
	// mappings are spread across, matching the NG SAP ~5,000 compartments.
	dbBenchNumValues = 5000
	// dbBenchPageSize is the list page size used when loading subject mappings,
	// at the fixtures' configured maximum.
	dbBenchPageSize = 5000
)

// dbBenchScalePoints is the set of total subject-mapping counts (N) measured.
// Override the ceiling with DVM_DB_MAX_N to bound runtime and container disk.
var dbBenchScalePoints = []int{10_000, 50_000, 100_000, 500_000, 1_000_000}

type dbBenchRow struct {
	mode   string
	n      int
	seedMS float64
	loadMS float64
	pages  int
	rows   int
}

// TestDVMDBBenchmark seeds and loads each corpus against a real Postgres and writes a CSV.
func TestDVMDBBenchmark(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DB benchmark in short mode")
	}
	ctx := context.Background()

	cfg := *Config
	cfg.DB.Schema = "test_dvm_db_bench"
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

	// Shared dependencies for the static corpus: one namespace (seeds standard
	// actions), one ANY_OF definition, and 5,000 attribute values.
	ns, err := pc.CreateNamespace(ctx, &namespaces.CreateNamespaceRequest{Name: "sapdb.gov"})
	if err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	staticDef := createDBBenchDefinition(ctx, t, pc, ns.GetId(), "ntk_static")
	for i := 0; i < dbBenchNumValues; i++ {
		if _, err := pc.CreateAttributeValue(ctx, staticDef.GetId(), &attributes.CreateAttributeValueRequest{
			Value: "compartment-" + strconv.Itoa(i),
		}); err != nil {
			t.Fatalf("create attribute value %d: %v", i, err)
		}
	}
	readActionID := queryReadActionID(ctx, t, pool, schema)

	// Dynamic corpus: one definition plus one dynamic value mapping. It does not
	// depend on N, so it is measured once and reported as a flat line.
	dynDef := createDBBenchDefinition(ctx, t, pc, ns.GetId(), "ntk_dynamic")
	dynSeedStart := time.Now()
	if _, err := pc.CreateDynamicValueMapping(ctx, &dynamicvaluemapping.CreateDynamicValueMappingRequest{
		AttributeDefinitionId: dynDef.GetId(),
		ValueResolver: &policy.DynamicValueResolver{
			SubjectExternalSelectorValue: ".properties.compartments[]",
			Operator:                     policy.DynamicValueOperatorEnum_DYNAMIC_VALUE_OPERATOR_ENUM_RESOURCE_VALUE_IN,
		},
		Actions: []*policy.Action{{Id: readActionID}},
	}); err != nil {
		t.Fatalf("create dynamic value mapping: %v", err)
	}
	dynSeedMS := msSince(dynSeedStart)
	dynLoadMS, dynPages, dynRows := loadAllDynamicValueMappings(ctx, t, pc)

	points := dbScalePoints(t)
	rows := make([]dbBenchRow, 0, len(points)*2)
	for _, n := range points {
		t.Logf("seeding static N=%d ...", n)
		truncateMappingTables(ctx, t, pool, schema)
		seedMS := seedStaticSubjectMappings(ctx, t, pool, schema, staticDef.GetId(), readActionID, n)

		t.Logf("loading static N=%d ...", n)
		loadMS, pages, loaded := loadAllSubjectMappings(ctx, t, pc)
		if loaded != n {
			t.Fatalf("static N=%d loaded %d rows; seed is wrong, refusing to record", n, loaded)
		}
		rows = append(rows,
			dbBenchRow{mode: "static", n: n, seedMS: seedMS, loadMS: loadMS, pages: pages, rows: loaded},
			dbBenchRow{mode: "dynamic", n: n, seedMS: dynSeedMS, loadMS: dynLoadMS, pages: dynPages, rows: dynRows},
		)
	}

	writeDBBenchCSV(t, rows)
}

func dbScalePoints(t *testing.T) []int {
	maxN := dbEnvInt(t, "DVM_DB_MAX_N")
	minN := dbEnvInt(t, "DVM_DB_MIN_N")
	points := make([]int, 0, len(dbBenchScalePoints))
	for _, n := range dbBenchScalePoints {
		if maxN > 0 && n > maxN {
			continue
		}
		if minN > 0 && n < minN {
			continue
		}
		points = append(points, n)
	}
	if len(points) == 0 {
		t.Fatalf("no scale points to measure (DVM_DB_MIN_N=%d, DVM_DB_MAX_N=%d)", minN, maxN)
	}
	return points
}

// dbEnvInt reads an optional integer env var, returning 0 when unset.
func dbEnvInt(t *testing.T, name string) int {
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

func createDBBenchDefinition(ctx context.Context, t *testing.T, pc interface {
	CreateAttribute(context.Context, *attributes.CreateAttributeRequest) (*policy.Attribute, error)
}, nsID, name string,
) *policy.Attribute {
	attr, err := pc.CreateAttribute(ctx, &attributes.CreateAttributeRequest{
		Name:        name,
		NamespaceId: nsID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
	})
	if err != nil {
		t.Fatalf("create definition %q: %v", name, err)
	}
	return attr
}

// queryReadActionID returns the id of the standard "read" action.
func queryReadActionID(ctx context.Context, t *testing.T, pool db.PgxIface, schema string) string {
	var id string
	q := "SELECT id::text FROM " + qualified(schema, "actions") + " WHERE name = 'read' LIMIT 1"
	if err := pool.QueryRow(ctx, q).Scan(&id); err != nil {
		t.Fatalf("query read action id: %v", err)
	}
	return id
}

// seedStaticSubjectMappings inserts N subject condition sets, subject mappings, and
// action rows server-side via generate_series. This is the raw-insert floor: the
// production import path runs per-row through the API and is far slower. It returns
// the elapsed milliseconds.
func seedStaticSubjectMappings(ctx context.Context, t *testing.T, pool db.PgxIface, schema, defID, readActionID string, n int) float64 {
	scs := qualified(schema, "subject_condition_set")
	sm := qualified(schema, "subject_mappings")
	sma := qualified(schema, "subject_mapping_actions")
	values := qualified(schema, "attribute_values")

	start := time.Now()

	// One subject condition set per synthetic user. The condition must be the
	// subject-sets array shape the extract_selector_values trigger walks.
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
			"JOIN vals v ON v.rn = (g - 1) % $3", defID, n, dbBenchNumValues); err != nil {
		t.Fatalf("seed subject_mappings: %v", err)
	}

	// One read action per subject mapping.
	if _, err := pool.Exec(ctx,
		"INSERT INTO "+sma+" (subject_mapping_id, action_id) "+
			"SELECT md5('sm' || g::text)::uuid, $1::uuid "+
			"FROM generate_series(1, $2) AS g", readActionID, n); err != nil {
		t.Fatalf("seed subject_mapping_actions: %v", err)
	}

	return msSince(start)
}

func truncateMappingTables(ctx context.Context, t *testing.T, pool db.PgxIface, schema string) {
	q := "TRUNCATE " +
		qualified(schema, "subject_mapping_actions") + ", " +
		qualified(schema, "subject_mappings") + ", " +
		qualified(schema, "subject_condition_set") + " CASCADE"
	if _, err := pool.Exec(ctx, q); err != nil {
		t.Fatalf("truncate mapping tables: %v", err)
	}
}

// loadAllSubjectMappings pages through ListSubjectMappings to exhaustion, mirroring
// the PDP cache load in policy_store.go. It returns elapsed ms, page count, and rows.
func loadAllSubjectMappings(ctx context.Context, t *testing.T, pc interface {
	ListSubjectMappings(context.Context, *subjectmapping.ListSubjectMappingsRequest) (*subjectmapping.ListSubjectMappingsResponse, error)
},
) (float64, int, int) {
	start := time.Now()
	var offset int32
	pages, rows := 0, 0
	for {
		resp, err := pc.ListSubjectMappings(ctx, &subjectmapping.ListSubjectMappingsRequest{
			Pagination: &policy.PageRequest{Limit: dbBenchPageSize, Offset: offset},
		})
		if err != nil {
			t.Fatalf("list subject mappings at offset %d: %v", offset, err)
		}
		pages++
		rows += len(resp.GetSubjectMappings())
		offset = resp.GetPagination().GetNextOffset()
		if offset <= 0 {
			break
		}
	}
	return msSince(start), pages, rows
}

// loadAllDynamicValueMappings pages through ListDynamicValueMappings to exhaustion.
func loadAllDynamicValueMappings(ctx context.Context, t *testing.T, pc interface {
	ListDynamicValueMappings(context.Context, *dynamicvaluemapping.ListDynamicValueMappingsRequest) (*dynamicvaluemapping.ListDynamicValueMappingsResponse, error)
},
) (float64, int, int) {
	start := time.Now()
	var offset int32
	pages, rows := 0, 0
	for {
		resp, err := pc.ListDynamicValueMappings(ctx, &dynamicvaluemapping.ListDynamicValueMappingsRequest{
			Pagination: &policy.PageRequest{Limit: dbBenchPageSize, Offset: offset},
		})
		if err != nil {
			t.Fatalf("list dynamic value mappings at offset %d: %v", offset, err)
		}
		pages++
		rows += len(resp.GetDynamicValueMappings())
		offset = resp.GetPagination().GetNextOffset()
		if offset <= 0 {
			break
		}
	}
	return msSince(start), pages, rows
}

func qualified(schema, table string) string {
	return pgx.Identifier{schema, table}.Sanitize()
}

func msSince(start time.Time) float64 {
	return float64(time.Since(start).Microseconds()) / 1000.0
}

func writeDBBenchCSV(t *testing.T, rows []dbBenchRow) {
	out := os.Getenv("DVM_DB_OUT")
	if out == "" {
		out = "db_results.csv"
	}
	f, err := os.Create(out)
	if err != nil {
		t.Fatalf("create %s: %v", out, err)
	}
	defer f.Close()

	if _, err := fmt.Fprintln(f, "mode,n,seed_ms,load_ms,pages,rows_loaded"); err != nil {
		t.Fatalf("write header: %v", err)
	}
	for _, r := range rows {
		if _, err := fmt.Fprintf(f, "%s,%d,%.3f,%.3f,%d,%d\n",
			r.mode, r.n, r.seedMS, r.loadMS, r.pages, r.rows); err != nil {
			t.Fatalf("write row: %v", err)
		}
	}
	t.Logf("wrote %d rows to %s", len(rows), out)
}
