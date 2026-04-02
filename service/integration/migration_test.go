package integration

import (
	"context"
	"database/sql"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/policy"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
)

// migrationTestHarness provides direct access to the goose provider for
// fine-grained migration control (UpTo, DownTo, ApplyVersion) and raw
// SQL execution between migration steps.
type migrationTestHarness struct {
	t        *testing.T
	ctx      context.Context //nolint:containedctx // context is used across test helper methods
	dbClient *db.Client
	provider *goose.Provider
	schema   string
	sqlDB    *sql.DB
}

func newMigrationTestHarness(t *testing.T, schema string) *migrationTestHarness {
	t.Helper()
	ctx := context.Background()
	c := *Config
	c.DB.Schema = schema

	tracer := otel.Tracer("")
	dbClient, err := db.New(ctx, c.DB, c.Logger, &tracer)
	require.NoError(t, err, "failed to create db client")

	// Create schema
	q := "CREATE SCHEMA IF NOT EXISTS " + pgx.Identifier{schema}.Sanitize()
	_, err = dbClient.Pgx.Exec(ctx, q)
	require.NoError(t, err, "failed to create schema")

	// Build goose provider directly for fine-grained control
	pool, ok := dbClient.Pgx.(*pgxpool.Pool)
	require.True(t, ok, "expected pgxpool.Pool")
	sqlDB := stdlib.OpenDBFromPool(pool)

	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, policy.Migrations)
	require.NoError(t, err, "failed to create goose provider")

	h := &migrationTestHarness{
		t:        t,
		ctx:      ctx,
		dbClient: dbClient,
		provider: provider,
		schema:   schema,
		sqlDB:    sqlDB,
	}

	t.Cleanup(func() {
		sqlDB.Close()
		dropSchema(ctx, t, dbClient, schema)
		dbClient.Pgx.Close()
	})

	return h
}

func (h *migrationTestHarness) upTo(version int64) {
	h.t.Helper()
	results, err := h.provider.UpTo(h.ctx, version)
	require.NoError(h.t, err, "migration UpTo(%d) failed", version)
	for _, r := range results {
		require.NoError(h.t, r.Error, "migration %d up error", r.Source.Version)
	}
}

func (h *migrationTestHarness) downTo(version int64) {
	h.t.Helper()
	results, err := h.provider.DownTo(h.ctx, version)
	require.NoError(h.t, err, "migration DownTo(%d) failed", version)
	for _, r := range results {
		require.NoError(h.t, r.Error, "migration %d down error", r.Source.Version)
	}
}

func (h *migrationTestHarness) exec(query string, args ...any) {
	h.t.Helper()
	_, err := h.dbClient.Pgx.Exec(h.ctx, query, args...)
	require.NoError(h.t, err, "exec failed: %s", query)
}

func (h *migrationTestHarness) queryRow(query string, args ...any) pgx.Row { //nolint:unparam // args kept variadic for future test cases
	h.t.Helper()
	return h.dbClient.Pgx.QueryRow(h.ctx, query, args...)
}

func dropSchema(ctx context.Context, t *testing.T, client *db.Client, schema string) {
	t.Helper()
	q := "DROP SCHEMA IF EXISTS " + pgx.Identifier{schema}.Sanitize() + " CASCADE"
	if _, err := client.Pgx.Exec(ctx, q); err != nil {
		t.Logf("warning: failed to drop schema %s: %v", schema, err)
	}
}

// TestMigrationUpDownUp validates that all migrations can be applied forward,
// rolled back completely, and re-applied. This catches broken Down migrations
// before they're needed in a production rollback.
func TestMigrationUpDownUp(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping migration roundtrip test")
	}

	h := newMigrationTestHarness(t, "test_opentdf_migration_roundtrip")

	// Phase 1: Apply all migrations up
	upResults, err := h.provider.Up(h.ctx)
	require.NoError(t, err, "migration up failed")
	require.NotEmpty(t, upResults, "expected at least one migration applied")
	for _, r := range upResults {
		require.NoError(t, r.Error, "migration %d up error", r.Source.Version)
	}
	t.Logf("phase 1 (up): applied %d migrations", len(upResults))

	// Phase 2: Roll back all migrations
	downResults, err := h.provider.DownTo(h.ctx, 0)
	require.NoError(t, err, "migration down failed")
	require.NotEmpty(t, downResults, "expected at least one migration rolled back")
	for _, r := range downResults {
		require.NoError(t, r.Error, "migration %d down error", r.Source.Version)
	}
	require.Len(t, downResults, len(upResults), "rollback count should match applied count")
	t.Logf("phase 2 (down): rolled back %d migrations", len(downResults))

	// Phase 3: Re-apply all migrations
	reupResults, err := h.provider.Up(h.ctx)
	require.NoError(t, err, "migration re-up failed after rollback")
	require.NotEmpty(t, reupResults, "expected at least one migration re-applied")
	for _, r := range reupResults {
		require.NoError(t, r.Error, "migration %d re-up error", r.Source.Version)
	}
	require.Len(t, reupResults, len(upResults), "re-applied count should match initial count")
	t.Logf("phase 3 (re-up): applied %d migrations", len(reupResults))
}

// TestMigrationData_SelectorFieldRename tests the JSONB field rename migration
// (20240405000000_update_selector_field_name) to verify data integrity through
// the up and down transitions.
//
// The migration renames subject_external_field -> subject_external_selector_value
// inside the condition JSONB column of subject_condition_set.
func TestMigrationData_SelectorFieldRename(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping data migration test")
	}

	h := newMigrationTestHarness(t, "test_opentdf_selector_rename")

	// Migrate to the version just before the rename migration
	const preMigration int64 = 20240402000000
	const renameMigration int64 = 20240405000000
	h.upTo(preMigration)

	// Insert test data using the old field name (subject_external_field)
	h.exec(`
		INSERT INTO subject_condition_set (id, condition) VALUES (
			'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
			'[{
				"condition_groups": [{
					"boolean_operator": "AND",
					"conditions": [{
						"operator": "IN",
						"subject_external_field": "team_name",
						"subject_external_values": ["engineering", "platform"]
					}]
				}]
			}]'::jsonb
		)
	`)

	// Apply the rename migration
	h.upTo(renameMigration)

	// Verify the field was renamed to subject_external_selector_value
	var fieldValue string
	row := h.queryRow(`
		SELECT condition->0->'condition_groups'->0->'conditions'->0->>'subject_external_selector_value'
		FROM subject_condition_set
		WHERE id = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
	`)
	require.NoError(t, row.Scan(&fieldValue))
	require.Equal(t, "team_name", fieldValue, "field should be renamed to subject_external_selector_value after up")

	// Verify old field name is gone
	var oldFieldValue *string
	row = h.queryRow(`
		SELECT condition->0->'condition_groups'->0->'conditions'->0->>'subject_external_field'
		FROM subject_condition_set
		WHERE id = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
	`)
	require.NoError(t, row.Scan(&oldFieldValue))
	require.Nil(t, oldFieldValue, "old field name should not exist after up migration")

	// Roll back the rename migration
	h.downTo(preMigration)

	// Verify the field was renamed back to subject_external_field
	row = h.queryRow(`
		SELECT condition->0->'condition_groups'->0->'conditions'->0->>'subject_external_field'
		FROM subject_condition_set
		WHERE id = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
	`)
	require.NoError(t, row.Scan(&fieldValue))
	require.Equal(t, "team_name", fieldValue, "field should be restored to subject_external_field after down")

	// Verify the new field name is gone after rollback
	row = h.queryRow(`
		SELECT condition->0->'condition_groups'->0->'conditions'->0->>'subject_external_selector_value'
		FROM subject_condition_set
		WHERE id = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
	`)
	require.NoError(t, row.Scan(&oldFieldValue))
	require.Nil(t, oldFieldValue, "new field name should not exist after down migration")
}
