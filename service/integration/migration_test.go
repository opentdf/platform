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

func (h *migrationTestHarness) queryRow(query string, args ...any) pgx.Row {
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

// TestMigrationData_ActionsNamespaceDownRemapsAndDedupes verifies that
// 20260312000000_add_namespace_to_actions down migration remaps namespaced
// action references to canonical global actions and deduplicates rows across
// referencing tables.
func TestMigrationData_ActionsNamespaceDownRemapsAndDedupes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping data migration test")
	}

	h := newMigrationTestHarness(t, "test_opentdf_actions_namespace_down")

	const (
		preNamespaceRollback  int64 = 20260318000000
		postNamespaceRollback int64 = 20260306000000

		namespaceID       = "11111111-1111-1111-1111-111111111111"
		attributeDefID    = "22222222-2222-2222-2222-222222222222"
		attributeValueID  = "33333333-3333-3333-3333-333333333333"
		subjectSetID      = "44444444-4444-4444-4444-444444444444"
		subjectMappingID  = "55555555-5555-5555-5555-555555555555"
		registeredResID   = "66666666-6666-6666-6666-666666666666"
		registeredValueID = "77777777-7777-7777-7777-777777777777"

		obligationDefID = "88888888-8888-8888-8888-888888888888"
		obligationValID = "99999999-9999-9999-9999-999999999999"

		namespacedCreateID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
		globalCustomID     = "abababab-abab-abab-abab-abababababab"
		namespaceCustomID  = "acacacac-acac-acac-acac-acacacacacac"

		smaRowGlobalID    = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
		smaRowNamespaceID = "cccccccc-cccc-cccc-cccc-cccccccccccc"
		otRowGlobalID     = "dddddddd-dddd-dddd-dddd-dddddddddddd"
		otRowNamespaceID  = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"

		smaCustomGlobalID    = "f1f1f1f1-f1f1-f1f1-f1f1-f1f1f1f1f1f1"
		smaCustomNamespaceID = "f2f2f2f2-f2f2-f2f2-f2f2-f2f2f2f2f2f2"
		rrCustomGlobalID     = "f3f3f3f3-f3f3-f3f3-f3f3-f3f3f3f3f3f3"
		rrCustomNamespaceID  = "f4f4f4f4-f4f4-f4f4-f4f4-f4f4f4f4f4f4"
		otCustomGlobalID     = "f5f5f5f5-f5f5-f5f5-f5f5-f5f5f5f5f5f5"
		otCustomNamespaceID  = "f6f6f6f6-f6f6-f6f6-f6f6-f6f6f6f6f6f6"
	)

	h.upTo(preNamespaceRollback)

	// Global canonical action id for create should win remap selection.
	var globalCreateID string
	row := h.queryRow(`
		SELECT id FROM actions
		WHERE name = 'create' AND namespace_id IS NULL
	`)
	require.NoError(t, row.Scan(&globalCreateID))

	// Seed minimal dependency graph.
	h.exec(`INSERT INTO attribute_namespaces (id, name, active) VALUES ($1, 'migration-test.example', true)`, namespaceID)
	h.exec(`
		INSERT INTO attribute_definitions (id, namespace_id, name, rule, active)
		VALUES ($1, $2, 'department', 'ALL_OF', true)
	`, attributeDefID, namespaceID)
	h.exec(`
		INSERT INTO attribute_values (id, attribute_definition_id, value, active)
		VALUES ($1, $2, 'engineering', true)
	`, attributeValueID, attributeDefID)
	h.exec(`
		INSERT INTO subject_condition_set (id, condition)
		VALUES ($1, '[{"condition_groups":[{"boolean_operator":"AND","conditions":[]}]}]'::jsonb)
	`, subjectSetID)
	h.exec(`
		INSERT INTO subject_mappings (id, attribute_value_id, subject_condition_set_id)
		VALUES ($1, $2, $3)
	`, subjectMappingID, attributeValueID, subjectSetID)
	h.exec(`
		INSERT INTO registered_resources (id, name)
		VALUES ($1, 'migration-test-resource')
	`, registeredResID)
	h.exec(`
		INSERT INTO registered_resource_values (id, registered_resource_id, value)
		VALUES ($1, $2, 'migration-test-resource-value')
	`, registeredValueID, registeredResID)
	h.exec(`
		INSERT INTO obligation_definitions (id, namespace_id, name)
		VALUES ($1, $2, 'migration-test-obligation')
	`, obligationDefID, namespaceID)
	h.exec(`
		INSERT INTO obligation_values_standard (id, obligation_definition_id, value)
		VALUES ($1, $2, 'migration-test-obligation-value')
	`, obligationValID, obligationDefID)

	// Namespaced duplicate of standard create action.
	h.exec(`
		INSERT INTO actions (id, name, is_standard, namespace_id)
		VALUES ($1, 'create', true, $2)
	`, namespacedCreateID, namespaceID)
	h.exec(`
		INSERT INTO actions (id, name, is_standard, namespace_id)
		VALUES ($1, 'migration-custom-merge', false, NULL), ($2, 'migration-custom-merge', false, $3)
	`, globalCustomID, namespaceCustomID, namespaceID)

	// Two references in each table that collapse to one after remap.
	h.exec(`
		INSERT INTO subject_mapping_actions (subject_mapping_id, action_id)
		VALUES ($1, $2), ($1, $3)
	`, subjectMappingID, globalCreateID, namespacedCreateID)
	h.exec(`
		INSERT INTO subject_mapping_actions (subject_mapping_id, action_id, created_at)
		VALUES ($1, $2, NOW()), ($1, $3, NOW() + interval '1 second')
	`, subjectMappingID, globalCustomID, namespaceCustomID)
	h.exec(`
		INSERT INTO registered_resource_action_attribute_values (id, registered_resource_value_id, action_id, attribute_value_id)
		VALUES ($1, $2, $3, $4), ($5, $2, $6, $4)
	`, smaRowGlobalID, registeredValueID, globalCreateID, attributeValueID, smaRowNamespaceID, namespacedCreateID)
	h.exec(`
		INSERT INTO registered_resource_action_attribute_values (id, registered_resource_value_id, action_id, attribute_value_id)
		VALUES ($1, $2, $3, $4), ($5, $2, $6, $4)
	`, rrCustomGlobalID, registeredValueID, globalCustomID, attributeValueID, rrCustomNamespaceID, namespaceCustomID)
	h.exec(`
		INSERT INTO obligation_triggers (id, obligation_value_id, action_id, attribute_value_id)
		VALUES ($1, $2, $3, $4), ($5, $2, $6, $4)
	`, otRowGlobalID, obligationValID, globalCreateID, attributeValueID, otRowNamespaceID, namespacedCreateID)
	h.exec(`
		INSERT INTO obligation_triggers (id, obligation_value_id, action_id, attribute_value_id)
		VALUES ($1, $2, $3, $4), ($5, $2, $6, $4)
	`, otCustomGlobalID, obligationValID, globalCustomID, attributeValueID, otCustomNamespaceID, namespaceCustomID)

	// Sanity precondition: namespaced action exists and ref tables have 2 rows for test key.
	var count int
	row = h.queryRow(`SELECT COUNT(*) FROM actions WHERE name = 'create'`)
	require.NoError(t, row.Scan(&count))
	require.GreaterOrEqual(t, count, 2)

	row = h.queryRow(`SELECT COUNT(*) FROM subject_mapping_actions WHERE subject_mapping_id = $1`, subjectMappingID)
	require.NoError(t, row.Scan(&count))
	require.Equal(t, 4, count)

	row = h.queryRow(`SELECT COUNT(*) FROM registered_resource_action_attribute_values WHERE registered_resource_value_id = $1 AND attribute_value_id = $2`, registeredValueID, attributeValueID)
	require.NoError(t, row.Scan(&count))
	require.Equal(t, 4, count)

	row = h.queryRow(`SELECT COUNT(*) FROM obligation_triggers WHERE obligation_value_id = $1 AND attribute_value_id = $2`, obligationValID, attributeValueID)
	require.NoError(t, row.Scan(&count))
	require.Equal(t, 4, count)

	h.downTo(postNamespaceRollback)

	// actions.namespace_id should be gone.
	row = h.queryRow(`
		SELECT COUNT(*)
		FROM information_schema.columns
		WHERE table_schema = current_schema()
		  AND table_name = 'actions'
		  AND column_name = 'namespace_id'
	`)
	require.NoError(t, row.Scan(&count))
	require.Equal(t, 0, count)

	// No duplicate action names after restoring global unique(name).
	row = h.queryRow(`
		SELECT COUNT(*)
		FROM (
			SELECT name FROM actions GROUP BY name HAVING COUNT(*) > 1
		) d
	`)
	require.NoError(t, row.Scan(&count))
	require.Equal(t, 0, count)

	// All references should now point at canonical global create action.
	var resolvedActionID string
	row = h.queryRow(`
		SELECT sma.action_id
		FROM subject_mapping_actions sma
		JOIN actions a ON a.id = sma.action_id
		WHERE sma.subject_mapping_id = $1 AND a.name = 'create'
	`, subjectMappingID)
	require.NoError(t, row.Scan(&resolvedActionID))
	require.Equal(t, globalCreateID, resolvedActionID)

	row = h.queryRow(`SELECT COUNT(*) FROM subject_mapping_actions WHERE subject_mapping_id = $1`, subjectMappingID)
	require.NoError(t, row.Scan(&count))
	require.Equal(t, 2, count)

	row = h.queryRow(`SELECT COUNT(*) FROM subject_mapping_actions WHERE subject_mapping_id = $1 AND action_id = $2`, subjectMappingID, globalCreateID)
	require.NoError(t, row.Scan(&count))
	require.Equal(t, 1, count)

	row = h.queryRow(`SELECT COUNT(*) FROM subject_mapping_actions WHERE subject_mapping_id = $1 AND action_id = $2`, subjectMappingID, globalCustomID)
	require.NoError(t, row.Scan(&count))
	require.Equal(t, 1, count)

	row = h.queryRow(`
		SELECT rr.action_id
		FROM registered_resource_action_attribute_values rr
		JOIN actions a ON a.id = rr.action_id
		WHERE rr.registered_resource_value_id = $1 AND rr.attribute_value_id = $2 AND a.name = 'create'
	`, registeredValueID, attributeValueID)
	require.NoError(t, row.Scan(&resolvedActionID))
	require.Equal(t, globalCreateID, resolvedActionID)

	row = h.queryRow(`SELECT COUNT(*) FROM registered_resource_action_attribute_values WHERE registered_resource_value_id = $1 AND attribute_value_id = $2`, registeredValueID, attributeValueID)
	require.NoError(t, row.Scan(&count))
	require.Equal(t, 2, count)

	row = h.queryRow(`SELECT COUNT(*) FROM registered_resource_action_attribute_values WHERE registered_resource_value_id = $1 AND attribute_value_id = $2 AND action_id = $3`, registeredValueID, attributeValueID, globalCreateID)
	require.NoError(t, row.Scan(&count))
	require.Equal(t, 1, count)

	row = h.queryRow(`SELECT COUNT(*) FROM registered_resource_action_attribute_values WHERE registered_resource_value_id = $1 AND attribute_value_id = $2 AND action_id = $3`, registeredValueID, attributeValueID, globalCustomID)
	require.NoError(t, row.Scan(&count))
	require.Equal(t, 1, count)

	row = h.queryRow(`
		SELECT ot.action_id
		FROM obligation_triggers ot
		JOIN actions a ON a.id = ot.action_id
		WHERE ot.obligation_value_id = $1 AND ot.attribute_value_id = $2 AND a.name = 'create'
	`, obligationValID, attributeValueID)
	require.NoError(t, row.Scan(&resolvedActionID))
	require.Equal(t, globalCreateID, resolvedActionID)

	row = h.queryRow(`SELECT COUNT(*) FROM obligation_triggers WHERE obligation_value_id = $1 AND attribute_value_id = $2`, obligationValID, attributeValueID)
	require.NoError(t, row.Scan(&count))
	require.Equal(t, 2, count)

	row = h.queryRow(`SELECT COUNT(*) FROM obligation_triggers WHERE obligation_value_id = $1 AND attribute_value_id = $2 AND action_id = $3`, obligationValID, attributeValueID, globalCreateID)
	require.NoError(t, row.Scan(&count))
	require.Equal(t, 1, count)

	row = h.queryRow(`SELECT COUNT(*) FROM obligation_triggers WHERE obligation_value_id = $1 AND attribute_value_id = $2 AND action_id = $3`, obligationValID, attributeValueID, globalCustomID)
	require.NoError(t, row.Scan(&count))
	require.Equal(t, 1, count)

	row = h.queryRow(`SELECT COUNT(*) FROM actions WHERE name = 'migration-custom-merge'`)
	require.NoError(t, row.Scan(&count))
	require.Equal(t, 1, count)

	// No orphan action refs.
	row = h.queryRow(`SELECT COUNT(*) FROM subject_mapping_actions sma LEFT JOIN actions a ON a.id = sma.action_id WHERE a.id IS NULL`)
	require.NoError(t, row.Scan(&count))
	require.Equal(t, 0, count)

	row = h.queryRow(`SELECT COUNT(*) FROM registered_resource_action_attribute_values rr LEFT JOIN actions a ON a.id = rr.action_id WHERE a.id IS NULL`)
	require.NoError(t, row.Scan(&count))
	require.Equal(t, 0, count)

	row = h.queryRow(`SELECT COUNT(*) FROM obligation_triggers ot LEFT JOIN actions a ON a.id = ot.action_id WHERE a.id IS NULL`)
	require.NoError(t, row.Scan(&count))
	require.Equal(t, 0, count)
}
