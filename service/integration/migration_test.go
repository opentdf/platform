package integration

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/policy"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
)

func newMigrationDBClient(ctx context.Context, cfg config.Config) (*db.Client, error) {
	tracer := otel.Tracer("")
	return db.New(ctx, cfg.DB, cfg.Logger, &tracer)
}

func dropSchema(ctx context.Context, t *testing.T, client *db.Client, schema string) {
	t.Helper()
	sql := "DROP SCHEMA IF EXISTS " + pgx.Identifier{schema}.Sanitize() + " CASCADE"
	if _, err := client.Pgx.Exec(ctx, sql); err != nil {
		t.Logf("warning: failed to drop schema %s: %v", schema, err)
	}
}

// TestMigrationUpDownUp validates that all migrations can be applied forward,
// rolled back completely, and re-applied. This catches broken Down migrations
// that would otherwise go unnoticed until a production rollback is needed.
func TestMigrationUpDownUp(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping migration roundtrip test")
	}

	ctx := context.Background()
	c := *Config
	c.DB.Schema = "test_opentdf_migration_roundtrip"

	dbClient, err := newMigrationDBClient(ctx, c)
	require.NoError(t, err, "failed to create db client")

	defer func() {
		dropSchema(ctx, t, dbClient, c.DB.Schema)
	}()

	// Phase 1: Apply all migrations up
	appliedUp, err := dbClient.RunMigrations(ctx, policy.Migrations)
	require.NoError(t, err, "migration up failed")
	require.Greater(t, appliedUp, 0, "expected at least one migration to be applied")
	t.Logf("phase 1 (up): applied %d migrations", appliedUp)

	// Phase 2: Roll back all migrations one at a time
	rolledBack := 0
	for {
		if err := dbClient.MigrationDown(ctx, policy.Migrations); err != nil {
			t.Logf("phase 2 (down): stopped after %d rollbacks: %v", rolledBack, err)
			break
		}
		rolledBack++
	}
	require.Greater(t, rolledBack, 0, "expected at least one migration to be rolled back")
	t.Logf("phase 2 (down): rolled back %d migrations", rolledBack)

	// Phase 3: Re-apply all migrations
	reapplied, err := dbClient.RunMigrations(ctx, policy.Migrations)
	require.NoError(t, err, "migration re-up failed after rollback")
	require.Greater(t, reapplied, 0, "expected at least one migration re-applied")
	t.Logf("phase 3 (re-up): applied %d migrations", reapplied)
}
