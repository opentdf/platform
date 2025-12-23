package db

import (
	"context"
	"testing"

	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/policy/db/migrations_sqlite"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
)

func TestSQLiteMigrations(t *testing.T) {
	ctx := context.Background()

	// Create a SQLite in-memory database configuration
	cfg := db.Config{
		Driver:        db.DriverSQLite,
		SQLitePath:    ":memory:",
		RunMigrations: true,
	}

	logCfg := logger.Config{
		Level:  "info",
		Output: "stdout",
		Type:   "text",
	}

	tracer := otel.Tracer("sqlite-migration-test")

	// Create the database client
	client, err := db.New(ctx, cfg, logCfg, &tracer)
	require.NoError(t, err, "Failed to create SQLite database client")
	require.NotNil(t, client)
	defer client.Close()

	// Get SQLite migrations directly from the embedded filesystem
	migrations := &migrations_sqlite.FS
	require.NotNil(t, migrations, "SQLite migrations should not be nil")

	// Run migrations
	applied, err := client.RunMigrations(ctx, migrations)
	require.NoError(t, err, "Failed to run SQLite migrations")

	t.Logf("Successfully applied %d SQLite migrations", applied)

	// Verify some tables were created
	// Query the sqlite_master to check if tables exist
	sqlDB := client.SQLDB
	require.NotNil(t, sqlDB)

	var tableName string
	err = sqlDB.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='attribute_namespaces'").Scan(&tableName)
	require.NoError(t, err, "attribute_namespaces table should exist")
	require.Equal(t, "attribute_namespaces", tableName)
}
