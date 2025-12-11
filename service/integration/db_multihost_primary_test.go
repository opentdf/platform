// Multi-Host Primary Failover Integration Tests
//
// This test suite validates multi-host primary failover using testcontainers.
// Tests verify:
// - Automatic primary failover when first primary fails
// - target_session_attrs=primary routing
// - Failover with read replicas configured
//
// Requirements:
// - Docker or Podman running locally
//
// Usage:
//   go test -run TestMultiHostPrimary -v

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMultiHostPrimaryFailover tests automatic failover to backup primary
func TestMultiHostPrimaryFailover(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping testcontainer test in short mode")
	}

	ctx := context.Background()

	// Start TWO primaries for failover testing (cleanup handled by setupPrimaryContainer)
	primary1Container, primary1Port := setupPrimaryContainer(ctx, t)
	_, primary2Port := setupPrimaryContainer(ctx, t)

	t.Run("both_primaries_healthy", func(t *testing.T) {
		// Configure with multi-host primary
		config := db.Config{
			Database:       postgresDB,
			User:           postgresUser,
			Password:       postgresPassword,
			SSLMode:        "disable",
			Schema:         "public",
			ConnectTimeout: 5,
			Pool: db.PoolConfig{
				MaxConns:          10,
				HealthCheckPeriod: 5,
			},
			PrimaryHosts: []db.ReplicaConfig{
				{Host: "localhost", Port: primary1Port},
				{Host: "localhost", Port: primary2Port},
			},
			RunMigrations:    false,
			VerifyConnection: true,
		}

		logCfg := logger.Config{
			Output: "stdout",
			Type:   "json",
			Level:  "error",
		}

		client, err := db.New(ctx, config, logCfg, nil)
		require.NoError(t, err, "Should connect to first primary")
		defer client.Close()

		// Create test table
		_, err = client.Pgx.Exec(ctx, `
			CREATE TABLE IF NOT EXISTS failover_test (
				id SERIAL PRIMARY KEY,
				data TEXT
			)
		`)
		require.NoError(t, err, "Should create table")

		// Write data
		_, err = client.Exec(ctx, "INSERT INTO failover_test (data) VALUES ($1)", "test1")
		require.NoError(t, err, "Write should succeed")

		// Read data
		rows, err := client.Query(ctx, "SELECT COUNT(*) FROM failover_test")
		require.NoError(t, err, "Read should succeed")
		rows.Close()
	})

	t.Run("primary_failover_when_first_fails", func(t *testing.T) {
		// Stop primary1 BEFORE creating client
		t.Logf("Stopping primary1 to test failover...")
		err := primary1Container.Stop(ctx, nil)
		require.NoError(t, err)

		// Small delay to ensure primary1 is fully stopped
		time.Sleep(1 * time.Second)

		// Configure with multi-host primary (primary1 is down)
		config := db.Config{
			Database:       postgresDB,
			User:           postgresUser,
			Password:       postgresPassword,
			SSLMode:        "disable",
			Schema:         "public",
			ConnectTimeout: 5,
			Pool: db.PoolConfig{
				MaxConns:          10,
				HealthCheckPeriod: 5,
			},
			PrimaryHosts: []db.ReplicaConfig{
				{Host: "localhost", Port: primary1Port}, // This one is DOWN
				{Host: "localhost", Port: primary2Port}, // Should failover to this
			},
			RunMigrations:    false,
			VerifyConnection: true,
		}

		logCfg := logger.Config{
			Output: "stdout",
			Type:   "json",
			Level:  "info",
		}

		// pgx should automatically try primary2 after primary1 fails
		client, err := db.New(ctx, config, logCfg, nil)
		require.NoError(t, err, "Should failover to primary2")
		defer client.Close()

		// Verify we can write (confirms we're on a primary)
		_, err = client.Pgx.Exec(ctx, `
			CREATE TABLE IF NOT EXISTS failover_test2 (
				id SERIAL PRIMARY KEY,
				data TEXT
			)
		`)
		require.NoError(t, err, "Should write to failover primary")

		_, err = client.Exec(ctx, "INSERT INTO failover_test2 (data) VALUES ($1)", "failover-test")
		require.NoError(t, err, "Write should succeed on failover primary")
	})
}

// TestMultiHostWithReplicas tests multi-host primary + read replicas together
func TestMultiHostPrimaryWithReadReplicas(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping testcontainer test in short mode")
	}

	ctx := context.Background()

	// Start primary (for replicas to replicate from) - cleanup handled by setupPrimaryContainer
	primaryContainer, primaryPort := setupPrimaryContainer(ctx, t)

	primaryHost, err := primaryContainer.Host(ctx)
	require.NoError(t, err)

	// Start backup primary (for multi-host failover) - cleanup handled by setupPrimaryContainer
	_, backupPrimaryPort := setupPrimaryContainer(ctx, t)

	// Start read replica - cleanup handled by setupReplicaContainer
	_, replicaPort := setupReplicaContainer(ctx, t, primaryHost, 5432, 1)

	// Configure with BOTH multi-host primary AND read replicas
	config := db.Config{
		Database:       postgresDB,
		User:           postgresUser,
		Password:       postgresPassword,
		SSLMode:        "disable",
		Schema:         "public",
		ConnectTimeout: 5,
		Pool: db.PoolConfig{
			MaxConns:          10,
			HealthCheckPeriod: 5,
		},
		PrimaryHosts: []db.ReplicaConfig{
			{Host: "localhost", Port: primaryPort},
			{Host: "localhost", Port: backupPrimaryPort}, // Backup primary for failover
		},
		ReadReplicas: []db.ReplicaConfig{
			{Host: "localhost", Port: replicaPort}, // Read replica
		},
		RunMigrations:    false,
		VerifyConnection: true,
	}

	logCfg := logger.Config{
		Output: "stdout",
		Type:   "json",
		Level:  "error",
	}

	client, err := db.New(ctx, config, logCfg, nil)
	require.NoError(t, err, "Should connect with multi-host + replicas")
	defer client.Close()

	// Verify configuration
	assert.Len(t, client.ReadReplicas, 1, "Should have 1 read replica")

	// Create table and data
	_, err = client.Pgx.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS combined_test (
			id SERIAL PRIMARY KEY,
			data TEXT
		)
	`)
	require.NoError(t, err)

	// Write to primary
	_, err = client.Exec(ctx, "INSERT INTO combined_test (data) VALUES ($1), ($2)", "test1", "test2")
	require.NoError(t, err, "Writes should go to primary")

	// Allow replication
	time.Sleep(500 * time.Millisecond)

	t.Run("reads_use_replica_with_multihost_primary", func(t *testing.T) {
		// Reads should use replica (not affected by multi-host primary config)
		for i := 0; i < 5; i++ {
			rows, err := client.Query(ctx, "SELECT COUNT(*) FROM combined_test")
			require.NoError(t, err, "Reads should succeed via replica")

			var count int
			if rows.Next() {
				rows.Scan(&count)
				assert.Equal(t, 2, count, "Should see replicated data")
			}
			rows.Close()
		}
	})

	t.Run("writes_use_primary_with_replicas", func(t *testing.T) {
		// Writes should still go to primary
		_, err := client.Exec(ctx, "INSERT INTO combined_test (data) VALUES ($1)", "test3")
		require.NoError(t, err, "Writes should go to primary")

		// Allow replication
		time.Sleep(300 * time.Millisecond)

		// Verify via read
		rows, err := client.Query(ctx, "SELECT COUNT(*) FROM combined_test")
		require.NoError(t, err)

		var count int
		if rows.Next() {
			rows.Scan(&count)
			assert.Equal(t, 3, count, "Should see all data")
		}
		rows.Close()
	})
}

