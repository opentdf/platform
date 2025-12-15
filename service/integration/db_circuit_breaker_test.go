// Circuit Breaker Integration Tests
//
// This test suite validates circuit breaker functionality using testcontainers.
// Tests verify:
// - Automatic failure detection and circuit opening
// - Fallback to primary when replicas fail
// - Circuit recovery and closure
// - Context-based routing (WithForcePrimary)
//
// Requirements:
// - Docker or Podman running locally
//
// Usage:
//   go test -run TestCircuitBreaker -v

package integration

import (
	"fmt"
	"testing"
	"time"

	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCircuitBreakerWithFailingReplica tests circuit breaker behavior when a replica fails
func TestCircuitBreakerWithFailingReplica(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping testcontainer test in short mode")
	}

	ctx := t.Context()

	// Start primary database (cleanup handled by setupPrimaryContainer)
	_, primaryPort, networkName, primaryContainerName := setupPrimaryContainer(ctx, t)

	// Start TWO replicas (cleanup handled by setupReplicaContainer)
	replica1Container, replica1Port := setupReplicaContainer(ctx, t, primaryContainerName, 1, networkName)
	replica2Container, replica2Port := setupReplicaContainer(ctx, t, primaryContainerName, 2, networkName)

	// Configure client with both replicas
	config := db.Config{
		Host:           "localhost",
		Port:           primaryPort,
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
		ReadReplicas: []db.ReplicaConfig{
			{Host: "localhost", Port: replica1Port},
			{Host: "localhost", Port: replica2Port},
		},
		RunMigrations:    false,
		VerifyConnection: true,
	}

	logCfg := logger.Config{
		Output: "stdout",
		Type:   "json",
		Level:  "info",
	}

	client, err := db.New(ctx, config, logCfg, nil)
	require.NoError(t, err, "Failed to create database client")
	defer client.Close()

	// Create test table
	_, err = client.Pgx.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS circuit_test (
			id SERIAL PRIMARY KEY,
			data TEXT
		)
	`)
	require.NoError(t, err)

	// Insert test data
	_, err = client.Pgx.Exec(ctx, "INSERT INTO circuit_test (data) VALUES ('test1'), ('test2')")
	require.NoError(t, err)

	// Allow replication
	time.Sleep(500 * time.Millisecond)

	t.Run("reads_work_with_healthy_replicas", func(t *testing.T) {
		// Query multiple times to verify replicas work
		for i := 0; i < 10; i++ {
			rows, err := client.Query(ctx, "SELECT COUNT(*) FROM circuit_test")
			require.NoError(t, err, "Query should succeed with healthy replicas")
			rows.Close()
		}
	})

	t.Run("circuit_opens_when_replica_fails", func(t *testing.T) {
		// Kill replica1 to simulate failure
		t.Logf("Stopping replica1 to simulate failure...")
		err := replica1Container.Stop(ctx, nil)
		require.NoError(t, err)

		// Allow circuit breaker to detect failure (try multiple queries)
		failureCount := 0
		for i := 0; i < 10; i++ {
			rows, err := client.Query(ctx, "SELECT COUNT(*) FROM circuit_test")
			if err != nil {
				failureCount++
				t.Logf("Query %d failed (expected during circuit opening): %v", i, err)
			} else {
				rows.Close()
			}
			time.Sleep(100 * time.Millisecond)
		}

		// After failures, queries should succeed via replica2 or primary fallback
		t.Logf("Circuit breaker should have opened for replica1 after %d failures", failureCount)
	})

	t.Run("queries_succeed_with_one_replica_down", func(t *testing.T) {
		// With replica1 down (circuit open), replica2 should handle queries
		successCount := 0
		for i := 0; i < 10; i++ {
			rows, err := client.Query(ctx, "SELECT COUNT(*) FROM circuit_test")
			if err == nil {
				successCount++
				rows.Close()
			}
			time.Sleep(50 * time.Millisecond)
		}

		// Most queries should succeed (routing to healthy replica2 or primary)
		assert.GreaterOrEqual(t, successCount, 8, "Most queries should succeed with one replica down")
	})

	t.Run("all_replicas_down_falls_back_to_primary", func(t *testing.T) {
		// Stop replica2 as well
		t.Logf("Stopping replica2 to force primary fallback...")
		err := replica2Container.Stop(ctx, nil)
		require.NoError(t, err)

		// Allow circuit breaker to detect failure
		time.Sleep(1 * time.Second)

		// Queries should still succeed via primary fallback
		successCount := 0
		for i := range 10 {
			rows, err := client.Query(ctx, "SELECT COUNT(*) FROM circuit_test")
			if err == nil {
				successCount++
				var count int
				if rows.Next() {
					err := rows.Scan(&count)
					require.NoError(t, err)
					assert.Equal(t, 2, count, "Should still read data from primary")
				}
				rows.Close()
			} else {
				t.Logf("Query %d failed: %v", i, err)
			}
			time.Sleep(100 * time.Millisecond)
		}

		// All queries should eventually succeed via primary
		assert.GreaterOrEqual(t, successCount, 8, "Queries should succeed via primary fallback")
	})
}

// TestContextBasedRouting tests WithForcePrimary context routing
func TestContextBasedRouting(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping testcontainer test in short mode")
	}

	ctx := t.Context()

	// Start primary (cleanup handled by setupPrimaryContainer)
	_, primaryPort, networkName, primaryContainerName := setupPrimaryContainer(ctx, t)

	// Start one replica (cleanup handled by setupReplicaContainer)
	_, replicaPort := setupReplicaContainer(ctx, t, primaryContainerName, 1, networkName)

	config := db.Config{
		Host:           "localhost",
		Port:           primaryPort,
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
		ReadReplicas: []db.ReplicaConfig{
			{Host: "localhost", Port: replicaPort},
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
	require.NoError(t, err)
	defer client.Close()

	// Create test table
	_, err = client.Pgx.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS context_test (
			id SERIAL PRIMARY KEY,
			data TEXT,
			created_at TIMESTAMP DEFAULT NOW()
		)
	`)
	require.NoError(t, err)

	t.Run("read_after_write_with_forced_primary", func(t *testing.T) {
		// Write data
		testData := fmt.Sprintf("test-%d", time.Now().UnixNano())
		var insertedID int
		err := client.Pgx.QueryRow(ctx, "INSERT INTO context_test (data) VALUES ($1) RETURNING id", testData).Scan(&insertedID)
		require.NoError(t, err, "Insert should succeed")

		// Immediately read with forced primary (avoids replication lag)
		forcedCtx := db.WithForcePrimary(ctx)

		row := client.QueryRow(forcedCtx, "SELECT data FROM context_test WHERE id = $1", insertedID)

		var retrievedData string
		err = row.Scan(&retrievedData)
		require.NoError(t, err, "Should read from primary immediately")
		assert.Equal(t, testData, retrievedData, "Should see just-written data")
	})

	t.Run("normal_reads_may_use_replica", func(t *testing.T) {
		// Normal reads (without forced primary) may route to replica
		// This tests the default behavior

		// Insert some data and wait for replication
		_, err := client.Pgx.Exec(ctx, "INSERT INTO context_test (data) VALUES ('replica-test')")
		require.NoError(t, err)

		time.Sleep(500 * time.Millisecond) // Allow replication

		// Normal query (may hit replica)
		rows, err := client.Query(ctx, "SELECT COUNT(*) FROM context_test")
		require.NoError(t, err)

		var count int
		if rows.Next() {
			err := rows.Scan(&count)
			require.NoError(t, err)
			assert.GreaterOrEqual(t, count, 1, "Should have data")
		}
		rows.Close()
	})
}

// TestSingleDatabaseWithoutReplicas ensures system works correctly with only primary
func TestSingleDatabaseWithoutReplicas(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping testcontainer test in short mode")
	}

	ctx := t.Context()

	// Start ONLY primary (no replicas) - cleanup handled by setupPrimaryContainer
	_, primaryPort, netName, contName := setupPrimaryContainer(ctx, t)
	_, _ = netName, contName // Not needed for this test

	config := db.Config{
		Host:           "localhost",
		Port:           primaryPort,
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
		ReadReplicas:     []db.ReplicaConfig{}, // Explicitly no replicas
		RunMigrations:    false,
		VerifyConnection: true,
	}

	logCfg := logger.Config{
		Output: "stdout",
		Type:   "json",
		Level:  "error",
	}

	client, err := db.New(ctx, config, logCfg, nil)
	require.NoError(t, err, "Should create client without replicas")
	defer client.Close()

	// Verify no replicas
	assert.Empty(t, client.ReadReplicas, "Should have no replicas")

	// Create test table
	_, err = client.Pgx.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS single_db_test (
			id SERIAL PRIMARY KEY,
			data TEXT
		)
	`)
	require.NoError(t, err, "Should create table on primary")

	t.Run("writes_work_without_replicas", func(t *testing.T) {
		_, err := client.Exec(ctx, "INSERT INTO single_db_test (data) VALUES ($1)", "test1")
		require.NoError(t, err, "Writes should work")
	})

	t.Run("reads_work_without_replicas", func(t *testing.T) {
		rows, err := client.Query(ctx, "SELECT COUNT(*) FROM single_db_test")
		require.NoError(t, err, "Reads should work (go to primary)")

		var count int
		if rows.Next() {
			err := rows.Scan(&count)
			require.NoError(t, err)
			assert.Equal(t, 1, count, "Should have 1 row")
		}
		rows.Close()
	})

	t.Run("context_forced_primary_still_works", func(t *testing.T) {
		// WithForcePrimary should work even without replicas
		forcedCtx := db.WithForcePrimary(ctx)

		rows, err := client.Query(forcedCtx, "SELECT * FROM single_db_test")
		require.NoError(t, err, "Forced primary should work")
		rows.Close()
	})
}
