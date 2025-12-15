// Read Replica Integration Tests with Testcontainers
//
// This test suite validates PostgreSQL read replica functionality by
// automatically spinning up a primary database and multiple read replicas
// using testcontainers. This provides fully isolated, reproducible tests
// without requiring manual docker-compose setup.
//
// Tests verify:
// - Streaming replication from primary to replicas
// - Round-robin load balancing for read queries
// - Write operations routing to primary only
// - Read-only enforcement on replicas
// - Concurrent query safety
// - Performance characteristics
//
// Requirements:
// - Docker or Podman running locally
// - See service/integration/main_test.go for testcontainers setup
//
// Usage:
//   go test -run TestReadReplicasWithTestcontainers -v
//   go test -bench BenchmarkReadReplicaPerformance -v

package integration

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/google/uuid"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	postgresUser     = "postgres"
	postgresPassword = "changeme"
	postgresDB       = "opentdf"
	replicatorUser   = "replicator"
	replicatorPass   = "replicator_password"
)

// testingHelper interface for both *testing.T and *testing.B
type testingHelper interface {
	Helper()
	Logf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	FailNow()
	Cleanup(func())
}

// setupPrimaryContainer creates a PostgreSQL primary database with replication configured
func setupPrimaryContainer(ctx context.Context, t testingHelper) (tc.Container, int) {
	t.Helper()

	randomSuffix := uuid.NewString()[:8]
	containerName := "testcontainer-postgres-primary-" + randomSuffix

	// Setup script to configure replication
	replicationSetup := fmt.Sprintf(`
		#!/bin/bash
		set -e
		echo "Setting up replication user..."
		psql -v ON_ERROR_STOP=1 --username "%s" --dbname "%s" <<-EOSQL
			DO \$\$
			BEGIN
				IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '%s') THEN
					CREATE ROLE %s WITH REPLICATION PASSWORD '%s' LOGIN;
				END IF;
			END
			\$\$;
			GRANT CONNECT ON DATABASE %s TO %s;
		EOSQL
		echo "host replication %s 0.0.0.0/0 md5" >> "$PGDATA/pg_hba.conf"
		psql -v ON_ERROR_STOP=1 --username "%s" --dbname "%s" -c "SELECT pg_reload_conf();"
		echo "Replication user configured"
	`, postgresUser, postgresDB, replicatorUser, replicatorUser, replicatorPass, postgresDB, replicatorUser, replicatorUser, postgresUser, postgresDB)

	req := tc.GenericContainerRequest{
		ContainerRequest: tc.ContainerRequest{
			Image:        "postgres:15-alpine",
			Name:         containerName,
			ExposedPorts: []string{"5432/tcp"},
			Env: map[string]string{
				"POSTGRES_USER":     postgresUser,
				"POSTGRES_PASSWORD": postgresPassword,
				"POSTGRES_DB":       postgresDB,
			},
			Cmd: []string{
				"postgres",
				"-c", "wal_level=replica",
				"-c", "max_wal_senders=10",
				"-c", "max_replication_slots=10",
				"-c", "hot_standby=on",
				"-c", "wal_keep_size=64",
			},
			WaitingFor: wait.ForSQL(nat.Port("5432/tcp"), "pgx", func(host string, port nat.Port) string {
				return fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable",
					postgresUser,
					postgresPassword,
					net.JoinHostPort(host, port.Port()),
					postgresDB,
				)
			}).WithStartupTimeout(time.Second * 60).WithQuery("SELECT 1"),
		},
		Started: true,
	}

	slog.Info("starting primary postgres container")
	container, err := tc.GenericContainer(ctx, req)
	if err != nil {
		t.Errorf("Failed to start primary container: %v", err)
		t.FailNow()
	}

	// Register cleanup immediately after container creation
	t.Cleanup(func() {
		if err := container.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate primary container: %v", err)
		}
	})

	port, err := container.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Errorf("Failed to get primary port: %v", err)
		t.FailNow()
	}

	// Wait for container to be ready
	time.Sleep(2 * time.Second)

	// Execute replication setup
	exitCode, reader, err := container.Exec(ctx, []string{"sh", "-c", replicationSetup})
	if err != nil {
		t.Errorf("Failed to execute replication setup: %v", err)
		t.FailNow()
	}

	// Read output from reader
	output, readErr := io.ReadAll(reader)
	if readErr != nil {
		t.Logf("Failed to read replication setup output: %v", readErr)
	}

	if exitCode != 0 {
		t.Logf("Replication setup output: %s", string(output))
		t.Errorf("Replication setup failed with exit code %d", exitCode)
		t.FailNow()
	}

	slog.Info("primary postgres container ready", slog.Int("port", port.Int()))

	return container, port.Int()
}

// setupReplicaContainer creates a PostgreSQL replica that replicates from the primary
func setupReplicaContainer(ctx context.Context, t testingHelper, primaryHost string, replicaNum int) (tc.Container, int) {
	t.Helper()
	primaryPort := 5432

	randomSuffix := uuid.NewString()[:8]
	containerName := fmt.Sprintf("testcontainer-postgres-replica%d-%s", replicaNum, randomSuffix)

	// Replica initialization script
	replicaInit := fmt.Sprintf(`
		#!/bin/sh
		set -e

		# Wait for primary to be ready
		until pg_isready -h %s -p %d -U %s; do
			echo "Waiting for primary database..."
			sleep 2
		done

		# Check if data directory is empty (first run)
		if [ ! -s "$PGDATA/PG_VERSION" ]; then
			echo "Initializing replica from primary..."
			rm -rf $PGDATA/*

			# Clone primary database
			PGPASSWORD='%s' pg_basebackup \
				-h %s \
				-p %d \
				-D $PGDATA \
				-U %s \
				-v \
				-P \
				-X stream \
				-R

			# Fix permissions
			chmod 700 $PGDATA
			chown -R postgres:postgres $PGDATA

			echo "Replica initialized successfully"
		fi

		# Start PostgreSQL
		exec postgres
	`, primaryHost, primaryPort, postgresUser, replicatorPass, primaryHost, primaryPort, replicatorUser)

	req := tc.GenericContainerRequest{
		ContainerRequest: tc.ContainerRequest{
			Image:        "postgres:15-alpine",
			Name:         containerName,
			ExposedPorts: []string{"5432/tcp"},
			Env: map[string]string{
				"POSTGRES_USER":     postgresUser,
				"POSTGRES_PASSWORD": postgresPassword,
				"POSTGRES_DB":       postgresDB,
				"PGDATA":            "/var/lib/postgresql/data",
			},
			Entrypoint: []string{"/bin/sh", "-c", replicaInit},
			WaitingFor: wait.ForSQL(nat.Port("5432/tcp"), "pgx", func(host string, port nat.Port) string {
				return fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable",
					postgresUser,
					postgresPassword,
					net.JoinHostPort(host, port.Port()),
					postgresDB,
				)
			}).WithStartupTimeout(time.Second * 120).WithQuery("SELECT 1"),
		},
		Started: true,
	}

	slog.Info("starting replica postgres container", slog.Int("replica", replicaNum))
	container, err := tc.GenericContainer(ctx, req)
	if err != nil {
		t.Errorf("Failed to start replica %d container: %v", replicaNum, err)
		t.FailNow()
	}

	// Register cleanup immediately after container creation
	t.Cleanup(func() {
		if err := container.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate replica %d container: %v", replicaNum, err)
		}
	})

	port, err := container.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Errorf("Failed to get replica %d port: %v", replicaNum, err)
		t.FailNow()
	}

	slog.Info("replica postgres container ready",
		slog.Int("replica", replicaNum),
		slog.Int("port", port.Int()))

	return container, port.Int()
}

func TestReadReplicasWithTestcontainers(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping testcontainer test in short mode")
	}

	ctx := t.Context()

	// Start primary database (cleanup handled by setupPrimaryContainer)
	primaryContainer, primaryPort := setupPrimaryContainer(ctx, t)

	// Get primary host (for replica connection)
	primaryHost, err := primaryContainer.Host(ctx)
	require.NoError(t, err)

	// Start replica databases (cleanup handled by setupReplicaContainer)
	_, replica1Port := setupReplicaContainer(ctx, t, primaryHost, 1)
	_, replica2Port := setupReplicaContainer(ctx, t, primaryHost, 2)

	// Configure database client with replicas
	config := db.Config{
		Host:           "localhost",
		Port:           primaryPort,
		Database:       postgresDB,
		User:           postgresUser,
		Password:       postgresPassword,
		SSLMode:        "disable",
		Schema:         "public",
		ConnectTimeout: 15,
		Pool: db.PoolConfig{
			MaxConns:          10,
			MinConns:          0,
			MaxConnLifetime:   3600,
			MaxConnIdleTime:   1800,
			HealthCheckPeriod: 60,
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
		Level:  "error",
	}

	// Create database client
	client, err := db.New(ctx, config, logCfg, nil)
	require.NoError(t, err, "Failed to create database client")
	defer client.Close()

	// Verify replicas are configured
	assert.Len(t, client.ReadReplicas, 2, "Should have 2 read replicas")

	t.Run("verify_replication_status", func(t *testing.T) {
		// Check replication status on primary
		rows, err := client.Pgx.Query(ctx, "SELECT client_addr, state, sync_state FROM pg_stat_replication")
		require.NoError(t, err)
		defer rows.Close()

		replicaCount := 0
		for rows.Next() {
			var clientAddr, state, syncState string
			err := rows.Scan(&clientAddr, &state, &syncState)
			require.NoError(t, err)
			t.Logf("Replica: addr=%s, state=%s, sync_state=%s", clientAddr, state, syncState)
			replicaCount++
		}

		assert.Equal(t, 2, replicaCount, "Should have 2 active replicas streaming")
	})

	t.Run("write_and_replicate_data", func(t *testing.T) {
		// Create test table on primary
		_, err = client.Pgx.Exec(ctx, `
			CREATE TABLE IF NOT EXISTS replica_test (
				id SERIAL PRIMARY KEY,
				data TEXT,
				created_at TIMESTAMP DEFAULT NOW()
			)
		`)
		require.NoError(t, err, "Failed to create test table")

		// Insert test data on primary
		_, err = client.Pgx.Exec(ctx, "INSERT INTO replica_test (data) VALUES ($1), ($2), ($3)",
			"test data 1", "test data 2", "test data 3")
		require.NoError(t, err, "Failed to insert test data")

		// Allow replication to catch up
		time.Sleep(500 * time.Millisecond)

		// Read from replicas using client.Query (should use round-robin)
		for range 6 {
			rows, err := client.Query(ctx, "SELECT COUNT(*) FROM replica_test")
			require.NoError(t, err, "Read query should succeed")

			var count int
			if rows.Next() {
				err = rows.Scan(&count)
				require.NoError(t, err, "Should scan count")
				assert.Equal(t, 3, count, "Should have 3 rows replicated")
			}
			rows.Close()
		}
	})

	t.Run("round_robin_distribution", func(t *testing.T) {
		// Perform many reads to verify round-robin works
		const numQueries = 100
		for i := 0; i < numQueries; i++ {
			rows, err := client.Query(ctx, "SELECT 1")
			require.NoError(t, err)
			rows.Close()
		}

		// Just verify no errors - actual distribution is internal
		// The atomic counter ensures thread-safe round-robin
	})

	t.Run("concurrent_read_queries", func(t *testing.T) {
		const numGoroutines = 50
		const queriesPerGoroutine = 20

		var wg sync.WaitGroup
		errChan := make(chan error, numGoroutines*queriesPerGoroutine)

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < queriesPerGoroutine; j++ {
					rows, err := client.Query(ctx, "SELECT COUNT(*) FROM replica_test")
					if err != nil {
						errChan <- err
						return
					}

					if rows.Next() {
						var count int
						if err := rows.Scan(&count); err != nil {
							errChan <- err
							rows.Close()
							return
						}
					}
					rows.Close()
				}
			}()
		}

		wg.Wait()
		close(errChan)

		// Check for errors
		for err := range errChan {
			t.Errorf("Concurrent query error: %v", err)
		}
	})

	t.Run("writes_go_to_primary", func(t *testing.T) {
		// All writes should go to primary
		_, err := client.Pgx.Exec(ctx, "INSERT INTO replica_test (data) VALUES ($1)", "write test")
		require.NoError(t, err, "Write should succeed on primary")

		// Verify write succeeded
		time.Sleep(100 * time.Millisecond)
		rows, err := client.Query(ctx, "SELECT COUNT(*) FROM replica_test WHERE data = $1", "write test")
		require.NoError(t, err)

		var count int
		if rows.Next() {
			err = rows.Scan(&count)
			require.NoError(t, err)
			assert.Equal(t, 1, count, "Write should be visible in replicas")
		}
		rows.Close()
	})

	t.Run("replica_is_read_only", func(t *testing.T) {
		// Try to write directly to a replica (should fail)
		_, err := client.ReadReplicas[0].Exec(ctx, "INSERT INTO replica_test (data) VALUES ($1)", "should fail")
		require.Error(t, err, "Write to replica should fail")
		assert.Contains(t, err.Error(), "read-only", "Error should indicate read-only mode")
	})
}

// BenchmarkReadReplicaPerformance benchmarks query performance with replicas
func BenchmarkReadReplicaPerformance(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark in short mode")
	}

	ctx := b.Context()

	// Start primary database (cleanup handled by setupPrimaryContainer)
	primaryContainer, primaryPort := setupPrimaryContainer(ctx, b)

	primaryHost, _ := primaryContainer.Host(ctx)

	// Start one replica (cleanup handled by setupReplicaContainer)
	_, replica1Port := setupReplicaContainer(ctx, b, primaryHost, 1)

	config := db.Config{
		Host:           "localhost",
		Port:           primaryPort,
		Database:       postgresDB,
		User:           postgresUser,
		Password:       postgresPassword,
		SSLMode:        "disable",
		Schema:         "public",
		ConnectTimeout: 15,
		Pool: db.PoolConfig{
			MaxConns: 20,
		},
		ReadReplicas: []db.ReplicaConfig{
			{Host: "localhost", Port: replica1Port},
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
	if err != nil {
		b.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// Create test data
	_, _ = client.Pgx.Exec(ctx, "CREATE TABLE IF NOT EXISTS bench_test (id SERIAL PRIMARY KEY, data TEXT)")
	_, _ = client.Pgx.Exec(ctx, "INSERT INTO bench_test (data) SELECT 'data' FROM generate_series(1, 1000)")
	time.Sleep(1 * time.Second) // Allow replication

	b.ResetTimer()

	b.Run("read_queries", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rows, err := client.Query(ctx, "SELECT COUNT(*) FROM bench_test")
			if err != nil {
				b.Fatal(err)
			}
			rows.Close()
		}
	})

	b.Run("concurrent_reads", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				rows, err := client.Query(ctx, "SELECT COUNT(*) FROM bench_test")
				if err != nil {
					b.Fatal(err)
				}
				rows.Close()
			}
		})
	})
}
