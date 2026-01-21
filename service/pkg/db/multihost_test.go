package db

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/opentdf/platform/service/logger"
	"github.com/sony/gobreaker/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMultiHostPrimaryConfig tests that multi-host primary configuration
// generates correct connection strings with target_session_attrs=primary
func TestMultiHostPrimaryConfig(t *testing.T) {
	tests := []struct {
		name              string
		config            Config
		expectedHosts     string
		shouldHavePrimary bool
	}{
		{
			name: "single host (backward compatible)",
			config: Config{
				Host:     "localhost",
				Port:     5432,
				Database: "testdb",
				User:     "testuser",
				Password: "testpass",
				SSLMode:  "disable",
			},
			expectedHosts:     "localhost:5432",
			shouldHavePrimary: false,
		},
		{
			name: "multi-host primary for failover",
			config: Config{
				Database: "testdb",
				User:     "testuser",
				Password: "testpass",
				SSLMode:  "disable",
				PrimaryHosts: []ReplicaConfig{
					{Host: "primary1", Port: 5432},
					{Host: "primary2", Port: 5433},
					{Host: "primary3", Port: 5434},
				},
			},
			expectedHosts:     "primary1:5432,primary2:5433,primary3:5434",
			shouldHavePrimary: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			poolConfig, err := tt.config.buildConfig()
			require.NoError(t, err, "buildConfig should not error")
			require.NotNil(t, poolConfig, "poolConfig should not be nil")

			connString := poolConfig.ConnString()
			assert.Contains(t, connString, tt.expectedHosts, "connection string should contain expected hosts")

			if tt.shouldHavePrimary {
				assert.Contains(t, connString, "target_session_attrs=primary",
					"multi-host config should include target_session_attrs=primary")
			}
		})
	}
}

// TestContextForcePrimary tests the context-based primary routing
func TestContextForcePrimary(t *testing.T) {
	ctx := t.Context()

	// Default context should not force primary
	assert.False(t, shouldForcePrimary(ctx), "default context should not force primary")

	// WithForcePrimary should force primary
	ctxWithForce := WithForcePrimary(ctx)
	assert.True(t, shouldForcePrimary(ctxWithForce), "WithForcePrimary context should force primary")
}

// TestReplicaCircuitBreaker tests basic circuit breaker functionality
func TestReplicaCircuitBreaker(t *testing.T) {
	// This is a unit test for the circuit breaker logic
	// Note: We can't test with real connections here, but we can test the logic

	t.Run("no replicas returns nil", func(t *testing.T) {
		cb := &replicaCircuitBreakers{
			breakers: []*gobreaker.CircuitBreaker[pgx.Rows]{},
			pools:    []PgxIface{},
		}

		pool, idx := cb.getHealthyReplica()
		assert.Nil(t, pool, "should return nil when no replicas configured")
		assert.Equal(t, -1, idx, "should return -1 index when no replicas")
	})

	t.Run("circuit breaker returns replica when closed", func(t *testing.T) {
		mockPool := &mockPgxIface{}
		logger := logger.CreateTestLogger().Logger

		cb := newReplicaCircuitBreakers([]PgxIface{mockPool}, logger)

		pool, idx := cb.getHealthyReplica()
		assert.NotNil(t, pool, "should return replica when circuit breaker closed")
		assert.Equal(t, 0, idx, "should return index 0")
		assert.Equal(t, mockPool, pool, "should return the mock pool")
	})

	t.Run("stats are returned", func(t *testing.T) {
		mockPool := &mockPgxIface{}
		logger := logger.CreateTestLogger().Logger

		cb := newReplicaCircuitBreakers([]PgxIface{mockPool}, logger)

		stats := cb.getStats()
		assert.Equal(t, 1, stats["total_replicas"], "should have 1 replica")
		assert.Equal(t, 1, stats["healthy_replicas"], "should have 1 healthy replica")
		assert.Equal(t, 0, stats["open_circuit_breakers"], "should have 0 open circuit breakers")
	})
}

// TestQueryRowCircuitBreaker verifies that QueryRow failures are tracked by the circuit breaker
func TestQueryRowCircuitBreaker(t *testing.T) {
	ctx := t.Context()

	// Create a mock pool that simulates Query-level failures (connection errors, etc.)
	// This ensures the circuit breaker sees the failures when Query() is called
	mockPool := &mockFailingPgxIface{failQuery: true}
	logger := logger.CreateTestLogger().Logger

	cb := newReplicaCircuitBreakers([]PgxIface{mockPool}, logger)

	t.Run("QueryRow_failures_trip_circuit_breaker", func(t *testing.T) {
		// Initial state: circuit should be closed
		assert.Equal(t, gobreaker.StateClosed, cb.breakers[0].State(), "circuit should start closed")

		// Make 5 QueryRow calls that will fail at Query level
		// Circuit breaker opens after 60% failure rate over 3+ requests
		for range 5 {
			_, err := cb.executeQueryRow(ctx, 0, "SELECT * FROM test", nil)
			require.Error(t, err, "QueryRow should fail when underlying Query fails")
		}

		// Circuit breaker should now be open due to failures
		assert.Equal(t, gobreaker.StateOpen, cb.breakers[0].State(),
			"circuit should open after QueryRow failures")
	})

	t.Run("QueryRow_successes_keep_circuit_closed", func(t *testing.T) {
		// Create a mock pool that succeeds
		successPool := &mockFailingPgxIface{failQuery: false}
		successCB := newReplicaCircuitBreakers([]PgxIface{successPool}, logger)

		// Make multiple successful QueryRow calls
		for range 10 {
			row, err := successCB.executeQueryRow(ctx, 0, "SELECT * FROM test", nil)
			require.NoError(t, err, "QueryRow should succeed")
			require.NotNil(t, row, "Should return a row")
		}

		// Circuit should remain closed
		assert.Equal(t, gobreaker.StateClosed, successCB.breakers[0].State(),
			"circuit should stay closed with successful QueryRow calls")
	})

	t.Run("QueryRow_vs_Query_consistency", func(t *testing.T) {
		// Verify that QueryRow and Query both contribute to the same circuit breaker

		mixedPool := &mockFailingPgxIface{failQuery: true}
		mixedCB := newReplicaCircuitBreakers([]PgxIface{mixedPool}, logger)

		// Make some Query calls that fail
		for range 2 {
			rows, err := mixedCB.executeQuery(ctx, 0, "SELECT * FROM test", nil)
			require.Error(t, err, "Query should fail")
			if rows != nil {
				_ = rows.Err() // Check rows error
				rows.Close()
			}
		}

		// Circuit not open yet (need 3+ requests with 60% failure)
		assert.Equal(t, gobreaker.StateClosed, mixedCB.breakers[0].State())

		// Add one more QueryRow call to trip the breaker
		_, err := mixedCB.executeQueryRow(ctx, 0, "SELECT * FROM test", nil)
		require.Error(t, err, "QueryRow should fail")

		// Now circuit should be open (3 requests, 100% failure rate)
		assert.Equal(t, gobreaker.StateOpen, mixedCB.breakers[0].State(),
			"circuit should open when Query and QueryRow failures are combined")
	})
}

// TestConfigValidation tests configuration validation rules
func TestConfigValidation(t *testing.T) {
	ctx := t.Context()
	logCfg := logger.Config{
		Output: "stdout",
		Type:   "json",
		Level:  "error",
	}

	t.Run("rejects_both_host_and_primary_hosts", func(t *testing.T) {
		config := Config{
			Host:     "localhost",
			Port:     5432,
			Database: "testdb",
			User:     "testuser",
			Password: "testpass",
			SSLMode:  "disable",
			PrimaryHosts: []ReplicaConfig{
				{Host: "primary1", Port: 5432},
				{Host: "primary2", Port: 5433},
			},
			VerifyConnection: false, // Don't verify since we're testing validation
		}

		_, err := New(ctx, config, logCfg, nil)
		require.Error(t, err, "Should error when both host and primary_hosts are specified")
		assert.Contains(t, err.Error(), "cannot specify both 'host' and 'primary_hosts'")
	})

	t.Run("accepts_only_host", func(t *testing.T) {
		config := Config{
			Host:     "localhost",
			Port:     5432,
			Database: "testdb",
			User:     "testuser",
			Password: "testpass",
			SSLMode:  "disable",
			Pool: PoolConfig{
				MaxConns:          1,
				HealthCheckPeriod: 60,
			},
			VerifyConnection: false,
		}

		// Should not error during config validation (will error on connection, but that's expected)
		_, err := New(ctx, config, logCfg, nil)
		// We expect a connection error, not a validation error
		if err != nil {
			assert.NotContains(t, err.Error(), "cannot specify both 'host' and 'primary_hosts'")
		}
	})

	t.Run("accepts_only_primary_hosts", func(t *testing.T) {
		config := Config{
			Database: "testdb",
			User:     "testuser",
			Password: "testpass",
			SSLMode:  "disable",
			Pool: PoolConfig{
				MaxConns:          1,
				HealthCheckPeriod: 60,
			},
			PrimaryHosts: []ReplicaConfig{
				{Host: "primary1", Port: 5432},
			},
			VerifyConnection: false,
		}

		// Should not error during config validation (will error on connection, but that's expected)
		_, err := New(ctx, config, logCfg, nil)
		// We expect a connection error, not a validation error
		if err != nil {
			assert.NotContains(t, err.Error(), "cannot specify both 'host' and 'primary_hosts'")
		}
	})
}

// mockPgxIface is a minimal mock for testing
type mockPgxIface struct {
	PgxIface
}

// mockFailingPgxIface simulates Query/QueryRow operations that can fail
type mockFailingPgxIface struct {
	PgxIface
	failQuery    bool
	failQueryRow bool
}

// Query implements PgxIface.Query
func (m *mockFailingPgxIface) Query(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
	if m.failQuery {
		return nil, assert.AnError
	}
	return &mockRows{}, nil
}

// QueryRow implements PgxIface.QueryRow
func (m *mockFailingPgxIface) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row {
	if m.failQueryRow {
		return &mockRow{err: assert.AnError}
	}
	return &mockRow{}
}

// mockRows implements pgx.Rows for testing
type mockRows struct {
	called bool
}

func (m *mockRows) Close()                                       {}
func (m *mockRows) Err() error                                   { return nil }
func (m *mockRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (m *mockRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (m *mockRows) Next() bool {
	if m.called {
		return false
	}
	m.called = true
	return true
}

func (m *mockRows) Scan(_ ...any) error {
	return nil
}

func (m *mockRows) Values() ([]any, error) {
	return nil, nil
}

func (m *mockRows) RawValues() [][]byte {
	return nil
}

func (m *mockRows) Conn() *pgx.Conn {
	return nil
}

// mockRow implements pgx.Row for testing
type mockRow struct {
	err error
}

func (m *mockRow) Scan(_ ...any) error {
	return m.err
}
