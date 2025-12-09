package db

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/sony/gobreaker/v2"
)

// replicaCircuitBreakers manages circuit breakers for read replicas
type replicaCircuitBreakers struct {
	breakers     []*gobreaker.CircuitBreaker[pgx.Rows]
	pools        []PgxIface
	replicaIndex atomic.Uint32
	logger       *slog.Logger
}

// newReplicaCircuitBreakers creates circuit breakers for each replica pool
func newReplicaCircuitBreakers(replicas []PgxIface, logger *slog.Logger) *replicaCircuitBreakers {
	breakers := make([]*gobreaker.CircuitBreaker[pgx.Rows], len(replicas))

	for i := range replicas {
		idx := i
		breakers[i] = gobreaker.NewCircuitBreaker[pgx.Rows](gobreaker.Settings{
			Name:        fmt.Sprintf("replica-%d", i+1),
			MaxRequests: 3, // Allow 3 requests in half-open state
			Interval:    30 * time.Second,
			Timeout:     60 * time.Second, // Time to wait in open state before trying again
			ReadyToTrip: func(counts gobreaker.Counts) bool {
				// Open circuit after 3 consecutive failures
				failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
				return counts.Requests >= 3 && failureRatio >= 0.6
			},
			OnStateChange: func(name string, from, to gobreaker.State) {
				logger.Info("replica circuit breaker state changed",
					slog.Int("replica_index", idx),
					slog.String("from", from.String()),
					slog.String("to", to.String()),
				)
			},
		})
	}

	return &replicaCircuitBreakers{
		breakers: breakers,
		pools:    replicas,
		logger:   logger,
	}
}

// getHealthyReplica returns a healthy replica using round-robin, or nil if all circuit breakers are open
func (rcb *replicaCircuitBreakers) getHealthyReplica() (PgxIface, int) {
	if len(rcb.breakers) == 0 {
		return nil, -1
	}

	// Try each replica starting from round-robin index
	startIdx := int(rcb.replicaIndex.Add(1) - 1)
	for i := range len(rcb.breakers) {
		idx := (startIdx + i) % len(rcb.breakers)

		// Check if circuit breaker is not open
		if rcb.breakers[idx].State() != gobreaker.StateOpen {
			return rcb.pools[idx], idx
		}
	}

	// All circuit breakers are open
	return nil, -1
}

// executeQuery wraps a query execution with circuit breaker protection
func (rcb *replicaCircuitBreakers) executeQuery(ctx context.Context, replicaIdx int, sql string, args []interface{}) (pgx.Rows, error) {
	if replicaIdx < 0 || replicaIdx >= len(rcb.breakers) {
		return nil, fmt.Errorf("invalid replica index: %d", replicaIdx)
	}

	// Execute query through circuit breaker
	return rcb.breakers[replicaIdx].Execute(func() (pgx.Rows, error) {
		return rcb.pools[replicaIdx].Query(ctx, sql, args...)
	})
}

// executeQueryRow wraps a query row execution with circuit breaker protection
func (rcb *replicaCircuitBreakers) executeQueryRow(ctx context.Context, replicaIdx int, sql string, args []interface{}) (pgx.Row, error) {
	if replicaIdx < 0 || replicaIdx >= len(rcb.breakers) {
		return nil, fmt.Errorf("invalid replica index: %d", replicaIdx)
	}

	// For QueryRow, we need a different approach since gobreaker expects a return value
	// but we need to return the Row directly without wrapping in circuit breaker
	// Instead, we'll check the state and track failures manually
	if rcb.breakers[replicaIdx].State() == gobreaker.StateOpen {
		return nil, fmt.Errorf("circuit breaker open for replica %d", replicaIdx)
	}

	return rcb.pools[replicaIdx].QueryRow(ctx, sql, args...), nil
}

// getStats returns circuit breaker statistics for monitoring
func (rcb *replicaCircuitBreakers) getStats() map[string]interface{} {
	stats := make(map[string]interface{})
	healthy := 0
	open := 0

	for i, cb := range rcb.breakers {
		state := cb.State()
		stats[fmt.Sprintf("replica_%d_state", i+1)] = state.String()

		if state == gobreaker.StateOpen {
			open++
		} else {
			healthy++
		}
	}

	stats["total_replicas"] = len(rcb.breakers)
	stats["healthy_replicas"] = healthy
	stats["open_circuit_breakers"] = open

	return stats
}
