package integration

import (
	"context"
	"fmt"
	"testing"

	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/stretchr/testify/require"
)

// assertIDsInOrder verifies that the given IDs appear in the expected relative
// order within items, tolerating extra rows that don't match any target ID.
func assertIDsInOrder[T any](tb testing.TB, items []T, getID func(T) string, ids ...string) {
	tb.Helper()

	targets := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		targets[id] = struct{}{}
	}

	positions := make(map[string]int, len(ids))
	for i, item := range items {
		id := getID(item)
		if _, ok := targets[id]; ok {
			positions[id] = i
		}
	}

	require.Len(tb, positions, len(ids))
	for i := 0; i < len(ids)-1; i++ {
		require.Less(tb, positions[ids[i]], positions[ids[i+1]])
	}
}

// forceDeleteRows hard-deletes rows by ID via raw SQL, bypassing the API's
// soft-delete/deactivate limitation for resources like namespaces and attributes.
func forceDeleteRows(ctx context.Context, db fixtures.DBInterface, table string, ids []string) error {
	sql := fmt.Sprintf(
		`DELETE FROM %s WHERE id = ANY($1::uuid[])`,
		db.TableName(table),
	)
	_, err := db.Client.Pgx.Exec(ctx, sql, ids)
	return err
}

// forceCreatedAtTie sets created_at to a fixed timestamp for the given IDs,
// guaranteeing that the ORDER BY tiebreaker (id ASC) determines sort order.
func forceCreatedAtTie(ctx context.Context, db fixtures.DBInterface, table string, ids []string) error {
	sql := fmt.Sprintf(
		`UPDATE %s SET created_at = '2000-01-01T00:00:00Z' WHERE id = ANY($1::uuid[])`,
		db.TableName(table),
	)
	_, err := db.Client.Pgx.Exec(ctx, sql, ids)
	return err
}
