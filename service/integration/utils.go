package integration

import (
	"context"
	"fmt"
	"testing"

	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/stretchr/testify/require"
)

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
