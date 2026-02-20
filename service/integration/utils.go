package integration

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func assertIDsInDescendingOrder[T any](tb testing.TB, items []T, getID func(T) string, ids ...string) {
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
