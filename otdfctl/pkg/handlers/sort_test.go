package handlers

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSortOption(t *testing.T) {
	tests := []struct {
		name      string
		field     string
		order     string
		expected  SortOption
		wantError error
	}{
		{
			name: "empty",
		},
		{
			name:  "field only",
			field: "name",
			expected: SortOption{
				Field:     "name",
				Direction: policy.SortDirection_SORT_DIRECTION_UNSPECIFIED,
			},
		},
		{
			name:  "ascending",
			field: "created_at",
			order: "asc",
			expected: SortOption{
				Field:     "created_at",
				Direction: policy.SortDirection_SORT_DIRECTION_ASC,
			},
		},
		{
			name:  "descending with whitespace",
			field: " updated_at ",
			order: " DESC ",
			expected: SortOption{
				Field:     "updated_at",
				Direction: policy.SortDirection_SORT_DIRECTION_DESC,
			},
		},
		{
			name:  "direction only",
			order: "desc",
			expected: SortOption{
				Field:     "",
				Direction: policy.SortDirection_SORT_DIRECTION_DESC,
			},
		},
		{
			name:      "invalid direction",
			field:     "name",
			order:     "up",
			wantError: ErrInvalidSortDirection,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := NewSortOption(tt.field, tt.order)
			if tt.wantError != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.wantError)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestSortField(t *testing.T) {
	allowed := map[string]int{
		"name":       1,
		"created_at": 2,
	}

	t.Run("omitted field returns zero value", func(t *testing.T) {
		field, err := sortField("test resources", SortOption{}, allowed)
		require.NoError(t, err)
		assert.Equal(t, 0, field)
	})

	t.Run("known field returns mapped value", func(t *testing.T) {
		field, err := sortField("test resources", SortOption{Field: "name"}, allowed)
		require.NoError(t, err)
		assert.Equal(t, 1, field)
	})

	t.Run("unknown field returns valid fields", func(t *testing.T) {
		field, err := sortField("test resources", SortOption{Field: "updated_at"}, allowed)
		require.Error(t, err)
		assert.Equal(t, 0, field)
		require.ErrorIs(t, err, ErrInvalidSortField)
		assert.EqualError(t, err, "invalid sort field\n\"updated_at\" is not a valid sort field for test resources; valid fields: created_at, name")
	})
}
