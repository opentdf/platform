package access

import (
	"errors"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsResourceExhausted(t *testing.T) {
	assert.True(t, isResourceExhausted(connect.NewError(connect.CodeResourceExhausted, errors.New("too big"))))
	assert.False(t, isResourceExhausted(connect.NewError(connect.CodeInternal, errors.New("boom"))))
	assert.False(t, isResourceExhausted(errors.New("plain error")))
	assert.False(t, isResourceExhausted(nil))
}

// pagingSource simulates a paginated list endpoint that returns resource_exhausted whenever the
// requested page would contain more than maxPerPage items, mimicking the connect message size limit.
type pagingSource struct {
	total      int32
	maxPerPage int32
	calls      int
	minLimit   int32
	collected  []int32
}

func (s *pagingSource) fetch(offset, limit int32) (int32, error) {
	s.calls++
	if s.minLimit == 0 || limit < s.minLimit {
		s.minLimit = limit
	}

	pageSize := limit
	if remaining := s.total - offset; pageSize > remaining {
		pageSize = remaining
	}
	// Simulate the transport limit: a page carrying too many items is rejected before any data.
	if pageSize > s.maxPerPage {
		return 0, connect.NewError(connect.CodeResourceExhausted, errors.New("message too large"))
	}

	for i := offset; i < offset+pageSize; i++ {
		s.collected = append(s.collected, i)
	}
	next := offset + pageSize
	if next >= s.total {
		next = 0
	}
	return next, nil
}

func TestPaginateAll_ShrinksOnResourceExhaustedAndAggregates(t *testing.T) {
	src := &pagingSource{total: 8, maxPerPage: 4}

	err := paginateAll(src.fetch)
	require.NoError(t, err)

	assert.Equal(t, []int32{0, 1, 2, 3, 4, 5, 6, 7}, src.collected, "all items collected across shrunk pages")
	assert.LessOrEqual(t, src.minLimit, src.maxPerPage, "page size shrank to fit under the limit")
	assert.Less(t, src.minLimit, int32(entitlementPolicyMaxPageSize), "page size shrank below the initial")
}

func TestPaginateAll_SinglePage(t *testing.T) {
	var calls int
	err := paginateAll(func(_, _ int32) (int32, error) {
		calls++
		return 0, nil // nextOffset <= 0 => done
	})
	require.NoError(t, err)
	assert.Equal(t, 1, calls)
}

func TestPaginateAll_PropagatesNonExhaustedError(t *testing.T) {
	sentinel := errors.New("boom")
	err := paginateAll(func(_, _ int32) (int32, error) {
		return 0, sentinel
	})
	require.ErrorIs(t, err, sentinel)
}

func TestPaginateAll_FloorStopsWhenSingleItemStillExhausts(t *testing.T) {
	var calls int
	var lastLimit int32
	err := paginateAll(func(_, limit int32) (int32, error) {
		calls++
		lastLimit = limit
		// Always too large, even at the floor: must terminate and surface the error, not loop forever.
		return 0, connect.NewError(connect.CodeResourceExhausted, errors.New("single object too large"))
	})
	require.Error(t, err)
	assert.True(t, isResourceExhausted(err))
	assert.Equal(t, int32(entitlementPolicyMinPageSize), lastLimit, "shrinks all the way to the floor before giving up")
	assert.Positive(t, calls)
}
