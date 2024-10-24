package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_GetListLimit(t *testing.T) {
	var defaultListLimit int32 = 1000
	cases := []struct {
		limit    int32
		expected int32
	}{
		{
			0,
			1000,
		},
		{
			1,
			1,
		},
		{
			10000,
			10000,
		},
	}

	for _, test := range cases {
		result := getListLimit(test.limit, defaultListLimit)
		assert.Equal(t, test.expected, result)
	}
}

func Test_GetNextOffset(t *testing.T) {
	var defaultTestListLimit int32 = 250
	cases := []struct {
		currOffset int32
		limit      int32
		total      int32
		expected   int32
		scenario   string
	}{
		{
			currOffset: 0,
			limit:      defaultTestListLimit,
			total:      1000,
			expected:   defaultTestListLimit,
			scenario:   "defaulted limit with many remaining",
		},
		{
			currOffset: 100,
			limit:      100,
			total:      1000,
			expected:   200,
			scenario:   "custom limit with many remaining",
		},
		{
			currOffset: 100,
			limit:      100,
			total:      200,
			expected:   0,
			scenario:   "custom limit with none remaining",
		},
		{
			currOffset: 100,
			limit:      defaultTestListLimit,
			total:      200,
			expected:   0,
			scenario:   "default limit with none remaining",
		},
		{
			currOffset: 350 - defaultTestListLimit - 1,
			limit:      defaultTestListLimit,
			total:      350,
			expected:   349,
			scenario:   "default limit with exactly one remaining",
		},
		{
			currOffset: 1000 - 500 - 1,
			limit:      500,
			total:      1000,
			expected:   1000 - 1,
			scenario:   "custom limit with exactly one remaining",
		},
	}

	for _, test := range cases {
		result := getNextOffset(test.currOffset, test.limit, test.total)
		assert.Equal(t, test.expected, result, test.scenario)
	}
}
