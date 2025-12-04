package flattening

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func BenchmarkFlattenMap(b *testing.B) {
	simpleInput := map[string]interface{}{
		"a": "aa",
		"b": 2,
		"c": 3.1,
		"d": false,
	}
	for n := 0; n < b.N; n++ {
		_, _ = Flatten(simpleInput)
	}
}

func BenchmarkFlattenMapWithinMap(b *testing.B) {
	simpleInput := map[string]interface{}{
		"a": "aa",
		"submap": map[string]interface{}{
			"b": 2,
			"c": 3.1,
			"d": false,
		},
	}
	for n := 0; n < b.N; n++ {
		_, _ = Flatten(simpleInput)
	}
}

func BenchmarkGetFromFlattened(b *testing.B) {
	flatInput := Flattened{
		Items: []Item{
			{Key: ".a", Value: "aa"},
			// rest of the Items
		},
	}
	queryString := ".a"
	for n := 0; n < b.N; n++ {
		_ = GetFromFlattened(flatInput, queryString)
	}
}

func TestSimpleMap(t *testing.T) {
	simpleInput := map[string]interface{}{
		"a": "aa",
		"b": 2,
		"c": 3.1,
		"d": false,
	}
	expectedOutput := Flattened{
		Items: []Item{
			{Key: ".a", Value: "aa"},
			{Key: ".b", Value: 2},
			{Key: ".c", Value: 3.1},
			{Key: ".d", Value: false},
		},
	}
	actualOutput, err := Flatten(simpleInput)
	require.NoError(t, err)
	assert.NotNil(t, actualOutput)
	assert.ElementsMatch(t, expectedOutput.Items, actualOutput.Items)
}

func TestMapWithinMap(t *testing.T) {
	simpleInput := map[string]interface{}{
		"a": "aa",
		"submap": map[string]interface{}{
			"b": 2,
			"c": 3.1,
			"d": false,
		},
	}
	expectedOutput := Flattened{
		Items: []Item{
			{Key: ".a", Value: "aa"},
			{Key: ".submap.b", Value: 2},
			{Key: ".submap.c", Value: 3.1},
			{Key: ".submap.d", Value: false},
		},
	}
	actualOutput, err := Flatten(simpleInput)
	require.NoError(t, err)
	assert.NotNil(t, actualOutput)
	assert.ElementsMatch(t, expectedOutput.Items, actualOutput.Items)
}

func TestMapWithinMapWithinMap(t *testing.T) {
	simpleInput := map[string]interface{}{
		"a": "aa",
		"submap": map[string]interface{}{
			"b": 2,
			"subsubmap": map[string]interface{}{
				"c": 3.1,
				"d": false,
			},
		},
	}
	expectedOutput := Flattened{
		Items: []Item{
			{Key: ".a", Value: "aa"},
			{Key: ".submap.b", Value: 2},
			{Key: ".submap.subsubmap.c", Value: 3.1},
			{Key: ".submap.subsubmap.d", Value: false},
		},
	}
	actualOutput, err := Flatten(simpleInput)
	require.NoError(t, err)
	assert.NotNil(t, actualOutput)
	assert.ElementsMatch(t, expectedOutput.Items, actualOutput.Items)
}

func TestListWithinMap(t *testing.T) {
	simpleInput := map[string]interface{}{
		"a": "aa",
		"sublist": []interface{}{
			2,
			3.1,
			false,
		},
	}
	expectedOutput := Flattened{
		Items: []Item{
			{Key: ".a", Value: "aa"},
			{Key: ".sublist[0]", Value: 2},
			{Key: ".sublist[1]", Value: 3.1},
			{Key: ".sublist[2]", Value: false},
			{Key: ".sublist[]", Value: 2},
			{Key: ".sublist[]", Value: 3.1},
			{Key: ".sublist[]", Value: false},
		},
	}
	actualOutput, err := Flatten(simpleInput)
	require.NoError(t, err)
	assert.NotNil(t, actualOutput)
	assert.ElementsMatch(t, expectedOutput.Items, actualOutput.Items)
}

func TestMapWithinListWithinMap(t *testing.T) {
	simpleInput := map[string]interface{}{
		"a": "aa",
		"sublist": []interface{}{
			2,
			map[string]interface{}{
				"c": 3.1,
				"d": false,
			},
		},
	}
	expectedOutput := Flattened{
		Items: []Item{
			{Key: ".a", Value: "aa"},
			{Key: ".sublist[0]", Value: 2},
			{Key: ".sublist[1].c", Value: 3.1},
			{Key: ".sublist[1].d", Value: false},
			{Key: ".sublist[]", Value: 2},
			{Key: ".sublist[].c", Value: 3.1},
			{Key: ".sublist[].d", Value: false},
		},
	}
	actualOutput, err := Flatten(simpleInput)
	require.NoError(t, err)
	assert.NotNil(t, actualOutput)
	assert.ElementsMatch(t, expectedOutput.Items, actualOutput.Items)
}

func TestListWithinMapWithinListWithinMap(t *testing.T) {
	simpleInput := map[string]interface{}{
		"a": "aa",
		"sublist": []interface{}{
			2,
			map[string]interface{}{
				"c": 3.1,
				"subsublist": []interface{}{
					false,
				},
			},
		},
	}
	expectedOutput := Flattened{
		Items: []Item{
			{Key: ".a", Value: "aa"},
			{Key: ".sublist[0]", Value: 2},
			{Key: ".sublist[1].c", Value: 3.1},
			{Key: ".sublist[1].subsublist[0]", Value: false},
			{Key: ".sublist[1].subsublist[]", Value: false},
			{Key: ".sublist[]", Value: 2},
			{Key: ".sublist[].c", Value: 3.1},
			{Key: ".sublist[].subsublist[0]", Value: false},
			{Key: ".sublist[].subsublist[]", Value: false},
		},
	}
	actualOutput, err := Flatten(simpleInput)
	require.NoError(t, err)
	assert.NotNil(t, actualOutput)
	assert.ElementsMatch(t, expectedOutput.Items, actualOutput.Items)
}

func TestSimpleValueExtraction(t *testing.T) {
	flatInput := Flattened{
		Items: []Item{
			{Key: ".a", Value: "aa"},
			{Key: ".sublist[0]", Value: 2},
			{Key: ".sublist[1].c", Value: 3.1},
			{Key: ".sublist[1].d", Value: false},
			{Key: ".sublist[2]", Value: 2},
			{Key: ".sublist[]", Value: 2},
			{Key: ".sublist[]", Value: 4},
			{Key: ".sublist[].c", Value: 3.1},
			{Key: ".sublist[].d", Value: false},
		},
	}
	queryString := ".a"
	expectedOutput := []interface{}{"aa"}
	actualOutput := GetFromFlattened(flatInput, queryString)
	assert.NotNil(t, actualOutput)
	assert.ElementsMatch(t, expectedOutput, actualOutput)
}

func TestDotValueExtraction(t *testing.T) {
	flatInput := Flattened{
		Items: []Item{
			{Key: ".a", Value: "aa"},
			{Key: ".submap.f", Value: "ff"},
			{Key: ".sublist[0]", Value: 2},
			{Key: ".sublist[1].c", Value: 3.1},
			{Key: ".sublist[1].d", Value: false},
			{Key: ".sublist[2]", Value: 2},
			{Key: ".sublist[]", Value: 2},
			{Key: ".sublist[]", Value: 4},
			{Key: ".sublist[].c", Value: 3.1},
			{Key: ".sublist[].d", Value: false},
		},
	}
	queryString := ".submap.f"
	expectedOutput := []interface{}{"ff"}
	actualOutput := GetFromFlattened(flatInput, queryString)
	assert.NotNil(t, actualOutput)
	assert.ElementsMatch(t, expectedOutput, actualOutput)
}

func TestListIndexValueExtraction(t *testing.T) {
	flatInput := Flattened{
		Items: []Item{
			{Key: ".a", Value: "aa"},
			{Key: ".submap.f", Value: "ff"},
			{Key: ".sublist[0]", Value: 2},
			{Key: ".sublist[1].c", Value: 3.1},
			{Key: ".sublist[1].d", Value: false},
			{Key: ".sublist[2]", Value: 2},
			{Key: ".sublist[]", Value: 2},
			{Key: ".sublist[]", Value: 4},
			{Key: ".sublist[].c", Value: 3.1},
			{Key: ".sublist[].d", Value: false},
		},
	}
	queryString := ".sublist[0]"
	expectedOutput := []interface{}{2}
	actualOutput := GetFromFlattened(flatInput, queryString)
	assert.NotNil(t, actualOutput)
	assert.ElementsMatch(t, expectedOutput, actualOutput)
}

func TestListIndexDotValueExtraction(t *testing.T) {
	flatInput := Flattened{
		Items: []Item{
			{Key: ".a", Value: "aa"},
			{Key: ".submap.f", Value: "ff"},
			{Key: ".sublist[0]", Value: 2},
			{Key: ".sublist[1].c", Value: 3.1},
			{Key: ".sublist[1].d", Value: false},
			{Key: ".sublist[2]", Value: 2},
			{Key: ".sublist[]", Value: 2},
			{Key: ".sublist[]", Value: 4},
			{Key: ".sublist[].c", Value: 3.1},
			{Key: ".sublist[].d", Value: false},
		},
	}
	queryString := ".sublist[1].d"
	expectedOutput := []interface{}{false}
	actualOutput := GetFromFlattened(flatInput, queryString)
	assert.NotNil(t, actualOutput)
	assert.ElementsMatch(t, expectedOutput, actualOutput)
}

func TestListNoIndexValueExtraction(t *testing.T) {
	flatInput := Flattened{
		Items: []Item{
			{Key: ".a", Value: "aa"},
			{Key: ".submap.f", Value: "ff"},
			{Key: ".sublist[0]", Value: 2},
			{Key: ".sublist[1].c", Value: 3.1},
			{Key: ".sublist[1].d", Value: false},
			{Key: ".sublist[2]", Value: 2},
			{Key: ".sublist[]", Value: 2},
			{Key: ".sublist[]", Value: 4},
			{Key: ".sublist[].c", Value: 3.1},
			{Key: ".sublist[].d", Value: false},
		},
	}
	queryString := ".sublist[]"
	expectedOutput := []interface{}{2, 4}
	actualOutput := GetFromFlattened(flatInput, queryString)
	assert.NotNil(t, actualOutput)
	assert.ElementsMatch(t, expectedOutput, actualOutput)
}

func TestFlattenInterfaceNoPanic(t *testing.T) {
	testCases := []struct {
		name  string
		value interface{}
	}{
		{
			name:  "nil",
			value: nil,
		},
		{
			name:  "intPtr",
			value: new(int),
		},
		{
			name:  "channel",
			value: make(chan int),
		},
		{
			name:  "func",
			value: func() {},
		},
		{
			name:  "interfaceValue",
			value: interface{}(123),
		},
		{
			name:  "interfaceEmptyValue",
			value: interface{}(nil),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				idx := make(map[string][]interface{})
				_, _ = flattenInterface(tc.value, idx)
			})
		})
	}
}
