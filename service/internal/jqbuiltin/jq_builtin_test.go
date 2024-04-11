package jqbuiltin_test

import (
	"testing"

	"github.com/opentdf/platform/service/internal/jqbuiltin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testResult1 string = "helloworld"

var testInput1 = map[string]interface{}{
	"testing1": testResult1,
}
var testQuery1 = ".testing1"

func Test_JQSuccessSimple(t *testing.T) {
	res, err := jqbuiltin.ExecuteQuery(testInput1, testQuery1)
	require.NoError(t, err)
	assert.Equal(t, []any{testResult1}, res)
}

var testInput2 = map[string]interface{}{
	"testing1": map[string]interface{}{"testing2": testResult1},
}
var testQuery2 = ".testing1.testing2"

func Test_JQSuccessTwoDeep(t *testing.T) {
	res, err := jqbuiltin.ExecuteQuery(testInput2, testQuery2)
	require.NoError(t, err)
	assert.Equal(t, []any{testResult1}, res)
}

var testInput3 = map[string]interface{}{
	"testing1": map[string]interface{}{"testing2": []any{testResult1}},
}
var testQuery3 = ".testing1.testing2[0]"

func Test_JQSuccessTwoDeepInArray(t *testing.T) {
	res, err := jqbuiltin.ExecuteQuery(testInput3, testQuery3)
	require.NoError(t, err)
	assert.Equal(t, []any{testResult1}, res)
}

const testResult2 string = "whatsup"

var testInput4 = map[string]interface{}{
	"testing1": map[string]interface{}{"testing2": []any{testResult1, testResult2}},
}
var testQuery4 = ".testing1.testing2[]"

func Test_JQSuccessTwoDeepAllInArray(t *testing.T) {
	res, err := jqbuiltin.ExecuteQuery(testInput4, testQuery4)
	require.NoError(t, err)
	assert.Equal(t, []any{testResult1, testResult2}, res)
}

var testInput5 = map[string]interface{}{
	"testing1": map[string]interface{}{"testing2": testResult1},
}
var testQuery5 = ".testing1.testing3"

func Test_JQSuccessTwoDeepAllNoMatch(t *testing.T) {
	res, err := jqbuiltin.ExecuteQuery(testInput5, testQuery5)
	require.NoError(t, err)
	assert.Equal(t, []any{}, res)
}

var testInput6 = map[string]interface{}{
	"testing1": map[string]interface{}{"testing2": []any{testResult1, testResult2}},
}
var testQuery6 = ".testing1.testing2 | index(\"" + testResult2 + "\")"

func Test_JQSuccessUnescapeQuote(t *testing.T) {
	res, err := jqbuiltin.ExecuteQuery(testInput6, testQuery6)
	require.NoError(t, err)
	assert.Equal(t, []any{1}, res)
}
