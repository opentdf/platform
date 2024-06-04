package subjectmappingbuiltin_test

import (
	"testing"

	"github.com/opentdf/platform/service/internal/subjectmappingbuiltin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

/// JQ evaluation tests

const jqtestResult1 string = "helloworld"

var jqtestInput1 = map[string]interface{}{
	"testing1": jqtestResult1,
}
var jqtestQuery1 = ".testing1"

func Test_JQSuccessSimple(t *testing.T) {
	res, err := subjectmappingbuiltin.ExecuteQuery(jqtestInput1, jqtestQuery1)
	require.NoError(t, err)
	assert.Equal(t, []any{jqtestResult1}, res)
}

var jqtestInput2 = map[string]interface{}{
	"testing1": map[string]interface{}{"testing2": jqtestResult1},
}
var jqtestQuery2 = ".testing1.testing2"

func Test_JQSuccessTwoDeep(t *testing.T) {
	res, err := subjectmappingbuiltin.ExecuteQuery(jqtestInput2, jqtestQuery2)
	require.NoError(t, err)
	assert.Equal(t, []any{jqtestResult1}, res)
}

var jqtestInput3 = map[string]interface{}{
	"testing1": map[string]interface{}{"testing2": []any{jqtestResult1}},
}
var jqtestQuery3 = ".testing1.testing2[0]"

func Test_JQSuccessTwoDeepInArray(t *testing.T) {
	res, err := subjectmappingbuiltin.ExecuteQuery(jqtestInput3, jqtestQuery3)
	require.NoError(t, err)
	assert.Equal(t, []any{jqtestResult1}, res)
}

const jqtestResult2 string = "whatsup"

var jqtestInput4 = map[string]interface{}{
	"testing1": map[string]interface{}{"testing2": []any{jqtestResult1, jqtestResult2}},
}
var jqtestQuery4 = ".testing1.testing2[]"

func Test_JQSuccessTwoDeepAllInArray(t *testing.T) {
	res, err := subjectmappingbuiltin.ExecuteQuery(jqtestInput4, jqtestQuery4)
	require.NoError(t, err)
	assert.Equal(t, []any{jqtestResult1, jqtestResult2}, res)
}

var jqtestInput5 = map[string]interface{}{
	"testing1": map[string]interface{}{"testing2": jqtestResult1},
}
var jqtestQuery5 = ".testing1.testing3"

func Test_JQSuccessTwoDeepAllNoMatch(t *testing.T) {
	res, err := subjectmappingbuiltin.ExecuteQuery(jqtestInput5, jqtestQuery5)
	require.NoError(t, err)
	assert.Equal(t, []any{}, res)
}

var jqtestInput6 = map[string]interface{}{
	"testing1": map[string]interface{}{"testing2": []any{jqtestResult1, jqtestResult2}},
}
var jqtestQuery6 = ".testing1.testing2 | index(\"" + jqtestResult2 + "\")"

func Test_JQSuccessUnescapeQuote(t *testing.T) {
	res, err := subjectmappingbuiltin.ExecuteQuery(jqtestInput6, jqtestQuery6)
	require.NoError(t, err)
	assert.Equal(t, []any{1}, res)
}
