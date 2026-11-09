package sdk

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStrictScannerCapturesValues checks the value the scanner returns: the
// byte span of every value and, within the capture depth, object members,
// array elements, and decoded strings.
func TestStrictScannerCapturesValues(t *testing.T) {
	data := []byte(`{"a":"xA","b":[1,{"c":true}]}`)
	node, err := parseStrictJSON(data, levelOther, 2)
	require.NoError(t, err)
	require.Equal(t, jsonObject, node.kind)
	assert.Equal(t, len(data), node.end)
	require.Len(t, node.members, 2)

	a := node.members[0]
	assert.Equal(t, "a", a.name)
	assert.Equal(t, `"a":"xA"`, string(data[a.start:a.value.end]), "a member's span is the member as received")
	assert.Equal(t, "xA", a.value.str)

	b, ok := node.member("b")
	require.True(t, ok)
	require.Len(t, b.elems, 2)
	assert.Equal(t, jsonNumber, b.elems[0].kind)
	assert.Empty(t, b.elems[1].members, "values beyond the capture depth keep only their span")
	assert.Equal(t, `{"c":true}`, string(data[b.elems[1].start:b.elems[1].end]))

	_, ok = node.member("A")
	assert.False(t, ok, "member names match exactly")
}
