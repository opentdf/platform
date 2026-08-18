package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"iter"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seqOf returns an error-free iter.Seq2 over the given items, mirroring how a
// paged iterator with no fetch failures would feed StreamList.
func seqOf(items ...any) iter.Seq2[any, error] {
	return func(yield func(any, error) bool) {
		for _, it := range items {
			if !yield(it, nil) {
				return
			}
		}
	}
}

// seqErr yields the given items and then a terminal error, mirroring a paged
// iterator whose later page fetch fails.
func seqErr(err error, items ...any) iter.Seq2[any, error] {
	return func(yield func(any, error) bool) {
		for _, it := range items {
			if !yield(it, nil) {
				return
			}
		}
		yield(nil, err)
	}
}

// failingWriter fails its Write after okWrites successful calls, exercising the
// io.Writer error branches of the streamers.
type failingWriter struct {
	okWrites int
	n        int
}

func (f *failingWriter) Write(p []byte) (int, error) {
	if f.n >= f.okWrites {
		return 0, errors.New("write failed")
	}
	f.n++
	return len(p), nil
}

func TestStreamListJSON(t *testing.T) {
	c := New(&cobra.Command{Use: "test"}, nil, WithPrintJSON())

	var buf bytes.Buffer
	items := seqOf(
		map[string]string{"id": "1", "name": "alpha"},
		map[string]string{"id": "2", "name": "beta"},
	)
	require.NoError(t, c.StreamList(&buf, []string{"ID", "Name"}, nil, items))

	// Exact-output assertion: each object's opening brace is indented two spaces
	// by the separator (SetIndent does not prefix the opening "{"), matching
	// printJSON. Pins the layout against separator regressions.
	const wantJSON = `[
  {
    "id": "1",
    "name": "alpha"
  },
  {
    "id": "2",
    "name": "beta"
  }
]
`
	// Exact byte comparison on purpose: JSONEq ignores whitespace, but this test
	// exists to pin the indentation/formatting, not JSON equality.
	//nolint:testifylint // encoded-compare: exact formatting is the assertion
	assert.Equal(t, wantJSON, buf.String())

	var decoded []map[string]string
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))
	require.Len(t, decoded, 2)
	assert.Equal(t, "1", decoded[0]["id"])
	assert.Equal(t, "beta", decoded[1]["name"])
}

func TestStreamListJSONEmpty(t *testing.T) {
	c := New(&cobra.Command{Use: "test"}, nil, WithPrintJSON())

	var buf bytes.Buffer
	require.NoError(t, c.StreamList(&buf, nil, nil, seqOf()))

	var decoded []any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))
	assert.Empty(t, decoded)
}

func TestStreamListJSONNoHTMLEscape(t *testing.T) {
	c := New(&cobra.Command{Use: "test"}, nil, WithPrintJSON())

	var buf bytes.Buffer
	items := seqOf(map[string]string{"attr": "a&b<c>"})
	require.NoError(t, c.StreamList(&buf, nil, nil, items))

	assert.Contains(t, buf.String(), "a&b<c>")
}

// TestStreamListJSONIteratorError verifies a page-fetch failure surfaces rather
// than looking like normal exhaustion (the P2 review concern).
func TestStreamListJSONIteratorError(t *testing.T) {
	c := New(&cobra.Command{Use: "test"}, nil, WithPrintJSON())

	sentinel := errors.New("page fetch failed")
	var buf bytes.Buffer
	err := c.StreamList(&buf, nil, nil, seqErr(sentinel, map[string]string{"id": "1"}))
	require.ErrorIs(t, err, sentinel)
}

func TestStreamListJSONMarshalError(t *testing.T) {
	c := New(&cobra.Command{Use: "test"}, nil, WithPrintJSON())

	var buf bytes.Buffer
	// A channel cannot be marshaled to JSON.
	err := c.StreamList(&buf, nil, nil, seqOf(make(chan int)))
	require.Error(t, err)
}

func TestStreamListJSONWriteErrors(t *testing.T) {
	one := map[string]string{"id": "1"}
	for name, tc := range map[string]struct {
		okWrites int
		items    iter.Seq2[any, error]
	}{
		"open bracket": {okWrites: 0, items: seqOf(one)},
		"separator":    {okWrites: 1, items: seqOf(one)},
		"item bytes":   {okWrites: 2, items: seqOf(one)},
		"tail":         {okWrites: 1, items: seqOf()},
	} {
		t.Run(name, func(t *testing.T) {
			c := New(&cobra.Command{Use: "test"}, nil, WithPrintJSON())
			w := &failingWriter{okWrites: tc.okWrites}
			assert.Error(t, c.StreamList(w, nil, nil, tc.items))
		})
	}
}

func TestStreamListTable(t *testing.T) {
	c := New(&cobra.Command{Use: "test"}, nil) // styled mode: no --json

	var buf bytes.Buffer
	items := seqOf(
		[]string{"1", "alpha"},
		[]string{"2", "beta"},
	)
	row := func(v any) []string { s, _ := v.([]string); return s }
	require.NoError(t, c.StreamList(&buf, []string{"ID", "Name"}, row, items))

	out := buf.String()
	assert.Contains(t, out, "ID")
	assert.Contains(t, out, "Name")
	assert.Contains(t, out, "alpha")
	assert.Contains(t, out, "beta")
	// header is written before the rows
	assert.Less(t, strings.Index(out, "ID"), strings.Index(out, "alpha"))
	// styled mode renders a bordered table rather than plain text
	assert.Contains(t, out, "╭")
}

func TestStreamListTableNoHeaders(t *testing.T) {
	c := New(&cobra.Command{Use: "test"}, nil)

	var buf bytes.Buffer
	items := seqOf([]string{"only"})
	row := func(v any) []string { s, _ := v.([]string); return s }
	require.NoError(t, c.StreamList(&buf, nil, row, items))

	assert.Contains(t, buf.String(), "only")
}

func TestStreamListTableIteratorError(t *testing.T) {
	c := New(&cobra.Command{Use: "test"}, nil)

	sentinel := errors.New("page fetch failed")
	row := func(v any) []string { s, _ := v.([]string); return s }
	err := c.StreamList(&bytes.Buffer{}, []string{"ID"}, row, seqErr(sentinel, []string{"1"}))
	require.ErrorIs(t, err, sentinel)
}

func TestStreamListTableWriteError(t *testing.T) {
	c := New(&cobra.Command{Use: "test"}, nil)

	row := func(v any) []string { s, _ := v.([]string); return s }
	w := &failingWriter{okWrites: 0}
	assert.Error(t, c.StreamList(w, []string{"ID"}, row, seqOf([]string{"1"})))
}
