package tdf

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectMimeTypePreservesThePayload(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		want    string
	}{
		{name: "text", content: "hello, world\n", want: "text/plain; charset=utf-8"},
		{name: "json", content: `{"a":1}`, want: "application/json"},
		// Larger than the sniff window, so a detector that consumed the reader
		// without handing the prefix back would truncate the payload.
		{name: "larger than sniff window", content: strings.Repeat("a", Size1MB+7), want: "text/plain; charset=utf-8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, seekable := range []bool{true, false} {
				name := "seekable"
				if !seekable {
					name = "pipe"
				}
				t.Run(name, func(t *testing.T) {
					var in io.Reader = strings.NewReader(tc.content)
					if !seekable {
						in = pipeReader{in}
					}

					got, rest, err := detectMimeType(in, "")
					require.NoError(t, err)
					assert.Equal(t, tc.want, got)

					// The whole payload must still reach the encoder.
					all, err := io.ReadAll(rest)
					require.NoError(t, err)
					assert.Equal(t, tc.content, string(all))
				})
			}
		})
	}
}

// pipeReader hides the Seek method of the reader it wraps, standing in for
// stdin on the end of a pipe.
type pipeReader struct{ inner io.Reader }

func (r pipeReader) Read(p []byte) (int, error) { return r.inner.Read(p) }

// TestDetectMimeTypeKeepsSeekability guards the ZIP32 layout: the SDK only
// measures a payload it can seek, and a sniffed input that came back wrapped in
// io.MultiReader would silently force every file encrypt to ZIP64.
func TestDetectMimeTypeKeepsSeekability(t *testing.T) {
	in := strings.NewReader("hello, world\n")

	_, rest, err := detectMimeType(in, "")
	require.NoError(t, err)

	_, ok := rest.(io.Seeker)
	assert.True(t, ok, "a seekable input must stay seekable")
}

func TestDetectMimeTypeFallsBackToExtension(t *testing.T) {
	// Bytes mimetype cannot classify, so the extension decides. ".pdf" is in
	// Go's builtin table, so this does not depend on the host's mime.types.
	unrecognized := bytes.Repeat([]byte{0x01, 0x02, 0x03, 0x04}, 8)

	got, _, err := detectMimeType(bytes.NewReader(unrecognized), "pdf")
	require.NoError(t, err)
	assert.Equal(t, "application/pdf", got)
}

func TestDetectMimeTypeUnknownExtensionStaysOctetStream(t *testing.T) {
	unrecognized := bytes.Repeat([]byte{0x01, 0x02, 0x03, 0x04}, 8)

	// The previous implementation called mimetype.Lookup(fileExt).String().
	// Lookup takes a MIME type string, not an extension, so it returned nil for
	// every extension and this path panicked.
	got, _, err := detectMimeType(bytes.NewReader(unrecognized), "zzzznotathing")
	require.NoError(t, err)
	assert.Equal(t, "application/octet-stream", got)
}

func TestDetectMimeTypeEmptyPayload(t *testing.T) {
	in := strings.NewReader("")

	got, _, err := detectMimeType(in, "")
	require.NoError(t, err)
	assert.Equal(t, "text/plain", got)
}
