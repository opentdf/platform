package tdf

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectMimeTypeRewindsForTheEncoder(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		want    string
	}{
		{name: "text", content: "hello, world\n", want: "text/plain; charset=utf-8"},
		{name: "json", content: `{"a":1}`, want: "application/json"},
		// Larger than the sniff window, so a detector that consumed the reader
		// instead of rewinding would truncate the payload.
		{name: "larger than sniff window", content: strings.Repeat("a", Size1MB+7), want: "text/plain; charset=utf-8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := strings.NewReader(tc.content)

			got, err := detectMimeType(in, "")
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)

			// The whole payload must still reach the encoder.
			all, err := io.ReadAll(in)
			require.NoError(t, err)
			assert.Len(t, all, len(tc.content))
		})
	}
}

func TestDetectMimeTypeFallsBackToExtension(t *testing.T) {
	// Bytes mimetype cannot classify, so the extension decides. ".pdf" is in
	// Go's builtin table, so this does not depend on the host's mime.types.
	unrecognized := bytes.Repeat([]byte{0x01, 0x02, 0x03, 0x04}, 8)

	got, err := detectMimeType(bytes.NewReader(unrecognized), "pdf")
	require.NoError(t, err)
	assert.Equal(t, "application/pdf", got)
}

func TestDetectMimeTypeUnknownExtensionStaysOctetStream(t *testing.T) {
	unrecognized := bytes.Repeat([]byte{0x01, 0x02, 0x03, 0x04}, 8)

	// The previous implementation called mimetype.Lookup(fileExt).String().
	// Lookup takes a MIME type string, not an extension, so it returned nil for
	// every extension and this path panicked.
	got, err := detectMimeType(bytes.NewReader(unrecognized), "zzzznotathing")
	require.NoError(t, err)
	assert.Equal(t, "application/octet-stream", got)
}

func TestDetectMimeTypeEmptyPayload(t *testing.T) {
	in := strings.NewReader("")

	got, err := detectMimeType(in, "")
	require.NoError(t, err)
	assert.Equal(t, "text/plain", got)
}
