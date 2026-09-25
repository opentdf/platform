package tdf

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/opentdf/platform/otdfctl/pkg/streamio"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pipeReader hides the Seek method of the reader it wraps, standing in for
// stdin on the end of a pipe.
type pipeReader struct{ inner io.Reader }

func (r pipeReader) Read(p []byte) (int, error) { return r.inner.Read(p) }

// espipeReader implements io.Seeker and refuses every seek, the way an *os.File
// on a FIFO, a process substitution, or /dev/stdin on the end of a pipe does.
// Neither of the other two shapes covers that: strings.Reader always seeks,
// pipeReader hides Seek entirely.
type espipeReader struct{ inner io.Reader }

func (r espipeReader) Read(p []byte) (int, error) { return r.inner.Read(p) }

func (r espipeReader) Seek(int64, int) (int64, error) {
	return 0, &os.PathError{Op: "seek", Path: "/dev/fd/63", Err: syscall.ESPIPE}
}

// readerKinds are the three input shapes detectMimeType has to cope with. Only
// the first can be rewound, so only the first may come back measurable.
var readerKinds = []struct {
	name       string
	wrap       func(io.Reader) io.Reader
	rewindable bool
}{
	{name: "seekable", wrap: func(r io.Reader) io.Reader { return r }, rewindable: true},
	{name: "pipe", wrap: func(r io.Reader) io.Reader { return pipeReader{r} }},
	{name: "refuses to seek", wrap: func(r io.Reader) io.Reader { return espipeReader{r} }},
}

func TestDetectMimeTypePreservesThePayload(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		want    string
	}{
		{name: "text", content: "hello, world\n", want: "text/plain; charset=utf-8"},
		{name: "json", content: `{"a":1}`, want: "application/json"},
		// Exactly the sniff window: the shortest input that fills the buffer, so
		// the shortest for which io.ReadFull returns a nil error rather than
		// io.ErrUnexpectedEOF, and the boundary at which replaying the prefix
		// could duplicate or drop a byte.
		{name: "exactly the sniff window", content: strings.Repeat("a", Size1MB), want: "text/plain; charset=utf-8"},
		// Larger than the sniff window, so a detector that consumed the reader
		// without handing the prefix back would truncate the payload.
		{name: "larger than sniff window", content: strings.Repeat("a", Size1MB+7), want: "text/plain; charset=utf-8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, kind := range readerKinds {
				t.Run(kind.name, func(t *testing.T) {
					in := kind.wrap(strings.NewReader(tc.content))

					got, rest, err := detectMimeType(in, "")
					require.NoError(t, err)
					assert.Equal(t, tc.want, got)

					// A stream that came back looking seekable would claim a
					// length the SDK then could not read.
					assert.Equal(t, kind.rewindable, streamio.Measurable(rest),
						"measurability must match rewindability")

					all, err := io.ReadAll(rest)
					require.NoError(t, err)
					assertSamePayload(t, tc.content, string(all))
				})
			}
		})
	}
}

// assertSamePayload compares payloads without rendering a megabyte-wide diff for
// the cases deliberately larger than the sniff window.
func assertSamePayload(t *testing.T, want, got string) {
	t.Helper()

	const diffLimit = 4096
	if len(want) <= diffLimit && len(got) <= diffLimit {
		assert.Equal(t, want, got)
		return
	}
	// Length first, since truncation is what these cases exist to catch, then
	// content by digest -- assert.Equal on a megabyte renders a useless diff.
	assert.Len(t, got, len(want), "payload length")
	assert.Equal(t, sha256.Sum256([]byte(want)), sha256.Sum256([]byte(got)), "payload digest")
}

// A sniffed input that came back wrapped in io.MultiReader would silently cost
// every file encrypt its declared length, and nothing else would fail.
func TestDetectMimeTypeKeepsSeekability(t *testing.T) {
	in := strings.NewReader("hello, world\n")

	_, rest, err := detectMimeType(in, "")
	require.NoError(t, err)

	// Same, not merely "is an io.Seeker": the documented contract is that a
	// rewindable input is handed back unchanged.
	assert.Same(t, in, rest, "a rewindable input must be handed back unchanged")
}

// A reader handed over mid-payload must be rewound to where it was, not to zero:
// `{ read -r header; otdfctl encrypt; } < payload.txt` leaves stdin part-consumed,
// and seeking to the start would encrypt the header the wrapper already took.
func TestDetectMimeTypeRestoresANonZeroOffset(t *testing.T) {
	const header, payload = "header line\n", "the actual payload\n"

	in := strings.NewReader(header + payload)
	_, err := in.Seek(int64(len(header)), io.SeekStart)
	require.NoError(t, err)

	_, rest, err := detectMimeType(in, "")
	require.NoError(t, err)

	got, err := io.ReadAll(rest)
	require.NoError(t, err)
	assert.Equal(t, payload, string(got), "the payload is what remains, not the whole file")
}

// errAfterNReader yields n bytes and then fails with something that is neither
// EOF nor ErrUnexpectedEOF: a failing device, or a socket reset mid-read. Not a
// dying shell producer -- `failing-cmd | otdfctl encrypt` closes the write end,
// which reads as a clean EOF that nothing here can tell from a whole payload.
type errAfterNReader struct {
	remaining int
	err       error
}

func (r *errAfterNReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, r.err
	}
	n := min(len(p), r.remaining)
	for i := range n {
		p[i] = 'a'
	}
	r.remaining -= n
	return n, nil
}

// Detection is the first thing that touches the payload, so swallowing a read
// error here would encrypt a truncated payload into a TDF that looks complete.
func TestDetectMimeTypeReportsAReadFailure(t *testing.T) {
	want := errors.New("the device gave up")

	_, rest, err := detectMimeType(&errAfterNReader{remaining: 16, err: want}, "")
	require.ErrorIs(t, err, want)

	// The nil is contractual: encryptRun assigns the returned reader through a
	// temporary so a failed detection cannot install it as the payload.
	assert.Nil(t, rest, "a failed detection must not hand back a reader")
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
