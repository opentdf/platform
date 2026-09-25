package streamio

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPiped(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		wantOK  bool
	}{
		{name: "with data", content: "hello world", wantOK: true},
		{name: "empty pipe reports absent", content: "", wantOK: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, w, err := os.Pipe()
			require.NoError(t, err)
			defer r.Close()

			go func() {
				defer w.Close()
				_, _ = io.WriteString(w, tc.content)
			}()

			got, ok, err := Piped(r)
			require.NoError(t, err)
			require.Equal(t, tc.wantOK, ok)
			if !tc.wantOK {
				return
			}

			// Peek must not consume: the whole payload is still readable.
			all, err := io.ReadAll(got)
			require.NoError(t, err)
			assert.Equal(t, tc.content, string(all))
		})
	}
}

func TestPipedPreservesPayloadLargerThanBuffer(t *testing.T) {
	content := strings.Repeat("a", PipeBufferSize*2+7)

	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer r.Close()

	go func() {
		defer w.Close()
		_, _ = io.WriteString(w, content)
	}()

	got, ok, err := Piped(r)
	require.NoError(t, err)
	require.True(t, ok)

	all, err := io.ReadAll(got)
	require.NoError(t, err)
	assert.Len(t, all, len(content))
}

func TestPipedOnTerminalReportsAbsent(t *testing.T) {
	// A regular file is not a char device, so use os.Stdin's actual mode only
	// when it is one; otherwise this assertion is vacuous and we skip.
	stat, err := os.Stdin.Stat()
	require.NoError(t, err)
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		t.Skip("stdin is not a terminal under this test runner")
	}
	_, ok, err := Piped(os.Stdin)
	require.NoError(t, err)
	assert.False(t, ok)
}

// tempFile writes content to a file that lasts as long as the test.
func tempFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "payload.txt")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

// openRegularStdin stands in for `otdfctl encrypt < payload.txt`: a redirect
// from a regular file is not a pipe, and Piped has to notice.
func openRegularStdin(t *testing.T, content string) *os.File {
	t.Helper()

	f, err := os.Open(tempFile(t, content))
	require.NoError(t, err)
	t.Cleanup(func() { f.Close() })
	return f
}

// useStdin makes f stdin for the duration of the test.
func useStdin(t *testing.T, f *os.File) {
	t.Helper()

	orig := os.Stdin
	os.Stdin = f
	t.Cleanup(func() { os.Stdin = orig })
}

// stdinPipe makes a pipe carrying content stdin. An empty content is a producer
// that writes nothing and hangs up, the same "nothing to read" a caller gets
// from `otdfctl encrypt < /dev/null`.
func stdinPipe(t *testing.T, content string) {
	t.Helper()

	r, w, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { r.Close() })
	go func() {
		defer w.Close()
		_, _ = io.WriteString(w, content)
	}()
	useStdin(t, r)
}

// A regular-file redirect must come back as the file itself. Wrapping it would
// cost the payload its length for nothing -- it is the same fd either way.
func TestPipedRegularFileStaysSeekable(t *testing.T) {
	const content = "hello from a redirect\n"
	f := openRegularStdin(t, content)

	got, ok, err := Piped(f)
	require.NoError(t, err)
	require.True(t, ok)

	assert.Same(t, f, got, "a regular file must be handed back unwrapped")

	// Presence came from the stat, so nothing was read on the way through.
	off, err := f.Seek(0, io.SeekCurrent)
	require.NoError(t, err)
	assert.Zero(t, off, "detecting presence must not consume the payload")

	all, err := io.ReadAll(got)
	require.NoError(t, err)
	assert.Equal(t, content, string(all))
}

// An empty redirect is "no input", not "a zero-byte payload" -- the same answer
// the Peek gives for an empty pipe.
func TestPipedEmptyRegularFileReportsAbsent(t *testing.T) {
	got, ok, err := Piped(openRegularStdin(t, ""))
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Nil(t, got)
}

// Presence is measured from the current offset, not from zero:
// `{ read -r hdr; otdfctl encrypt; } < f` leaves stdin mid-file, and what
// remains is the payload.
func TestPipedRegularFileAtNonZeroOffset(t *testing.T) {
	const header, payload = "header line\n", "the actual payload\n"
	f := openRegularStdin(t, header+payload)
	_, err := f.Seek(int64(len(header)), io.SeekStart)
	require.NoError(t, err)

	got, ok, err := Piped(f)
	require.NoError(t, err)
	require.True(t, ok)

	all, err := io.ReadAll(got)
	require.NoError(t, err)
	assert.Equal(t, payload, string(all), "the payload is what remains, not the whole file")
}

// A file consumed to its end has nothing left to encrypt, so it reports absent
// even though the file itself is not empty.
func TestPipedRegularFileAtEOFReportsAbsent(t *testing.T) {
	const content = "already read\n"
	f := openRegularStdin(t, content)
	_, err := f.Seek(int64(len(content)), io.SeekStart)
	require.NoError(t, err)

	_, ok, err := Piped(f)
	require.NoError(t, err)
	assert.False(t, ok)
}

// A procfs file is a readable regular file that stats as zero bytes, so the
// stat cannot be the one to say whether a payload is there. Deciding on it alone
// turned `otdfctl encrypt < /proc/cpuinfo` into "no input".
func TestPipedZeroSizedRegularFileWithContent(t *testing.T) {
	f, err := os.Open(zeroSizedFileWithContent(t))
	require.NoError(t, err)
	defer f.Close()

	got, ok, err := Piped(f)
	require.NoError(t, err)
	require.True(t, ok, "a file that stats as empty may still have content")

	all, err := io.ReadAll(got)
	require.NoError(t, err)
	assert.NotEmpty(t, all, "the payload has to survive the presence check")
}

// zeroSizedFileWithContent names a file that stats as zero bytes and reads out
// content anyway. Only procfs and its kin do that, and nothing in a TempDir can
// be made to, so this skips everywhere else.
func zeroSizedFileWithContent(t *testing.T) string {
	t.Helper()

	if runtime.GOOS != "linux" {
		t.Skip("a readable regular file that stats as zero bytes needs procfs")
	}
	const path = "/proc/self/status"
	stat, err := os.Stat(path)
	require.NoError(t, err)
	require.True(t, stat.Mode().IsRegular(), "the premise of this test")
	require.Zero(t, stat.Size(), "the premise of this test")
	return path
}

// Nothing between here and sdk.CreateTDF would fail if a wrapper hid the Seeker;
// every file encrypt would just quietly stop declaring its length.
func TestOpenFileStaysMeasurable(t *testing.T) {
	const content = "hello, world\n"
	path := filepath.Join(t.TempDir(), "payload.txt")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	in, cleanup, err := openFile(path)
	require.NoError(t, err)
	defer cleanup()

	assert.True(t, Measurable(in), "a file argument must reach the SDK measurable")

	got, err := io.ReadAll(in)
	require.NoError(t, err)
	assert.Equal(t, content, string(got))
}

// A stat of zero is not a measurement. The SDK limits its reads to the length it
// was given, so undercounting is worse than not counting: the encrypt succeeds
// and the TDF holds nothing.
func TestOpenFileDoesNotMeasureAZeroSizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.txt")
	require.NoError(t, os.WriteFile(path, nil, 0o600))

	in, cleanup, err := openFile(path)
	require.NoError(t, err)
	defer cleanup()

	assert.False(t, Measurable(in))
}

// The case that branch exists for: procfs reports zero and then reads out
// content. Both halves matter -- io.ReadAll drains the file either way, and it is
// the SDK's io.LimitReader, sized from the measurement, that would stop at zero.
func TestOpenFileReadsAZeroSizedFileWhole(t *testing.T) {
	in, cleanup, err := openFile(zeroSizedFileWithContent(t))
	require.NoError(t, err)
	defer cleanup()

	assert.False(t, Measurable(in), "the stat undercounts, so it must not be trusted")

	got, err := io.ReadAll(in)
	require.NoError(t, err)
	assert.NotEmpty(t, got, "the payload has to reach the SDK")
}

func TestOpenFileReportsAMissingFile(t *testing.T) {
	_, cleanup, err := openFile(filepath.Join(t.TempDir(), "absent.txt"))
	require.ErrorIs(t, err, os.ErrNotExist)

	// cleanup is non-nil even here, so a caller may defer it without a nil guard.
	require.NotNil(t, cleanup)
	cleanup()
}

// Open and OpenExclusive part company only over being handed both sources at
// once, so every other case is asserted of both.
func TestResolveInput(t *testing.T) {
	for _, resolver := range []struct {
		name string
		open func(string) (io.Reader, func(), error)
	}{
		{name: "Open", open: Open},
		{name: "OpenExclusive", open: OpenExclusive},
	} {
		t.Run(resolver.name, func(t *testing.T) {
			for _, tc := range []struct {
				name, inFile, onStdin string
				wantMeasurable        bool
				wantErr               error
			}{
				// A file argument reaches the SDK measurable. A pipe must not:
				// encrypting one would then need a TMPDIR to spool it.
				{name: "file argument", inFile: "the payload\n", wantMeasurable: true},
				{name: "stdin", onStdin: "piped payload\n"},
				{name: "neither", wantErr: ErrNoInput},
			} {
				t.Run(tc.name, func(t *testing.T) {
					stdinPipe(t, tc.onStdin)
					path := ""
					if tc.inFile != "" {
						path = tempFile(t, tc.inFile)
					}

					in, cleanup, err := resolver.open(path)
					// cleanup is non-nil even on the error return, so a caller
					// may defer it without a nil guard.
					require.NotNil(t, cleanup)
					defer cleanup()

					if tc.wantErr != nil {
						require.ErrorIs(t, err, tc.wantErr)
						return
					}
					require.NoError(t, err)
					assert.Equal(t, tc.wantMeasurable, Measurable(in))

					got, err := io.ReadAll(in)
					require.NoError(t, err)
					assert.Equal(t, tc.inFile+tc.onStdin, string(got)) // exactly one is set
				})
			}
		})
	}
}

// Given both, Open takes the file argument and leaves stdin not just unused but
// unread: `while read f; do otdfctl … "$f"; done < list` loses a line for every
// byte peeked out from under the loop.
func TestOpenPrefersTheFileArgument(t *testing.T) {
	const onStdin, inFile = "the loop's list\n", "the payload\n"
	stdinPipe(t, onStdin)

	in, cleanup, err := Open(tempFile(t, inFile))
	require.NoError(t, err)
	defer cleanup()

	got, err := io.ReadAll(in)
	require.NoError(t, err)
	assert.Equal(t, inFile, string(got))

	rest, err := io.ReadAll(os.Stdin)
	require.NoError(t, err)
	assert.Equal(t, onStdin, string(rest), "stdin must survive a call that never wanted it")
}

// OpenExclusive refuses to pick, rather than silently dropping one of the two
// payloads it was handed.
func TestOpenExclusiveRejectsTwoInputs(t *testing.T) {
	stdinPipe(t, "a piped payload\n")

	_, cleanup, err := OpenExclusive(tempFile(t, "a file payload\n"))
	require.ErrorIs(t, err, ErrTwoInputs)
	require.NotNil(t, cleanup)
	cleanup()
}

func TestSpoolIsSeekableAndComplete(t *testing.T) {
	// Larger than any plausible internal buffer, so a truncating copy shows up.
	content := strings.Repeat("xyz", PipeBufferSize)

	f, cleanup, err := Spool(strings.NewReader(content))
	require.NoError(t, err)
	defer cleanup()

	// The spool must be positioned at the head, not at the end of the copy.
	pos, err := f.Seek(0, io.SeekCurrent)
	require.NoError(t, err)
	assert.Equal(t, int64(0), pos, "spool must be rewound for the caller")

	got, err := io.ReadAll(f)
	require.NoError(t, err)
	assert.Len(t, got, len(content))

	// Seeking backwards is the whole reason for spooling: a TDF's manifest is at
	// the end of the archive, so the reader has to be able to go back.
	_, err = f.Seek(0, io.SeekStart)
	require.NoError(t, err)
	head := make([]byte, 3)
	_, err = io.ReadFull(f, head)
	require.NoError(t, err)
	assert.Equal(t, "xyz", string(head))
}

func TestSpoolCleanupRemovesTheFile(t *testing.T) {
	f, cleanup, err := Spool(strings.NewReader("payload"))
	require.NoError(t, err)

	name := f.Name()
	require.FileExists(t, name)

	cleanup()
	assert.NoFileExists(t, name, "the spool must not outlive the command")
}

func TestOpenSeekableReadsNamedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "in.tdf")
	require.NoError(t, os.WriteFile(path, []byte("payload"), 0o600))

	in, cleanup, err := OpenSeekable(path)
	require.NoError(t, err)
	defer cleanup()

	got, err := io.ReadAll(in)
	require.NoError(t, err)
	assert.Equal(t, "payload", string(got))

	assert.Equal(t, path, in.Name(), "a named file must not be copied through a spool")
}

func TestOpenSeekableReportsMissingFile(t *testing.T) {
	_, _, err := OpenSeekable(filepath.Join(t.TempDir(), "absent.tdf"))
	require.Error(t, err)
	// Distinguishable from "you gave me nothing", which callers report differently.
	require.NotErrorIs(t, err, ErrNoInput)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestOpenSeekableSpoolsNonSeekableNamedFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("FIFOs are not portable to windows")
	}

	path := filepath.Join(t.TempDir(), "in.fifo")
	require.NoError(t, syscall.Mkfifo(path, 0o600))

	content := "a named pipe cannot seek, so this has to be spooled"
	go func() {
		w, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return
		}
		defer w.Close()
		_, _ = io.WriteString(w, content)
	}()

	in, cleanup, err := OpenSeekable(path)
	require.NoError(t, err)
	defer cleanup()

	got, err := io.ReadAll(in)
	require.NoError(t, err)
	assert.Equal(t, content, string(got))

	assert.NotEqual(t, path, in.Name(), "the FIFO's bytes went into a temp file")
	_, err = in.Seek(0, io.SeekStart)
	require.NoError(t, err, "the whole point of spooling is that the result seeks")
}

func TestOpenSeekableReadsFromStdinPipe(t *testing.T) {
	const content = "piped stdin, spooled to disk"
	stdinPipe(t, content)

	in, cleanup, err := OpenSeekable("")
	require.NoError(t, err)
	defer cleanup()

	got, err := io.ReadAll(in)
	require.NoError(t, err)
	assert.Equal(t, content, string(got))

	assert.NotSame(t, os.Stdin, in, "a real stream has to be spooled to seek")
}

// A redirect from a regular file seeks already. Spooling it would copy the whole
// TDF into TMPDIR to produce a handle no better than the one we had.
func TestOpenSeekableDoesNotSpoolARegularFileStdin(t *testing.T) {
	const content = "redirected stdin, read in place\n"

	useStdin(t, openRegularStdin(t, content))

	in, cleanup, err := OpenSeekable("")
	require.NoError(t, err)
	defer cleanup()

	assert.Same(t, os.Stdin, in, "a regular-file redirect must not be spooled")

	got, err := io.ReadAll(in)
	require.NoError(t, err)
	assert.Equal(t, content, string(got))

	// Closing stdin is not ours to do, so cleanup has to leave it usable.
	cleanup()
	_, err = in.Seek(0, io.SeekStart)
	require.NoError(t, err, "cleanup must not close stdin")
}

func TestOpenSeekableReturnsErrNoInputForEmptyStdinPipe(t *testing.T) {
	stdinPipe(t, "")

	_, _, err := OpenSeekable("")
	require.ErrorIs(t, err, ErrNoInput)
}
