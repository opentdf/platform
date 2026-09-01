package streamio

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPipeReader(t *testing.T) {
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

			got, ok, err := PipeReader(r)
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

func TestPipeReaderPreservesPayloadLargerThanBuffer(t *testing.T) {
	content := strings.Repeat("a", PipeBufferSize*2+7)

	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer r.Close()

	go func() {
		defer w.Close()
		_, _ = io.WriteString(w, content)
	}()

	got, ok, err := PipeReader(r)
	require.NoError(t, err)
	require.True(t, ok)

	all, err := io.ReadAll(got)
	require.NoError(t, err)
	assert.Len(t, all, len(content))
}

func TestPipeReaderOnTerminalReportsAbsent(t *testing.T) {
	// A regular file is not a char device, so use os.Stdin's actual mode only
	// when it is one; otherwise this assertion is vacuous and we skip.
	stat, err := os.Stdin.Stat()
	require.NoError(t, err)
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		t.Skip("stdin is not a terminal under this test runner")
	}
	_, ok, err := PipeReader(os.Stdin)
	require.NoError(t, err)
	assert.False(t, ok)
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

	// A named file is opened directly, not copied through a spool.
	assert.Equal(t, path, in.Name())
}

func TestOpenSeekableReportsMissingFile(t *testing.T) {
	_, _, err := OpenSeekable(filepath.Join(t.TempDir(), "absent.tdf"))
	require.Error(t, err)
	// Distinguishable from "you gave me nothing", which callers report differently.
	require.NotErrorIs(t, err, ErrNoInput)
	require.ErrorIs(t, err, os.ErrNotExist)
}
