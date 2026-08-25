package tdf

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOutputFileCommitRenamesIntoPlace(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.tdf")

	o, err := newOutputFile(dest)
	require.NoError(t, err)

	_, err = o.Write([]byte("payload"))
	require.NoError(t, err)

	// Nothing is visible at the destination until Commit.
	_, err = os.Stat(dest)
	require.ErrorIs(t, err, os.ErrNotExist, "destination must not exist before Commit")

	require.NoError(t, o.Commit())

	got, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Equal(t, "payload", string(got))
	assert.Empty(t, tempSiblings(t, dir, "out.tdf"), "temp file should be gone after Commit")
}

func TestOutputFileCleanupLeavesNoPartialOutput(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.tdf")

	o, err := newOutputFile(dest)
	require.NoError(t, err)
	_, err = o.Write([]byte("partial"))
	require.NoError(t, err)

	// Simulates the failure path: encryption died after some bytes were written.
	o.Cleanup()

	_, err = os.Stat(dest)
	require.ErrorIs(t, err, os.ErrNotExist, "a failed run must not leave a partial file")
	assert.Empty(t, tempSiblings(t, dir, "out.tdf"), "a failed run must not leave a temp file")
}

func TestOutputFileCleanupAfterCommitIsNoop(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.tdf")

	o, err := newOutputFile(dest)
	require.NoError(t, err)
	_, err = o.Write([]byte("payload"))
	require.NoError(t, err)
	require.NoError(t, o.Commit())

	// Both deferred and explicit cleanup run on the success path.
	o.Cleanup()
	o.Cleanup()

	got, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Equal(t, "payload", string(got), "Cleanup after Commit must not delete the output")
}

func TestOutputFileTempIsSiblingOfDestination(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.tdf")

	o, err := newOutputFile(dest)
	require.NoError(t, err)
	defer o.Cleanup()

	// A cross-filesystem temp dir would turn the rename into a copy and lose
	// atomicity, so the temp file must live beside the destination.
	assert.Equal(t, dir, filepath.Dir(o.f.Name()))
}

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

			got, ok, err := pipeReader(r)
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
	content := strings.Repeat("a", Size1MB*2+7)

	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer r.Close()

	go func() {
		defer w.Close()
		_, _ = io.WriteString(w, content)
	}()

	got, ok, err := pipeReader(r)
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
	_, ok, err := pipeReader(os.Stdin)
	require.NoError(t, err)
	assert.False(t, ok)
}

// tempSiblings returns any leftover temp files newOutputFile would have created
// for dest in dir.
func tempSiblings(t *testing.T, dir, dest string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	var found []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "."+dest+".tmp-") {
			found = append(found, e.Name())
		}
	}
	return found
}
