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

	_, err = os.Stat(dest)
	require.ErrorIs(t, err, os.ErrNotExist)
	require.NoError(t, o.Commit())

	got, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Equal(t, "payload", string(got))
	assert.Empty(t, tempSiblings(t, dir, "out.tdf"))
}

func TestOutputFileCleanupLeavesNoPartialOutput(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.tdf")

	o, err := newOutputFile(dest)
	require.NoError(t, err)
	_, err = o.Write([]byte("partial"))
	require.NoError(t, err)
	o.Cleanup()

	_, err = os.Stat(dest)
	require.ErrorIs(t, err, os.ErrNotExist)
	assert.Empty(t, tempSiblings(t, dir, "out.tdf"))
}

func TestOutputFileCleanupAfterCommitIsNoop(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.tdf")

	o, err := newOutputFile(dest)
	require.NoError(t, err)
	_, err = o.Write([]byte("payload"))
	require.NoError(t, err)
	require.NoError(t, o.Commit())
	o.Cleanup()
	o.Cleanup()

	got, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Equal(t, "payload", string(got))
}

func TestOutputFileTempIsSiblingOfDestination(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.tdf")

	o, err := newOutputFile(dest)
	require.NoError(t, err)
	defer o.Cleanup()
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
			if ok {
				all, err := io.ReadAll(got)
				require.NoError(t, err)
				assert.Equal(t, tc.content, string(all))
			}
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
	assert.Equal(t, content, string(all))
}

func tempSiblings(t *testing.T, dir, dest string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	var found []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "."+dest+".tmp-") {
			found = append(found, entry.Name())
		}
	}
	return found
}
