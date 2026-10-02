//go:build !windows

package streamio

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A rename cannot stand in for /dev/null, and replacing it would destroy the
// device node. `-o /dev/null` is a routine way to benchmark or smoke-test a
// decrypt, and worked before the switch to atomic output.
func TestOutputFileWritesThroughDevNull(t *testing.T) {
	o, err := NewOutputFile(os.DevNull, testOutputFileMode)
	require.NoError(t, err)

	_, err = o.Write([]byte("payload"))
	require.NoError(t, err)
	require.NoError(t, o.Commit())

	fi, err := os.Stat(os.DevNull)
	require.NoError(t, err)
	assert.NotZero(t, fi.Mode()&os.ModeDevice, "%s must still be a device node", os.DevNull)
}

// Cleanup removes the temp file it created; it must not remove a destination it
// was only writing through, which is not its to delete.
func TestOutputFileCleanupLeavesDirectDestination(t *testing.T) {
	o, err := NewOutputFile(os.DevNull, testOutputFileMode)
	require.NoError(t, err)

	_, err = o.Write([]byte("partial"))
	require.NoError(t, err)
	o.Cleanup()

	fi, err := os.Stat(os.DevNull)
	require.NoError(t, err)
	assert.NotZero(t, fi.Mode()&os.ModeDevice, "Cleanup must not remove a direct destination")
}

// os.Stat follows symlinks, so a link to a regular file looks regular and the
// rename would replace the link rather than update its target. os.Lstat is what
// makes this land on the target, as os.Create did.
func TestOutputFileWritesThroughSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	link := filepath.Join(dir, "link.txt")

	require.NoError(t, os.WriteFile(target, []byte("stale"), 0o600))
	require.NoError(t, os.Symlink(target, link))

	o, err := NewOutputFile(link, testOutputFileMode)
	require.NoError(t, err)
	_, err = o.Write([]byte("payload"))
	require.NoError(t, err)
	require.NoError(t, o.Commit())

	fi, err := os.Lstat(link)
	require.NoError(t, err)
	assert.NotZero(t, fi.Mode()&os.ModeSymlink, "the symlink must survive, not be replaced by a regular file")

	got, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "payload", string(got), "the write must land on the symlink's target")
}

// A fifo has no seekable identity to rename over either, and opening one for
// writing blocks until a reader arrives — so this only checks the routing
// decision, not a full write.
func TestDirectDestinationDetection(t *testing.T) {
	dir := t.TempDir()

	regular := filepath.Join(dir, "regular.txt")
	require.NoError(t, os.WriteFile(regular, []byte("x"), 0o600))

	for _, tc := range []struct {
		name string
		path string
		want bool
	}{
		{"missing path takes the atomic route", filepath.Join(dir, "nope.txt"), false},
		{"existing regular file takes the atomic route", regular, false},
		{"device node is written through", os.DevNull, true},
		{"directory is written through, and fails to open", dir, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := isDirectDestination(tc.path)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// A directory reaches the direct path and then fails to open, which is a better
// outcome than os.CreateTemp succeeding inside it and the rename failing later.
func TestOutputFileRejectsDirectoryDestination(t *testing.T) {
	_, err := NewOutputFile(t.TempDir(), testOutputFileMode)
	require.Error(t, err)
}
