//go:build unix

package streamio

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// outputFileMode is a request, not an override: a user who has set a
// restrictive umask has asked for files no one else can read, and writing the
// output through a temp file must not quietly hand them a 0644 one.
//
// The umask is process-wide, so this must not run alongside other tests that
// create files — no t.Parallel() here or in the rest of the package.
func TestOutputFileCommitHonorsUmask(t *testing.T) {
	for _, tc := range []struct {
		name     string
		umask    int
		expected os.FileMode
	}{
		{name: "permissive umask leaves the requested mode intact", umask: 0o022, expected: 0o644},
		{name: "restrictive umask tightens output", umask: 0o077, expected: 0o600},
		{name: "group-only umask", umask: 0o027, expected: 0o640},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer syscall.Umask(syscall.Umask(tc.umask))

			dir := t.TempDir()
			dest := filepath.Join(dir, "out.tdf")

			o, err := NewOutputFile(dest, testOutputFileMode)
			require.NoError(t, err)
			_, err = o.Write([]byte("payload"))
			require.NoError(t, err)

			// The temp file is the file that gets renamed into place, so it has
			// to be masked too — a Chmod at commit time would not be.
			tempInfo, err := os.Stat(o.Name())
			require.NoError(t, err)
			assert.Equal(t, tc.expected, tempInfo.Mode().Perm(), "temp file mode")

			require.NoError(t, o.Commit())

			info, err := os.Stat(dest)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, info.Mode().Perm(), "committed destination mode")
		})
	}
}
