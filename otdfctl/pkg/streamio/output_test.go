package streamio

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testOutputFileMode = 0o644

func TestOutputFileCommitRenamesIntoPlace(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.tdf")

	o, err := NewOutputFile(dest, testOutputFileMode)
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

	o, err := NewOutputFile(dest, testOutputFileMode)
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

	o, err := NewOutputFile(dest, testOutputFileMode)
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

	o, err := NewOutputFile(dest, testOutputFileMode)
	require.NoError(t, err)
	defer o.Cleanup()

	// A rename is only atomic within one filesystem — a shared temp dir on a
	// different filesystem would make Commit's os.Rename fail outright — so the
	// temp file must live beside the destination.
	assert.Equal(t, dir, filepath.Dir(o.Name()))
}

func TestOutputFileCommitSetsReadableMode(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.tdf")

	o, err := NewOutputFile(dest, testOutputFileMode)
	require.NoError(t, err)
	_, err = o.Write([]byte("payload"))
	require.NoError(t, err)
	require.NoError(t, o.Commit())

	info, err := os.Stat(dest)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(testOutputFileMode), info.Mode().Perm(),
		"os.CreateTemp defaults to 0600; Commit must not leak that onto the destination")
}

func TestOutputFileCommitSetsRequestedMode(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "plaintext.txt")

	o, err := NewOutputFile(dest, 0o600)
	require.NoError(t, err)
	_, err = o.Write([]byte("plaintext"))
	require.NoError(t, err)
	require.NoError(t, o.Commit())

	info, err := os.Stat(dest)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestOutputFileCommitReplacesExistingFileWithRequestedMode(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "plaintext.txt")
	require.NoError(t, os.WriteFile(dest, []byte("old"), 0o644))

	o, err := NewOutputFile(dest, 0o600)
	require.NoError(t, err)
	_, err = o.Write([]byte("new"))
	require.NoError(t, err)
	require.NoError(t, o.Commit())

	got, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Equal(t, "new", string(got))
	info, err := os.Stat(dest)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	assert.Empty(t, tempSiblings(t, dir, "plaintext.txt"))
}

func TestOutputFileCleanupPreservesExistingFile(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "plaintext.txt")
	require.NoError(t, os.WriteFile(dest, []byte("original"), 0o600))

	o, err := NewOutputFile(dest, 0o600)
	require.NoError(t, err)
	_, err = o.Write([]byte("partial"))
	require.NoError(t, err)
	o.Cleanup()

	got, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Equal(t, "original", string(got))
	assert.Empty(t, tempSiblings(t, dir, "plaintext.txt"))
}

func TestOutputFileCommitAfterCommitReturnsError(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.tdf")

	o, err := NewOutputFile(dest, testOutputFileMode)
	require.NoError(t, err)
	_, err = o.Write([]byte("payload"))
	require.NoError(t, err)
	require.NoError(t, o.Commit())

	require.ErrorIs(t, o.Commit(), ErrOutputFileFinished)

	got, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Equal(t, "payload", string(got), "a redundant Commit must not disturb the already-committed output")
}

func TestOutputFileCommitAfterCleanupReturnsError(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.tdf")

	o, err := NewOutputFile(dest, testOutputFileMode)
	require.NoError(t, err)
	_, err = o.Write([]byte("payload"))
	require.NoError(t, err)

	o.Cleanup()
	require.ErrorIs(t, o.Commit(), ErrOutputFileFinished)

	_, err = os.Stat(dest)
	require.ErrorIs(t, err, os.ErrNotExist, "Commit after Cleanup must not create the destination")
}

// tempSiblings returns any leftover temp files NewOutputFile would have created
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
