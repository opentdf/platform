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

const testOutputFileMode = 0o644

func TestOutputFileCommitRenamesIntoPlace(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.tdf")

	o, err := NewOutputFile(dest, testOutputFileMode, nil)
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
	assert.Empty(t, tempSiblings(t, dir), "temp file should be gone after Commit")
}

func TestOutputFileCleanupLeavesNoPartialOutput(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.tdf")

	o, err := NewOutputFile(dest, testOutputFileMode, nil)
	require.NoError(t, err)
	_, err = o.Write([]byte("partial"))
	require.NoError(t, err)

	// Simulates the failure path: encryption died after some bytes were written.
	o.Cleanup()

	_, err = os.Stat(dest)
	require.ErrorIs(t, err, os.ErrNotExist, "a failed run must not leave a partial file")
	assert.Empty(t, tempSiblings(t, dir), "a failed run must not leave a temp file")
}

func TestOutputFileCleanupAfterCommitIsNoop(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.tdf")

	o, err := NewOutputFile(dest, testOutputFileMode, nil)
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

	o, err := NewOutputFile(dest, testOutputFileMode, nil)
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

	o, err := NewOutputFile(dest, testOutputFileMode, nil)
	require.NoError(t, err)
	_, err = o.Write([]byte("payload"))
	require.NoError(t, err)
	require.NoError(t, o.Commit())

	info, err := os.Stat(dest)
	require.NoError(t, err)
	assert.Equal(t, plainCreateMode(t, dir, testOutputFileMode), info.Mode().Perm(),
		"the temp file is an implementation detail; its mode must not leak onto the destination")
}

func TestOutputFileTempNamesDoNotCollide(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.tdf")

	const concurrent = 16
	names := make(map[string]bool, concurrent)
	for range concurrent {
		o, err := NewOutputFile(dest, testOutputFileMode, nil)
		require.NoError(t, err)
		defer o.Cleanup()

		require.False(t, names[o.Name()], "temp names must be unique: %s reused", o.Name())
		names[o.Name()] = true
	}
}

func TestOutputFileCommitSetsRequestedMode(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "plaintext.txt")

	o, err := NewOutputFile(dest, 0o600, nil)
	require.NoError(t, err)
	_, err = o.Write([]byte("plaintext"))
	require.NoError(t, err)
	require.NoError(t, o.Commit())

	info, err := os.Stat(dest)
	require.NoError(t, err)
	assert.Equal(t, plainCreateMode(t, dir, 0o600), info.Mode().Perm())
}

func TestOutputFileCommitReplacesExistingFileWithRequestedMode(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "plaintext.txt")
	require.NoError(t, os.WriteFile(dest, []byte("old"), 0o644))

	o, err := NewOutputFile(dest, 0o600, nil)
	require.NoError(t, err)
	_, err = o.Write([]byte("new"))
	require.NoError(t, err)
	require.NoError(t, o.Commit())

	got, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Equal(t, "new", string(got))
	info, err := os.Stat(dest)
	require.NoError(t, err)
	assert.Equal(t, plainCreateMode(t, dir, 0o600), info.Mode().Perm())
	assert.Empty(t, tempSiblings(t, dir))
}

func TestOutputFileCleanupPreservesExistingFile(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "plaintext.txt")
	require.NoError(t, os.WriteFile(dest, []byte("original"), 0o600))

	o, err := NewOutputFile(dest, 0o600, nil)
	require.NoError(t, err)
	_, err = o.Write([]byte("partial"))
	require.NoError(t, err)
	o.Cleanup()

	got, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Equal(t, "original", string(got))
	assert.Empty(t, tempSiblings(t, dir))
}

func TestOutputFileCommitAfterCommitReturnsError(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.tdf")

	o, err := NewOutputFile(dest, testOutputFileMode, nil)
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

	o, err := NewOutputFile(dest, testOutputFileMode, nil)
	require.NoError(t, err)
	_, err = o.Write([]byte("payload"))
	require.NoError(t, err)

	o.Cleanup()
	require.ErrorIs(t, o.Commit(), ErrOutputFileFinished)

	_, err = os.Stat(dest)
	require.ErrorIs(t, err, os.ErrNotExist, "Commit after Cleanup must not create the destination")
}

// An ordinary destination that happens to be the input is not the destructive
// case: the payload goes to a temp sibling and is renamed over the input only
// once the read has finished. Decrypting a file in place is a reasonable thing
// to ask for, so the guard must not reject it.
func TestOutputFileAllowsRegularDestinationNamingInput(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "in-place.txt")
	require.NoError(t, os.WriteFile(dest, []byte("ciphertext"), 0o600))

	input, err := os.Open(dest)
	require.NoError(t, err)
	defer input.Close()

	o, err := NewOutputFile(dest, testOutputFileMode, input)
	require.NoError(t, err)

	// The input stays readable while the output is open, which is what makes
	// the temp-and-rename route safe here.
	got, err := io.ReadAll(input)
	require.NoError(t, err)
	assert.Equal(t, "ciphertext", string(got))

	_, err = o.Write([]byte("plaintext"))
	require.NoError(t, err)
	require.NoError(t, o.Commit())

	final, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Equal(t, "plaintext", string(final))
}

// The temporary name is bounded by the fixed prefix, not by the destination's,
// so a destination whose own name is as long as the filesystem allows still
// opens. Deriving the prefix from the basename overflowed NAME_MAX here and
// failed before a byte had been read.
func TestOutputFileAcceptsMaximumLengthDestinationName(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, strings.Repeat("n", 255))

	// Not every filesystem allows a 255-byte component; probe rather than
	// assume, so this reports the temp-name bug and nothing else.
	probe, err := os.OpenFile(dest, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Skipf("filesystem will not hold a 255-byte name: %v", err)
	}
	require.NoError(t, probe.Close())
	require.NoError(t, os.Remove(dest))

	o, err := NewOutputFile(dest, testOutputFileMode, nil)
	require.NoError(t, err)
	_, err = o.Write([]byte("payload"))
	require.NoError(t, err)
	require.NoError(t, o.Commit())

	got, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Equal(t, "payload", string(got))
}

// plainCreateMode reports the permissions a plain create with mode produces in
// dir under whatever umask the test process happens to be running with, which
// is what a committed OutputFile is expected to match. Probing beats hardcoding
// the mode: the tests then assert the umask is honored rather than assuming the
// developer or CI runner set a particular one.
func plainCreateMode(t *testing.T, dir string, mode os.FileMode) os.FileMode {
	t.Helper()
	probe := filepath.Join(dir, "umask-probe")
	f, err := os.OpenFile(probe, os.O_RDWR|os.O_CREATE|os.O_EXCL, mode)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	defer os.Remove(probe)

	info, err := os.Stat(probe)
	require.NoError(t, err)
	return info.Mode().Perm()
}

// tempSiblings returns any leftover temp files NewOutputFile would have created
// in dir. The prefix carries no destination name, so this cannot be narrowed to
// one destination — which is fine, since every caller wants dir swept clean.
func tempSiblings(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	var found []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), tempFilePrefix) {
			found = append(found, e.Name())
		}
	}
	return found
}
