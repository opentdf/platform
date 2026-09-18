package streamio

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrOutputFileFinished reports that Commit or Cleanup was called on an
// OutputFile that had already been committed or discarded.
var ErrOutputFileFinished = errors.New("streamio: output file already committed or discarded")

// tempFileAttempts bounds the search for an unused temporary name, so a
// pathological directory cannot spin here forever.
const tempFileAttempts = 1000

// OutputFile writes to a temporary file alongside the destination and renames
// it into place only once the write has succeeded, so an interrupted or failed
// run leaves no partial output where a complete file is expected.
//
// Note that cli.ExitWithError calls os.Exit, which does not run deferred
// functions. Cleanup must therefore be called explicitly on every error path,
// not only via defer.
type OutputFile struct {
	f        *os.File
	path     string
	finished bool
}

// NewOutputFile creates the temporary file in the destination's own directory.
// A rename is only atomic within a single filesystem, so the temp file must
// live beside the destination rather than in a shared temp directory —
// Commit's os.Rename fails outright (EXDEV) if that invariant is broken.
//
// The temp file is created with mode, and a rename carries that mode onto the
// destination after the process umask has been applied.
func NewOutputFile(path string, mode os.FileMode) (*OutputFile, error) {
	f, err := createTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-", mode)
	if err != nil {
		return nil, err
	}
	return &OutputFile{f: f, path: path}, nil
}

// createTemp is os.CreateTemp with a caller-chosen mode. os.CreateTemp hardcodes
// 0600, and correcting that afterwards with Chmod would ignore the umask, so
// this opens the file directly to let mode reach the kernel.
func createTemp(dir, prefix string, mode os.FileMode) (*os.File, error) {
	for range tempFileAttempts {
		var suffix [8]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return nil, err
		}

		// O_EXCL is what makes the name ours: if the random name is already
		// taken, the open fails rather than truncating another writer's file.
		name := filepath.Join(dir, prefix+hex.EncodeToString(suffix[:]))
		f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, mode)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		return f, err
	}
	return nil, fmt.Errorf("streamio: no unused temporary name for %s after %d attempts", filepath.Join(dir, prefix), tempFileAttempts)
}

func (o *OutputFile) Write(p []byte) (int, error) { return o.f.Write(p) }

// Name reports the path of the temporary file currently being written, which is
// not the destination until Commit succeeds.
func (o *OutputFile) Name() string { return o.f.Name() }

// Commit closes the temporary file and moves it onto the destination path.
//
// It returns ErrOutputFileFinished if called more than once, or after Cleanup —
// otherwise a second call would re-enter the close/rename-failure path against
// an already-closed or already-moved file and report a spurious error.
func (o *OutputFile) Commit() error {
	if o.finished {
		return ErrOutputFileFinished
	}
	o.finished = true
	if err := o.f.Close(); err != nil {
		os.Remove(o.f.Name())
		return err
	}
	if err := os.Rename(o.f.Name(), o.path); err != nil {
		os.Remove(o.f.Name())
		return err
	}
	return nil
}

// Cleanup discards the temporary file. It is a no-op after a successful Commit
// (or a prior Cleanup), so it is safe to both defer it and call it directly.
func (o *OutputFile) Cleanup() {
	if o.finished {
		return
	}
	o.finished = true
	o.f.Close()
	os.Remove(o.f.Name())
}
