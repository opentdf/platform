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

// ErrOutputAliasesInput reports that the destination resolves to the file being
// read. Opening it would truncate the input before it has been read.
var ErrOutputAliasesInput = errors.New("streamio: output would overwrite the input")

// tempFileAttempts bounds the search for an unused temporary name, so a
// pathological directory cannot spin here forever.
const tempFileAttempts = 1000

// tempFilePrefix names the temporary files created beside a destination.
//
// Deliberately fixed rather than derived from the destination: a component name
// is capped (255 bytes on most filesystems), and a prefix carrying the
// destination's own basename overflows that cap for a destination whose name is
// itself valid, failing the open before a single byte has been read. The random
// suffix is what distinguishes concurrent writers; the prefix only has to be
// recognizable enough to sweep up after a crash.
const tempFilePrefix = ".otdfctl.tmp-"

// OutputFile writes to a temporary file alongside the destination and renames
// it into place only once the write has succeeded, so an interrupted or failed
// run leaves no partial output where a complete file is expected.
//
// A destination that a rename cannot stand in for — /dev/null, /dev/stdout, a
// fifo, a symlink the caller means to write through — is opened and written
// directly instead, matching what os.Create did before. Those destinations give
// up the no-partial-output guarantee, which is inherent: there is nothing to
// rename into place.
//
// Note that cli.ExitWithError calls os.Exit, which does not run deferred
// functions. Cleanup must therefore be called explicitly on every error path,
// not only via defer.
type OutputFile struct {
	f      *os.File
	path   string
	direct bool

	finished bool
}

// NewOutputFile opens the destination for writing.
//
// For an ordinary destination it creates the temporary file in the
// destination's own directory. A rename is only atomic within a single
// filesystem, so the temp file must live beside the destination rather than in
// a shared temp directory — Commit's os.Rename fails outright (EXDEV) if that
// invariant is broken.
//
// The temp file is created with mode, and a rename carries that mode onto the
// destination after the process umask has been applied. A destination written
// through directly is opened with mode, which the umask likewise applies to,
// and which has no effect at all on a destination that already exists.
//
// input is the file the caller is reading, already open, and is what the
// destination is checked against — pass nil when there is none. Callers open
// their input before their output precisely so a failure to read costs nothing;
// without this the write-through open would undo that.
func NewOutputFile(path string, mode os.FileMode, input *os.File) (*OutputFile, error) {
	direct, err := isDirectDestination(path)
	if err != nil {
		return nil, err
	}
	if direct {
		// Only the write-through open is destructive. An ordinary destination
		// naming the input goes to a temp sibling and is renamed over it once
		// the read has finished, which is in-place decryption working as asked
		// rather than a footgun.
		alias, err := aliasesInput(path, input)
		if err != nil {
			return nil, err
		}
		if alias {
			return nil, fmt.Errorf("%w: %s", ErrOutputAliasesInput, path)
		}

		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
		if err != nil {
			return nil, err
		}
		return &OutputFile{f: f, path: path, direct: true}, nil
	}

	f, err := createTemp(filepath.Dir(path), tempFilePrefix, mode)
	if err != nil {
		return nil, err
	}
	return &OutputFile{f: f, path: path}, nil
}

// aliasesInput reports whether a write-through open of path would land on
// input.
//
// os.Stat, not os.Lstat: a symlink destination is the case that matters, since
// the open follows it, and the link's own identity is never what gets written.
// A dangling symlink resolves to nothing and aliases nothing — the open creates
// the target.
func aliasesInput(path string, input *os.File) (bool, error) {
	if input == nil {
		return false, nil
	}
	inputInfo, err := input.Stat()
	if err != nil {
		return false, err
	}
	destInfo, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return os.SameFile(inputInfo, destInfo), nil
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

// isDirectDestination reports whether path names something that must be written
// through rather than replaced by a rename.
//
// os.Lstat rather than os.Stat, so a symlink is recognized as a symlink: with
// os.Stat a link to a regular file looks regular, and the rename would replace
// the link itself instead of updating what it points at.
//
// A path that does not exist yet is the common case and takes the atomic route.
func isDirectDestination(path string) (bool, error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return !fi.Mode().IsRegular(), nil
}

func (o *OutputFile) Write(p []byte) (int, error) { return o.f.Write(p) }

// Name reports the path currently being written: the temporary file for an
// ordinary destination, which is not the destination until Commit succeeds, or
// the destination itself for one being written through directly.
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

	if o.direct {
		return o.f.Close()
	}

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
//
// A destination being written through directly is only closed, never removed —
// the file is the caller's, and for /dev/null and friends removing it would do
// real damage.
func (o *OutputFile) Cleanup() {
	if o.finished {
		return
	}
	o.finished = true
	o.f.Close()
	if !o.direct {
		os.Remove(o.f.Name())
	}
}
