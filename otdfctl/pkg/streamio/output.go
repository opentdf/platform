package streamio

import (
	"os"
	"path/filepath"
)

// OutputFile writes to a temporary file alongside the destination and renames
// it into place only once the write has succeeded, so an interrupted or failed
// run leaves no partial output where a complete file is expected.
//
// Note that cli.ExitWithError calls os.Exit, which does not run deferred
// functions. Cleanup must therefore be called explicitly on every error path,
// not only via defer.
type OutputFile struct {
	f         *os.File
	path      string
	committed bool
}

// NewOutputFile creates the temporary file in the destination's own directory,
// which keeps the final rename atomic — across filesystems it would degrade to
// a copy.
func NewOutputFile(path string) (*OutputFile, error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return nil, err
	}
	return &OutputFile{f: f, path: path}, nil
}

func (o *OutputFile) Write(p []byte) (int, error) { return o.f.Write(p) }

// Name reports the path of the temporary file currently being written, which is
// not the destination until Commit succeeds.
func (o *OutputFile) Name() string { return o.f.Name() }

// Commit closes the temporary file and moves it onto the destination path.
func (o *OutputFile) Commit() error {
	if err := o.f.Close(); err != nil {
		os.Remove(o.f.Name())
		return err
	}
	if err := os.Rename(o.f.Name(), o.path); err != nil {
		os.Remove(o.f.Name())
		return err
	}
	o.committed = true
	return nil
}

// Cleanup discards the temporary file. It is a no-op after a successful Commit,
// so it is safe to both defer it and call it directly.
func (o *OutputFile) Cleanup() {
	if o.committed {
		return
	}
	o.f.Close()
	os.Remove(o.f.Name())
}
