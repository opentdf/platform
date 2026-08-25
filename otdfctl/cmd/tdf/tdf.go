package tdf

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/opentdf/platform/otdfctl/pkg/cli"
)

const (
	Size1MB     = 1024 * 1024
	MaxFileSize = int64(10 * 1024 * 1024 * 1024) // 10 GB
	TDF         = "TDF"
	// GroupID is the group ID for TDF commands
	GroupID = TDF
)

func readPipedStdin() []byte {
	stat, err := os.Stdin.Stat()
	if err != nil {
		cli.ExitWithError("Failed to read stat from stdin", err)
	}
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		buf, err := io.ReadAll(os.Stdin)
		if err != nil {
			cli.ExitWithError("failed to scan bytes from stdin", err)
		}
		return buf
	}
	return nil
}

// stdinReader reports whether stdin is a pipe or redirect carrying at least one
// byte, and returns a reader over it.
//
// Presence is established with a one-byte Peek rather than a read, so the
// payload still reaches the caller intact and nothing is buffered beyond the
// reader's window. A terminal, or an empty redirect such as
// `otdfctl encrypt < /dev/null`, reports false — matching the behavior of the
// buffered implementation, which decided the same question by checking whether
// a full read of stdin came back empty.
//
// The buffer is sized so that a later Peek for MIME detection is served from
// it without a second allocation.
func stdinReader() (*bufio.Reader, bool) {
	r, ok, err := pipeReader(os.Stdin)
	if err != nil {
		cli.ExitWithError("failed to scan bytes from stdin", err)
	}
	return r, ok
}

// pipeReader is the testable half of stdinReader.
func pipeReader(in *os.File) (*bufio.Reader, bool, error) {
	stat, err := in.Stat()
	if err != nil {
		return nil, false, err
	}
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		return nil, false, nil
	}

	r := bufio.NewReaderSize(in, Size1MB)
	if _, err := r.Peek(1); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return r, true, nil
}

// outputFile writes to a temporary file alongside the destination and renames
// it into place only once the write has succeeded, so an interrupted or failed
// run leaves no partial output where a complete file is expected.
//
// Note that cli.ExitWithError calls os.Exit, which does not run deferred
// functions. Cleanup must therefore be called explicitly on every error path,
// not only via defer.
type outputFile struct {
	f         *os.File
	path      string
	committed bool
}

// newOutputFile creates the temporary file in the destination's own directory,
// which keeps the final rename atomic — across filesystems it would degrade to
// a copy.
func newOutputFile(path string) (*outputFile, error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return nil, err
	}
	return &outputFile{f: f, path: path}, nil
}

func (o *outputFile) Write(p []byte) (int, error) { return o.f.Write(p) }

// Commit closes the temporary file and moves it onto the destination path.
func (o *outputFile) Commit() error {
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

// Cleanup discards the temporary file. It is a no-op after a successful
// Commit, so it is safe to both defer it and call it directly.
func (o *outputFile) Cleanup() {
	if o.committed {
		return
	}
	o.f.Close()
	os.Remove(o.f.Name())
}
