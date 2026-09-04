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

// stdinReader reports whether stdin is a non-empty pipe or redirect and
// returns it without consuming the first byte.
func stdinReader() (*bufio.Reader, bool) {
	r, ok, err := pipeReader(os.Stdin)
	if err != nil {
		cli.ExitWithError("failed to scan bytes from stdin", err)
	}
	return r, ok
}

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

// outputFile stages output next to its destination and renames it into place
// only after encryption succeeds.
type outputFile struct {
	f         *os.File
	path      string
	committed bool
}

func newOutputFile(path string) (*outputFile, error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return nil, err
	}
	return &outputFile{f: f, path: path}, nil
}

func (o *outputFile) Write(p []byte) (int, error) {
	return o.f.Write(p)
}

func (o *outputFile) Commit() error {
	if err := o.f.Close(); err != nil {
		_ = os.Remove(o.f.Name())
		return err
	}
	if err := os.Rename(o.f.Name(), o.path); err != nil {
		_ = os.Remove(o.f.Name())
		return err
	}
	o.committed = true
	return nil
}

func (o *outputFile) Cleanup() {
	if o == nil || o.committed {
		return
	}
	_ = o.f.Close()
	_ = os.Remove(o.f.Name())
}
