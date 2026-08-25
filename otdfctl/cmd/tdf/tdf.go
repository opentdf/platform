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
	Size1MB = 1024 * 1024
	TDF     = "TDF"
	// GroupID is the group ID for TDF commands
	GroupID = TDF
)

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

// spoolToTempFile copies r into a temporary file and rewinds it, giving a
// seekable view of a stream that has none.
//
// A TDF's manifest sits at the end of the archive, so decrypt and inspect have
// to seek and cannot consume a pipe directly. Spooling trades disk for the
// memory the old whole-payload read used, and needs a TMPDIR with room for the
// full TDF — it fails loudly if there isn't one.
//
// The returned cleanup must run on every path. cli.ExitWithError calls os.Exit
// and skips deferred functions, so deferring it alone is not enough.
func spoolToTempFile(r io.Reader) (*os.File, func(), error) {
	f, err := os.CreateTemp("", "otdfctl-spool-*.tdf")
	if err != nil {
		return nil, func() {}, err
	}
	cleanup := func() {
		f.Close()
		os.Remove(f.Name())
	}
	if _, err := io.Copy(f, r); err != nil {
		cleanup()
		return nil, func() {}, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		cleanup()
		return nil, func() {}, err
	}
	return f, cleanup, nil
}

// openSeekableInput resolves a command's input to something seekable: the named
// file when one is given, otherwise piped stdin spooled to disk. It reports the
// same "no input" condition for an absent file argument and an empty pipe.
//
// The returned cleanup must run on every path, per spoolToTempFile.
func openSeekableInput(path string) (*os.File, func(), error) {
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, func() {}, err
		}
		return f, func() { f.Close() }, nil
	}

	piped, ok := stdinReader()
	if !ok {
		return nil, func() {}, errNoInput
	}
	return spoolToTempFile(piped)
}

var errNoInput = errors.New("no input provided")

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
