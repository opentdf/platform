// Package streamio provides the input and output plumbing shared by commands
// that move payloads too large to hold in memory.
//
// Everything here returns errors rather than terminating the process, so the
// decision to exit stays with the command layer. That is the difference from
// the older helpers in pkg/cli, which call cli.ExitWithError from inside the
// read and are therefore unusable from anywhere that wants to recover.
package streamio

import (
	"bufio"
	"errors"
	"io"
	"os"
)

// PipeBufferSize is the window PipeReader buffers over a pipe. It is sized so
// that a caller peeking a prefix for content-type detection is served from the
// same buffer rather than allocating a second one.
const PipeBufferSize = 1024 * 1024

// ErrNoInput reports that a command was given neither a file argument nor a
// non-empty pipe. It is distinct from a failure to open a named file, which
// callers report differently.
var ErrNoInput = errors.New("no input provided")

// PipeReader reports whether in is a pipe or redirect carrying at least one
// byte, and returns a reader over it.
//
// Presence is established with a one-byte Peek rather than a read, so the
// payload still reaches the caller intact and nothing is buffered beyond the
// reader's window. A terminal, or an empty redirect such as
// `otdfctl encrypt < /dev/null`, reports false — matching the behavior of a
// buffered implementation, which decides the same question by checking whether
// a full read came back empty.
func PipeReader(in *os.File) (*bufio.Reader, bool, error) {
	stat, err := in.Stat()
	if err != nil {
		return nil, false, err
	}
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		return nil, false, nil
	}

	r := bufio.NewReaderSize(in, PipeBufferSize)
	if _, err := r.Peek(1); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return r, true, nil
}

// Spool copies r into a temporary file and rewinds it, giving a seekable view
// of a stream that has none.
//
// A TDF's manifest sits at the end of the archive, so decrypt and inspect have
// to seek and cannot consume a pipe directly. Spooling trades disk for the
// memory a whole-payload read would use, and needs a TMPDIR with room for the
// full TDF — it fails loudly if there isn't one.
//
// The returned cleanup must run on every path. cli.ExitWithError calls os.Exit
// and skips deferred functions, so deferring it alone is not enough.
func Spool(r io.Reader) (*os.File, func(), error) {
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

// OpenSeekable resolves a command's input to something seekable: the named file
// when one is given, otherwise piped stdin spooled to disk. It returns
// ErrNoInput for the same "nothing to read" condition whether the file argument
// was absent or the pipe was empty.
//
// The returned cleanup must run on every path, per Spool.
func OpenSeekable(path string) (*os.File, func(), error) {
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, func() {}, err
		}
		return f, func() { f.Close() }, nil
	}

	piped, ok, err := PipeReader(os.Stdin)
	if err != nil {
		return nil, func() {}, err
	}
	if !ok {
		return nil, func() {}, ErrNoInput
	}
	return Spool(piped)
}
