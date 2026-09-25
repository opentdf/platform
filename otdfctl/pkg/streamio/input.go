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

// PipeBufferSize is the window Piped buffers over a pipe — generous enough that
// a typical CLI payload is served from a single read.
const PipeBufferSize = 1024 * 1024

var (
	// ErrNoInput reports that a command was given neither a file argument nor a
	// non-empty pipe. It is distinct from a failure to open a named file, which
	// callers report differently.
	ErrNoInput = errors.New("no input provided")

	// ErrTwoInputs reports that a command which takes one payload was given two.
	// Only OpenExclusive returns it; Open prefers the file argument instead.
	ErrTwoInputs = errors.New("file argument and stdin input both provided")
)

// Seekable reports r's current position, and whether it could be asked for one.
//
// It probes rather than asserting io.Seeker, because an *os.File on a FIFO, a
// process substitution, or /dev/stdin on the end of a pipe all satisfy the
// interface and then return ESPIPE. Seeking to the current position never moves
// it, so this is safe on a payload about to be read.
func Seekable(r io.Reader) (io.Seeker, int64, bool) {
	seeker, ok := r.(io.Seeker)
	if !ok {
		return nil, 0, false
	}
	off, err := seeker.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, 0, false
	}
	return seeker, off, true
}

// Measurable reports whether the SDK can size r without reading it, and so
// whether the archive gets the compact layout. See handlers.Handler's Encrypt.
func Measurable(r io.Reader) bool {
	_, _, ok := Seekable(r)
	return ok
}

// unmeasurable hides a reader's Seek method, so anything probing for one sizes
// the payload by reading it instead.
type unmeasurable struct{ io.Reader }

// openFile opens path for reading, ready to hand to the SDK as-is.
//
// The file stays measurable, except when its stat cannot be trusted: a procfs or
// sysfs file is a regular file that reports zero bytes and then reads out
// content. Measuring one declares an empty payload, and the SDK limits its reads
// to the length it was given, so the encrypt would succeed with nothing in it.
// Those come back with the Seeker hidden — an archive a few dozen bytes larger
// beats an archive missing the payload.
//
// cleanup is always non-nil, including on the error return.
func openFile(path string) (io.Reader, func(), error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, func() {}, err
	}
	cleanup := func() { f.Close() }
	stat, err := f.Stat()
	if err != nil {
		cleanup()
		return nil, func() {}, err
	}
	if stat.Mode().IsRegular() && stat.Size() == 0 {
		return unmeasurable{f}, cleanup, nil
	}
	return f, cleanup, nil
}

// Piped reports whether in carries at least one byte of payload, and returns a
// reader over it. A terminal, or an empty redirect such as
// `otdfctl encrypt < /dev/null`, reports false. It is named for the usual case
// but takes redirects too, which is the harder half.
//
// A redirect from a regular file — `otdfctl encrypt < payload.txt` — is handed
// back as the *os.File itself, so the payload stays measurable. Wrapping it
// would throw that away for nothing: it is the same fd either way. Everything
// else is a stream, and gets a buffered reader.
func Piped(in *os.File) (io.Reader, bool, error) {
	stat, err := in.Stat()
	if err != nil {
		return nil, false, err
	}
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		return nil, false, nil
	}

	// Presence comes from the stat rather than a Peek, which would advance the
	// fd the caller is about to be handed. Measured from the current offset, not
	// zero: `{ read -r header; otdfctl encrypt; } < payload.txt` leaves stdin
	// mid-file, and what remains is the payload.
	//
	// Only a stat that counts bytes ahead of the offset gets to decide, since a
	// zero-byte procfs file reads out content anyway (see openFile). Everything
	// else falls through to the Peek, which asks the file instead of the stat and
	// still answers absent for a genuinely empty or already-consumed one.
	if stat.Mode().IsRegular() {
		if _, off, ok := Seekable(in); ok && stat.Size() > off {
			return in, true, nil
		}
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

// Open resolves a command's payload: the named file when one is given,
// otherwise stdin. It returns ErrNoInput when there is neither.
//
// Nothing is copied, so a measurable source reaches the caller measurable; see
// Measurable. A file argument wins outright and stdin is not even looked at,
// since a command run inside `while read f; do ... done < list` inherits a stdin
// that is the loop's, not a payload — and looking costs a peek that would eat it.
//
// cleanup is always non-nil, including on the error return. For a piped payload
// it does nothing: closing stdin is not ours to do.
func Open(path string) (io.Reader, func(), error) {
	if path != "" {
		return openFile(path)
	}
	piped, ok, err := Piped(os.Stdin)
	switch {
	case err != nil:
		return nil, func() {}, err
	case !ok:
		return nil, func() {}, ErrNoInput
	}
	return piped, func() {}, nil
}

// OpenExclusive is Open for a command that refuses to choose: being handed both
// a file argument and a payload on stdin is ErrTwoInputs rather than a silent
// preference. Telling them apart means inspecting stdin even when the file
// argument would have decided it, which for a pipe consumes what it peeked.
func OpenExclusive(path string) (io.Reader, func(), error) {
	piped, hasPiped, err := Piped(os.Stdin)
	switch {
	case err != nil:
		return nil, func() {}, err
	case path != "" && hasPiped:
		return nil, func() {}, ErrTwoInputs
	case path != "":
		return openFile(path)
	case hasPiped:
		return piped, func() {}, nil
	}
	return nil, func() {}, ErrNoInput
}

// Spool copies r into a temporary file and rewinds it, giving a seekable view
// of a stream that has none.
//
// A TDF's manifest sits at the end of the archive, so any command that needs
// to seek it cannot consume a pipe directly. Spooling trades disk for the
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

// OpenSeekable is Open for a command that has to seek its input — reading a
// TDF, whose manifest sits at the end of the archive.
//
// Only what cannot seek is spooled to disk: a named file or a redirect from one
// seeks already, and copying it would need a TMPDIR with room for the whole TDF
// to hand back a view no better than the one it had.
//
// The returned cleanup must run on every path, per Spool.
func OpenSeekable(path string) (*os.File, func(), error) {
	in, cleanup, err := Open(path)
	if err != nil {
		return nil, func() {}, err
	}
	if f, ok := in.(*os.File); ok && Measurable(f) {
		return f, cleanup, nil
	}
	// A pipe, a FIFO, /dev/fd/N, or a file whose stat openFile would not vouch
	// for. Spooling closes over the original, so let go of it either way.
	spooled, spoolCleanup, err := Spool(in)
	cleanup()
	return spooled, spoolCleanup, err
}
