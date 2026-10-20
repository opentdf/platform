// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package zipstream

import (
	"bufio"
	"compress/flate"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
)

// OpenTDF writers store both TDF entries uncompressed, but other TDF writers
// compress them with DEFLATE. The reader accepts both; see zipFileEntry.

// APPNOTE 4.4.5 compression methods this reader can read.
const (
	zipMethodStore   = 0
	zipMethodDeflate = 8
)

// maxDeflateRatio is the most DEFLATE can expand its input. The longest match
// is 258 bytes and costs at least two bits (one for its length code, one for
// its distance code), so no stream inflates to more than 1032 times its own
// length.
const maxDeflateRatio = 1032

const (
	// inflateBufferSize is how much compressed data each refill pulls from
	// the archive. A refill costs a seek and a read on a ReadSeeker that may
	// be backed by network range requests, so it should be rare.
	inflateBufferSize = 64 << 10

	// inflateChunkSize caps what a read allocates before it has inflated the
	// bytes to fill it. It covers the default 2 MiB segment in one step.
	inflateChunkSize = 4 << 20
)

var (
	// ErrUnsupportedCompression reports an archive entry compressed with a
	// method other than STORED (0) or DEFLATE (8).
	ErrUnsupportedCompression = errors.New("zip: unsupported compression method")

	// errInflatedSize reports a deflated entry whose data inflates to more or
	// fewer bytes than its declared uncompressed size.
	errInflatedSize = errors.New("zip: inflated data does not match the declared uncompressed size")
)

// unsupportedCompressionError names the entry and its method.
func unsupportedCompressionError(name string, method uint16) error {
	desc := fmt.Sprintf("method %d", method)
	if known := compressionMethodName(method); known != "" {
		desc += " (" + known + ")"
	}
	return fmt.Errorf("%w %s for entry %q; only stored (0) and deflate (8) are supported",
		ErrUnsupportedCompression, desc, name)
}

// compressionMethodName names the APPNOTE 4.4.5 methods an archive is most
// likely to carry, for error messages.
//
//nolint:mnd // APPNOTE 4.4.5 method IDs
func compressionMethodName(method uint16) string {
	switch method {
	case 1:
		return "shrink"
	case 6:
		return "implode"
	case 9:
		return "deflate64"
	case 12:
		return "bzip2"
	case 14:
		return "LZMA"
	case 93:
		return "zstd"
	case 95:
		return "xz"
	case 98:
		return "PPMd"
	case 99:
		return "AES encrypted"
	default:
		return ""
	}
}

// deflatedSize checks a deflated entry's declared uncompressed size against
// what its compressed length could hold. A larger declaration is malformed,
// and is refused here before any read can size a buffer from it.
func deflatedSize(name string, compressed int64, declared uint64) (int64, error) {
	if declared > math.MaxInt64 || declared/maxDeflateRatio > uint64(compressed) {
		return 0, fmt.Errorf("%w: %s declares %d uncompressed bytes, more than %d deflated bytes can hold",
			errZipFormat, name, declared, compressed)
	}
	return int64(declared), nil
}

// entrySource reads one entry's compressed bytes from the archive. Every
// entry shares the archive's ReadSeeker, so it seeks to its own position
// before each read rather than trusting where the last read left off, and it
// stops at the entry's last byte so the inflater can never read into the next
// entry or the central directory.
type entrySource struct {
	rs         io.ReadSeeker
	start, end int64
	pos        int64
}

func (s *entrySource) Read(p []byte) (int, error) {
	if s.pos >= s.end {
		return 0, io.EOF
	}
	if rem := s.end - s.pos; int64(len(p)) > rem {
		p = p[:rem]
	}
	if _, err := s.rs.Seek(s.pos, io.SeekStart); err != nil {
		return 0, fmt.Errorf("readSeeker.Seek failed: %w", err)
	}
	n, err := s.rs.Read(p)
	s.pos += int64(n)
	return n, err
}

// inflater serves reads of a deflated entry in uncompressed coordinates.
//
// DEFLATE decodes front to back only, so it keeps a forward cursor. A read at
// or past the cursor inflates and discards up to the requested offset, then
// inflates the requested bytes; a read behind the cursor restarts from the
// start of the entry. Reading segments in order costs one pass over the entry;
// each backward read costs re-inflating everything before its offset.
//
// The range the last read returned is kept, and a read inside it is served
// from there. The sdk's Read fetches the whole segment under its cursor on
// every call, so a caller reading in small pieces asks for the same segment
// many times running; without this, each repeat would restart inflation and a
// sequential read would be quadratic in the payload size. Memory is bounded by
// that range, the DEFLATE window, and the read buffer, never the entry size.
//
// It never inflates more than one byte past the declared size, which is what
// it takes to tell that a stream holds more than it declares.
//
// It is not safe for concurrent use; Reader serializes access with its mutex.
type inflater struct {
	name string
	size int64 // declared uncompressed size
	src  entrySource
	// buf and inflate hold the current pass. Both are nil before the first
	// read, after a read reaches the end of the entry, and after a failure.
	buf     *bufio.Reader
	inflate io.ReadCloser
	pos     int64 // uncompressed offset of the current pass
	// last is what the most recent read returned, starting at lastIndex.
	last      []byte
	lastIndex int64
}

func newInflater(rs io.ReadSeeker, name string, index, length, size int64) *inflater {
	return &inflater{
		name: name,
		size: size,
		src:  entrySource{rs: rs, start: index, end: index + length},
	}
}

// read returns length bytes at uncompressed offset index, from the last read
// if it covers them. The caller has checked that the range lies within the
// declared size. Callers get their own copy, as they do from a STORED entry.
func (z *inflater) read(index, length int64) ([]byte, error) {
	if off := index - z.lastIndex; z.last != nil && off >= 0 && length <= int64(len(z.last))-off {
		return slices.Clone(z.last[off : off+length]), nil
	}

	data, err := z.readUncached(index, length)
	if err != nil {
		return nil, err
	}
	z.last, z.lastIndex = data, index
	return slices.Clone(data), nil
}

// readAll inflates the whole entry. It bypasses the last-read cache: it
// serves ReadAllFileData, which reads the manifest once.
func (z *inflater) readAll() ([]byte, error) {
	return z.readUncached(0, z.size)
}

func (z *inflater) readUncached(index, length int64) ([]byte, error) {
	if z.inflate == nil || index < z.pos {
		if err := z.restart(); err != nil {
			z.release()
			return nil, err
		}
	}

	data, err := z.advance(index, length)
	if err != nil {
		// The pass is in an unknown state; the next read starts over.
		z.release()
		return nil, err
	}
	return data, nil
}

func (z *inflater) advance(index, length int64) ([]byte, error) {
	if skip := index - z.pos; skip > 0 {
		n, err := io.CopyN(io.Discard, z.inflate, skip)
		z.pos += n
		if err != nil {
			return nil, z.inflateError(err)
		}
	}

	data, err := readInflated(z.inflate, length)
	if err != nil {
		return nil, z.inflateError(err)
	}
	z.pos += length

	if z.pos == z.size {
		if err := z.checkEnd(); err != nil {
			return nil, err
		}
		// Nothing past the end can be read, so free the pass.
		z.release()
	}
	return data, nil
}

// restart begins a new pass at the start of the entry.
func (z *inflater) restart() error {
	z.src.pos = z.src.start
	z.pos = 0
	if z.inflate == nil {
		z.buf = bufio.NewReaderSize(&z.src, inflateBufferSize)
		z.inflate = flate.NewReader(z.buf)
		return nil
	}
	z.buf.Reset(&z.src)
	resetter, ok := z.inflate.(flate.Resetter)
	if !ok {
		return errors.New("zip: flate reader cannot be reset")
	}
	return resetter.Reset(z.buf, nil)
}

func (z *inflater) release() {
	z.buf = nil
	z.inflate = nil
	z.pos = 0
}

// checkEnd confirms the stream ends at the declared size. Asking for one more
// byte is enough to tell a stream that carries more, without inflating
// however much more there is.
func (z *inflater) checkEnd() error {
	var b [1]byte
	n, err := io.ReadFull(z.inflate, b[:])
	switch {
	case n > 0:
		return fmt.Errorf("%w: %s inflates past its declared %d bytes", errInflatedSize, z.name, z.size)
	case errors.Is(err, io.EOF):
		return nil
	default:
		return fmt.Errorf("zip: inflating %s: %w", z.name, err)
	}
}

func (z *inflater) inflateError(err error) error {
	// io.ReadFull reports a stream that ends early as io.ErrUnexpectedEOF,
	// and so does flate for compressed data that is cut off.
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("%w: %s inflates to fewer than its declared %d bytes: %w",
			errInflatedSize, z.name, z.size, io.ErrUnexpectedEOF)
	}
	return fmt.Errorf("zip: inflating %s: %w", z.name, err)
}

// readInflated reads exactly n bytes from r. Its buffer grows as data
// arrives rather than being allocated at n up front, so a forged size costs
// memory only in proportion to what the stream really inflates to.
func readInflated(r io.Reader, n int64) ([]byte, error) {
	buf := make([]byte, 0, min(n, inflateChunkSize))
	for int64(len(buf)) < n {
		grow := int(min(n-int64(len(buf)), max(int64(len(buf)), inflateChunkSize)))
		buf = slices.Grow(buf, grow)
		start := len(buf)
		buf = buf[:start+grow]
		if _, err := io.ReadFull(r, buf[start:]); err != nil {
			return nil, err
		}
	}
	return buf, nil
}
