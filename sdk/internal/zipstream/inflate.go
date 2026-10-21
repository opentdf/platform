// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package zipstream

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
)

// OpenTDF writers store both TDF entries uncompressed, but other TDF writers
// compress them with DEFLATE. Deflated entries are read through archive/zip,
// which inflates them, holds them to their declared uncompressed size, and
// checks their CRC-32 once one is read to the end. What this file adds is
// random access in uncompressed coordinates, which payload segment reads need
// and archive/zip does not offer. STORED entries never reach archive/zip.

// readChunkSize caps what a deflated read allocates before it has inflated
// the bytes to fill it. It covers the default 2 MiB segment in one step.
const readChunkSize = 4 << 20

// minInflateBudget is the floor of a Reader's inflation budget: the most
// uncompressed bytes a deflated entry may declare is the larger of the
// archive's length and this. A STORED entry can never be longer than its
// archive, but DEFLATE expands up to about 1000 times, so without a budget a
// few-MB archive could make a reader allocate gigabytes. Payload ciphertext
// does not compress, so a legitimate deflated payload stays under the
// archive's length; the floor leaves room for a manifest that compresses well.
// An explicit manifest size limit overrides the budget; see ReadAllFileData.
const minInflateBudget = 10 << 20

// inflateBudgetError reports a deflated entry declaring more than the budget.
func inflateBudgetError(name string, declared, budget int64, remedy string) error {
	return fmt.Errorf("%w: %s declares %d uncompressed bytes, more than the %d bytes allowed for a deflated entry in this archive; %s",
		errZipFileSizeError, name, declared, budget, remedy)
}

// unsupportedCompressionError wraps zip.ErrAlgorithm, so callers outside the
// SDK can test for it, with the entry and the method.
func unsupportedCompressionError(name string, method uint16) error {
	return fmt.Errorf("%w: entry %q uses compression method %d; only stored (0) and deflate (8) are supported",
		zip.ErrAlgorithm, name, method)
}

// deflatedSize converts a deflated entry's declared uncompressed size to the
// int64 that reads are bounded by. archive/zip enforces the size itself as the
// entry is read; this refuses only a size too large to represent.
func deflatedSize(name string, declared uint64) (int64, error) {
	if declared > math.MaxInt64 {
		return 0, fmt.Errorf("%w: %s declares %d uncompressed bytes", errZipFormat, name, declared)
	}
	return int64(declared), nil
}

// zipView is archive/zip's reading of an archive that holds deflated
// entries. NewReader hands one only to deflated entries, and the zip.Reader is
// built on the first read of one, so archives with only STORED entries never
// touch archive/zip. Callers must hold Reader.mu.
type zipView struct {
	rs io.ReadSeeker
	zr *zip.Reader
}

func (v *zipView) reader() (*zip.Reader, error) {
	if v.zr != nil {
		return v.zr, nil
	}
	size, err := v.rs.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, fmt.Errorf("readSeeker.Seek failed: %w", err)
	}
	// ErrInsecurePath comes with a usable reader. It is about extracting to a
	// filesystem, which this package never does.
	zr, err := zip.NewReader(readerAt{rs: v.rs}, size)
	if err != nil && !errors.Is(err, zip.ErrInsecurePath) {
		return nil, fmt.Errorf("archive/zip cannot read the archive: %w", err)
	}
	v.zr = zr
	return zr, nil
}

// readerAt adapts the archive's ReadSeeker for archive/zip. Callers must hold
// Reader.mu, which serializes every use of the ReadSeeker.
type readerAt struct {
	rs io.ReadSeeker
}

func (r readerAt) ReadAt(p []byte, off int64) (int, error) {
	if _, err := r.rs.Seek(off, io.SeekStart); err != nil {
		return 0, fmt.Errorf("readSeeker.Seek failed: %w", err)
	}
	n, err := io.ReadFull(r.rs, p)
	if errors.Is(err, io.ErrUnexpectedEOF) {
		// io.ReaderAt reports a read cut short by the end of input as io.EOF.
		err = io.EOF
	}
	return n, err
}

// deflatedFile serves reads of one deflated entry in uncompressed coordinates
// from archive/zip's reader for it.
//
// DEFLATE decodes front to back only, so it keeps a forward cursor over the
// open entry. A read at or past the cursor discards up to the requested
// offset, then reads the requested bytes; a read behind the cursor reopens the
// entry and starts over. Reading segments in order costs one pass; each
// backward read costs re-inflating everything before its offset.
//
// The range the last read returned is kept, and a read inside it is served
// from there. The sdk's Read fetches the whole segment under its cursor on
// every call, so a caller reading in small pieces asks for the same segment
// many times running; without this, each repeat would reopen the entry and a
// sequential read would be quadratic in the payload size.
//
// It is not safe for concurrent use; Reader serializes access with its mutex.
type deflatedFile struct {
	view   *zipView
	name   string
	index  int64 // data offset; it identifies the entry to archive/zip
	length int64 // compressed size
	size   int64 // declared uncompressed size
	file   *zip.File
	// rc is the current pass and pos its uncompressed offset. rc is nil
	// before the first read, after a read reaches the end, and after a failure.
	rc  io.ReadCloser
	pos int64
	// last is what the most recent read returned, starting at lastIndex.
	last      []byte
	lastIndex int64
}

// read returns length bytes at uncompressed offset index, from the last read
// if it covers them. The caller has checked that the range lies within the
// declared size. Callers get their own copy, as they do from a STORED entry.
func (d *deflatedFile) read(index, length int64) ([]byte, error) {
	if off := index - d.lastIndex; d.last != nil && off >= 0 && length <= int64(len(d.last))-off {
		return slices.Clone(d.last[off : off+length]), nil
	}

	data, err := d.readUncached(index, length)
	if err != nil {
		return nil, err
	}
	d.last, d.lastIndex = data, index
	return slices.Clone(data), nil
}

// readAll reads the whole entry. It bypasses the last-read cache: it serves
// ReadAllFileData, which reads the manifest once.
func (d *deflatedFile) readAll() ([]byte, error) {
	return d.readUncached(0, d.size)
}

func (d *deflatedFile) readUncached(index, length int64) ([]byte, error) {
	data, err := d.advance(index, length)
	if err != nil {
		// The pass is in an unknown state; the next read starts over.
		d.closePass()
		return nil, fmt.Errorf("zip: reading %s: %w", d.name, err)
	}
	return data, nil
}

func (d *deflatedFile) advance(index, length int64) ([]byte, error) {
	if d.rc == nil || index < d.pos {
		if err := d.reopen(); err != nil {
			return nil, err
		}
	}

	if skip := index - d.pos; skip > 0 {
		n, err := io.CopyN(io.Discard, d.rc, skip)
		d.pos += n
		if err != nil {
			return nil, err
		}
	}

	data, err := readGrowing(d.rc, length)
	if err != nil {
		return nil, err
	}
	d.pos += length

	if d.pos == d.size {
		// archive/zip checks that the stream ends at the declared size, and
		// verifies the CRC-32, only on the read that finds the end. It answers
		// one byte past the declared size with ErrFormat.
		var b [1]byte
		if _, err := io.ReadFull(d.rc, b[:]); !errors.Is(err, io.EOF) {
			return nil, err
		}
		// Nothing past the end can be read, so free the pass.
		d.closePass()
	}
	return data, nil
}

// reopen starts a new pass at the start of the entry.
func (d *deflatedFile) reopen() error {
	d.closePass()
	f, err := d.zipFile()
	if err != nil {
		return err
	}
	rc, err := f.Open()
	if err != nil {
		return err
	}
	d.rc = rc
	return nil
}

func (d *deflatedFile) closePass() {
	if d.rc != nil {
		_ = d.rc.Close()
		d.rc = nil
	}
	d.pos = 0
}

// zipFile finds archive/zip's entry for this one. It matches on the data
// offset as well as the name, so that two entries sharing a name cannot be
// crossed, and requires archive/zip to agree on both sizes, so the bounds
// NewReader checked hold for what archive/zip reads.
func (d *deflatedFile) zipFile() (*zip.File, error) {
	if d.file != nil {
		return d.file, nil
	}
	zr, err := d.view.reader()
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if f.Name != d.name {
			continue
		}
		if off, err := f.DataOffset(); err != nil || off != d.index {
			continue
		}
		if f.Method != zip.Deflate || f.CompressedSize64 != uint64(d.length) || f.UncompressedSize64 != uint64(d.size) {
			return nil, fmt.Errorf("%w: archive/zip disagrees about the method or sizes of %s", errZipFormat, d.name)
		}
		d.file = f
		return f, nil
	}
	return nil, fmt.Errorf("%w: archive/zip has no entry %s with data at %d", errZipFormat, d.name, d.index)
}

// readGrowing reads exactly n bytes from r. Its buffer grows as data arrives
// rather than being allocated at n up front, so a forged declared size costs
// memory only in proportion to what the entry really inflates to.
func readGrowing(r io.Reader, n int64) ([]byte, error) {
	buf := make([]byte, 0, min(n, readChunkSize))
	for int64(len(buf)) < n {
		grow := int(min(n-int64(len(buf)), max(int64(len(buf)), readChunkSize)))
		buf = slices.Grow(buf, grow)
		start := len(buf)
		buf = buf[:start+grow]
		if _, err := io.ReadFull(r, buf[start:]); err != nil {
			return nil, err
		}
	}
	return buf, nil
}
