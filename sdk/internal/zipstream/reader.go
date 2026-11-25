// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package zipstream

import (
	"archive/zip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
)

// https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
// https://rzymek.github.io/post/excel-zip64/
// Overall .ZIP file format:
//   [local file header 1]
//   [file data 1]
//   [ext 1]
//   [data descriptor 1]
//   .
//   .
//   .
//   [local file header n]
//   [file data n]
//   [ext n]
//   [data descriptor n]
//   [central directory header 1]
//   .
//   .
//   .
//   [central directory header n]
//   [zip64 end of central directory record]
//   [zip64 end of central directory locator]
//   [end of central directory record]

var (
	errZipFormat           = errors.New("zip: not a valid zip file")
	errZipFileNotFound     = errors.New("zip: file not found")
	errZipFileSizeError    = errors.New("zip: not a valid file size")
	errZipFormatFileHeader = errors.New("zip: unable to read local file header")
)

// zipFileEntry locates one entry's bytes in the archive. NewReader
// guarantees index and length are non-negative and index+length is at most the
// start of the central directory.
//
// size is the entry's logical length, which every read is bounded by. For a
// STORED entry it is length. For a DEFLATE entry it is the declared
// uncompressed size, and deflated reads the entry through archive/zip.
type zipFileEntry struct {
	index    int64
	length   int64
	size     int64
	deflated *deflatedFile
}

type Reader struct {
	readSeeker  io.ReadSeeker
	fileEntries map[string]zipFileEntry
	// mu serializes use of readSeeker, which every entry shares (archive/zip
	// reads it too, for deflated entries), and of the deflated entries'
	// cursors. It is a pointer so that copies of a Reader, such as the one a
	// TDFReader holds, share it.
	mu *sync.Mutex
	// inflateBudget is the most uncompressed bytes a deflated entry may
	// declare without an explicit limit: the larger of the archive's length
	// and minInflateBudget.
	inflateBudget int64
}

// NewReader Create archive reader instance.
//
// Entries may be STORED or DEFLATE compressed. An entry using any other
// compression method fails NewReader with an error wrapping zip.ErrAlgorithm.
func NewReader(readSeeker io.ReadSeeker) (Reader, error) {
	reader := Reader{mu: &sync.Mutex{}}
	reader.fileEntries = make(map[string]zipFileEntry)

	// The EOCD seek also reports the archive length, which bounds every offset
	// read below.
	eocdStart, err := readSeeker.Seek(-endOfCDRecordSize, io.SeekEnd)
	if err != nil {
		return reader, fmt.Errorf("readSeeker.Seek failed: %w", err)
	}
	archive, err := archiveBound(eocdStart)
	if err != nil {
		return reader, err
	}
	// archiveBound has checked that the archive's length fits an int64.
	reader.inflateBudget = max(eocdStart+endOfCDRecordSize, minInflateBudget)

	endOfCDRecord := EndOfCDRecord{}
	err = binary.Read(readSeeker, binary.LittleEndian, &endOfCDRecord)
	if err != nil {
		return reader, fmt.Errorf("binary.Read failed: %w", err)
	}

	// check if it's valid zip format
	if endOfCDRecord.Signature != endOfCentralDirectorySignature {
		return reader, errZipFormat
	}

	// check if zip is zip64 or zip32 format
	//
	// Any of the three EOCD fields that ZIP64 can overflow may carry the
	// sentinel independently: the entry count (two bytes wide, so its
	// sentinel is 0xFFFF), the central directory size, and the central
	// directory offset. An archive with more than 65534 entries needs ZIP64
	// for the count alone while its central directory still starts below
	// 4 GiB, so keying off the offset by itself misses it.
	var entryCount uint64
	var centralDirectoryStart uint64
	if !eocdNeedsZip64(endOfCDRecord) { //nolint:nestif // pkzip is complicated
		entryCount = uint64(endOfCDRecord.NumberOfCDRecordEntries)
		centralDirectoryStart = uint64(endOfCDRecord.CentralDirectoryOffset)
	} else {
		// read zip64 end of central directory locator
		_, err := readSeeker.Seek(-(endOfCDRecordSize + zip64EndOfCDRecordLocatorSize), io.SeekEnd)
		if err != nil {
			return reader, fmt.Errorf("readSeeker.Seek failed: %w", err)
		}

		zip64EndOfCDRecordLocator := Zip64EndOfCDRecordLocator{}
		err = binary.Read(readSeeker, binary.LittleEndian, &zip64EndOfCDRecordLocator)
		if err != nil {
			return reader, fmt.Errorf("binary.Read failed: %w", err)
		}

		if zip64EndOfCDRecordLocator.Signature != zip64EndOfCDLocatorSignature {
			return reader, errZipFormat
		}

		// read zip64 end of central directory record. It follows the central
		// directory, so it is bounded by the archive rather than cdStart.
		zip64EndOfCD, err := archive.offset("zip64 end of central directory record",
			zip64EndOfCDRecordLocator.CDOffset, 0)
		if err != nil {
			return reader, err
		}

		_, err = readSeeker.Seek(zip64EndOfCD, io.SeekStart)
		if err != nil {
			return reader, fmt.Errorf("readSeeker.Seek failed: %w", err)
		}

		zip64EndOfCDRecord := Zip64EndOfCDRecord{}
		err = binary.Read(readSeeker, binary.LittleEndian, &zip64EndOfCDRecord)
		if err != nil {
			return reader, fmt.Errorf("binary.Read failed: %w", err)
		}

		if zip64EndOfCDRecord.Signature != zip64EndOfCDSignature {
			return reader, errZipFormat
		}

		entryCount = zip64EndOfCDRecord.NumberOfCDRecordEntries
		centralDirectoryStart = zip64EndOfCDRecord.StartingDiskCentralDirectoryOffset
	}

	// Local file headers and file data precede the central directory, so its
	// start is their bound. It is read off disk too, so check it first.
	cdStart, err := archive.narrow(boundCDStart, centralDirectoryStart)
	if err != nil {
		return reader, err
	}

	// Each central directory record is at least cdFileHeaderSize bytes, so a
	// larger count is impossible. This is an early-out, not what makes the loop
	// safe; the per-entry offset and signature checks already stop the walk.
	if maxEntries := archive.limit / cdFileHeaderSize; entryCount > maxEntries {
		return reader, fmt.Errorf(
			"%w: %d central directory entries declared, but a %d byte archive has room for at most %d",
			errZipFormat, entryCount, archive.limit, maxEntries)
	}

	nextCD := uint64(0)
	cdFileHeader := CDFileHeader{}
	// Deflated entries share one archive/zip view, built on first use.
	view := &zipView{rs: readSeeker}

	reader.readSeeker = readSeeker
	for i := uint64(0); i < entryCount; i++ {
		// read central directory header of index(i)
		cdEntryStart, err := archive.offset("central directory entry", centralDirectoryStart, nextCD)
		if err != nil {
			return reader, err
		}

		_, err = readSeeker.Seek(cdEntryStart, io.SeekStart)
		if err != nil {
			return reader, fmt.Errorf("readSeeker.Seek failed: %w", err)
		}

		err = binary.Read(readSeeker, binary.LittleEndian, &cdFileHeader)
		if err != nil {
			return reader, fmt.Errorf("binary.Read failed: %w", err)
		}

		if cdFileHeader.Signature != centralDirectoryHeaderSignature {
			return reader, errZipFormat
		}

		// read the filename
		fileNameByteArray := make([]byte, cdFileHeader.FilenameLength)
		err = binary.Read(readSeeker, binary.LittleEndian, fileNameByteArray)
		if err != nil {
			return reader, fmt.Errorf("binary.Read failed: %w", err)
		}

		// readSeeker is now positioned at this entry's extra-field area.
		offset, bytesToRead, uncompressedSize, err := resolveEntryLocation(readSeeker, cdFileHeader)
		if err != nil {
			return reader, err
		}

		// Read each file
		localFileHeader := LocalFileHeader{}
		localHeaderStart, err := cdStart.offset("local file header", offset, 0)
		if err != nil {
			return reader, err
		}

		_, err = readSeeker.Seek(localHeaderStart, io.SeekStart)
		if err != nil {
			return reader, fmt.Errorf("readSeeker.Seek failed: %w", err)
		}
		err = binary.Read(readSeeker, binary.LittleEndian, &localFileHeader)
		if err != nil {
			return reader, fmt.Errorf("binary.Read failed: %w", err)
		}

		if localFileHeader.Signature != fileHeaderSignature {
			return reader, errZipFormatFileHeader
		}

		// The local header's own filename and extra-field lengths are
		// authoritative here; the central directory copies may differ.
		dataStart, err := cdStart.offset("file data start", offset,
			localFileHeaderSize+uint64(localFileHeader.FilenameLength)+uint64(localFileHeader.ExtraFieldLength))
		if err != nil {
			return reader, err
		}

		// bytesToRead is untrusted. Bound it by the central directory, not EOF:
		// an EOF bound would let a forged size cover the central directory,
		// which ReadAllFileData would return as file content. Taking length as
		// the difference of two bounded positions keeps it non-negative.
		dataEnd, err := cdStart.offset("file data", uint64(dataStart), bytesToRead)
		if err != nil {
			return reader, err
		}

		name := string(fileNameByteArray)
		entry, err := newZipFileEntry(view, name, cdFileHeader.CompressionMethod,
			dataStart, dataEnd-dataStart, uncompressedSize)
		if err != nil {
			return reader, err
		}
		reader.fileEntries[name] = entry

		// Widen every term before summing: all three header lengths are
		// uint16, so adding them at their declared width wraps at 65536 and
		// lands the next seek inside the current entry. The file comment is
		// part of the record too -- omitting it desyncs every entry after
		// the first one that carries a comment.
		nextCD += uint64(cdFileHeaderSize) +
			uint64(cdFileHeader.FilenameLength) +
			uint64(cdFileHeader.ExtraFieldLength) +
			uint64(cdFileHeader.FileCommentLength)
	}

	return reader, nil
}

// newZipFileEntry records an entry whose compressed data spans length bytes
// at index. The compression method is checked here, as the archive is opened,
// so an archive that cannot be read fails before anything is decrypted.
//
// STORED entries keep their established behavior: the stored length is the
// entry's size, whatever the declared uncompressed size says, and they never
// touch view.
func newZipFileEntry(view *zipView, name string, method uint16, index, length int64, uncompressedSize uint64) (zipFileEntry, error) {
	entry := zipFileEntry{index: index, length: length}
	switch method {
	case zip.Store:
		entry.size = length
	case zip.Deflate:
		size, err := deflatedSize(name, uncompressedSize)
		if err != nil {
			return zipFileEntry{}, err
		}
		entry.size = size
		entry.deflated = &deflatedFile{view: view, name: name, index: index, length: length, size: size}
	default:
		return zipFileEntry{}, unsupportedCompressionError(name, method)
	}
	return entry, nil
}

// Names of the limits offsets are measured against, for error messages.
const (
	boundArchiveEnd = "end of the archive"
	boundCDStart    = "start of the central directory"
)

// bound is a named limit inside the archive. Construct one only via
// archiveBound or narrow; offset also rejects a limit above MaxInt64, so a
// stray literal cannot make its int64 conversion unsafe.
type bound struct {
	name  string
	limit uint64
}

// archiveBound derives the outermost bound from the offset of the end of
// central directory record. The guard is against an io.ReadSeeker reporting a
// negative position or one whose record end would exceed MaxInt64.
func archiveBound(eocdStart int64) (bound, error) {
	if eocdStart < 0 || eocdStart > math.MaxInt64-endOfCDRecordSize {
		return bound{}, fmt.Errorf(
			"%w: readSeeker reported an implausible end of central directory offset %d",
			errZipFormat, eocdStart)
	}
	return bound{name: boundArchiveEnd, limit: uint64(eocdStart) + endOfCDRecordSize}, nil
}

// narrow returns a bound named name at limit, refusing one past b.
func (b bound) narrow(name string, limit uint64) (bound, error) {
	if limit > b.limit {
		return bound{}, fmt.Errorf("%w: %s at %d lies past the %s at %d",
			errZipFormat, name, limit, b.name, b.limit)
	}
	return bound{name: name, limit: limit}, nil
}

// offset returns base+delta as an int64 if it lies within b; field names what
// is being located, for the error message. With b.limit <= MaxInt64, passing
// the check guarantees a non-negative int64, and the subtraction keeps the
// addition from wrapping before it is checked.
//
// The comparison is inclusive because the last entry's data legitimately ends
// exactly at the central directory (see TestWriterManifestEndsAtCentralDirectory).
// Only the start position is checked, so callers reading a record there rely on
// the following binary.Read and signature check to reject a truncated or
// misplaced one.
func (b bound) offset(field string, base, delta uint64) (int64, error) {
	if b.limit > math.MaxInt64 || base > b.limit || delta > b.limit-base {
		return 0, fmt.Errorf("%w: %s at %d+%d runs past the %s at %d",
			errZipFormat, field, base, delta, b.name, b.limit)
	}
	return int64(base + delta), nil
}

// resolveEntryLocation returns the local header offset, the number of stored
// (compressed) bytes, and the declared uncompressed size for a central
// directory entry, reading the ZIP64 extended information extra field when the
// 32-bit fields carry the sentinel.
//
// That field is a property of the entry, not of the archive: APPNOTE permits
// one on an entry whose EOCD is not ZIP64, so the lookup is driven off this
// entry's own sentinel values rather than an archive-wide flag. The reader
// must be positioned at the start of the entry's extra-field area, and the
// area is only consumed when the entry declares one -- reading
// unconditionally would eat the bytes of whatever record follows.
func resolveEntryLocation(readSeeker io.Reader, cdFileHeader CDFileHeader) (uint64, uint64, uint64, error) {
	offset := uint64(cdFileHeader.LocalHeaderOffset)
	bytesToRead := uint64(cdFileHeader.CompressedSize)
	uncompressedSize := uint64(cdFileHeader.UncompressedSize)

	if cdFileHeader.ExtraFieldLength == 0 || !cdHeaderHasZip64Sentinel(cdFileHeader) {
		return offset, bytesToRead, uncompressedSize, nil
	}

	extraFields := make([]byte, cdFileHeader.ExtraFieldLength)
	if _, err := io.ReadFull(readSeeker, extraFields); err != nil {
		return 0, 0, 0, fmt.Errorf("io.ReadFull failed: %w", err)
	}

	zip64, err := parseZip64ExtraField(extraFields, cdFileHeader)
	if err != nil {
		return 0, 0, 0, err
	}

	if zip64.found {
		if cdFileHeader.UncompressedSize == zip64MagicVal {
			uncompressedSize = zip64.uncompressedSize
		}
		if cdFileHeader.CompressedSize == zip64MagicVal {
			bytesToRead = zip64.compressedSize
		}
		if cdFileHeader.LocalHeaderOffset == zip64MagicVal {
			offset = zip64.localHeaderOffset
		}
	}

	return offset, bytesToRead, uncompressedSize, nil
}

// eocdNeedsZip64 reports whether the end of central directory record defers
// any of its fields to the ZIP64 end of central directory record. Note the
// entry count is two bytes wide, so it uses a 16-bit sentinel.
func eocdNeedsZip64(eocd EndOfCDRecord) bool {
	return eocd.CentralDirectoryOffset == zip64MagicVal ||
		eocd.SizeOfCentralDirectory == zip64MagicVal ||
		eocd.NumberOfCDRecordEntries == zip64MagicVal16
}

// cdHeaderHasZip64Sentinel reports whether any central directory field of
// this entry defers its value to a ZIP64 extended information extra field.
func cdHeaderHasZip64Sentinel(h CDFileHeader) bool {
	return h.CompressedSize == zip64MagicVal ||
		h.UncompressedSize == zip64MagicVal ||
		h.LocalHeaderOffset == zip64MagicVal
}

// zip64ExtraValues holds the values a ZIP64 Extended Information extra
// field supplies for one central directory entry. Only the fields whose
// central directory counterpart carried the sentinel are populated.
type zip64ExtraValues struct {
	found             bool
	uncompressedSize  uint64
	compressedSize    uint64
	localHeaderOffset uint64
}

// parseZip64ExtraField walks the whole extra-field area of a central
// directory entry looking for the ZIP64 Extended Information field
// (0x0001). The field is not required to come first -- a Unix timestamp or
// NTFS field frequently precedes it -- so the area has to be iterated
// rather than probed at its head.
//
// Within the field the values appear in APPNOTE 4.5.3 order: original
// (uncompressed) size, compressed size, then local header offset. Each is
// present only when the matching central directory field holds the
// 0xFFFFFFFF sentinel. Reading the compressed size first would hand back the
// wrong value for any entry where the two differ, which every deflated entry
// does.
func parseZip64ExtraField(extraFields []byte, h CDFileHeader) (zip64ExtraValues, error) {
	var values zip64ExtraValues

	for pos := 0; pos+extraFieldHeaderSize <= len(extraFields); {
		tag := binary.LittleEndian.Uint16(extraFields[pos:])
		size := int(binary.LittleEndian.Uint16(extraFields[pos+2:]))
		pos += extraFieldHeaderSize

		if size > len(extraFields)-pos {
			// A field claiming to run past the end of the area is
			// malformed; there is nothing sane to resync to.
			return values, errZipFormat
		}

		if tag != zip64ExternalID {
			pos += size
			continue
		}

		body := extraFields[pos : pos+size]
		bodyPos := 0
		read := func() (uint64, bool) {
			const uint64Size = 8
			if bodyPos+uint64Size > len(body) {
				return 0, false
			}
			v := binary.LittleEndian.Uint64(body[bodyPos:])
			bodyPos += uint64Size
			return v, true
		}

		if h.UncompressedSize == zip64MagicVal {
			v, ok := read()
			if !ok {
				return values, errZipFormat
			}
			values.uncompressedSize = v
		}
		if h.CompressedSize == zip64MagicVal {
			v, ok := read()
			if !ok {
				return values, errZipFormat
			}
			values.compressedSize = v
		}
		if h.LocalHeaderOffset == zip64MagicVal {
			v, ok := read()
			if !ok {
				return values, errZipFormat
			}
			values.localHeaderOffset = v
		}

		values.found = true
		return values, nil
	}

	return values, nil
}

// ReadFileData Read data from file of given length of size.
//
// index and length are in uncompressed coordinates. A read that reaches the
// end of a deflated entry also has archive/zip check that the data ends there
// and that its CRC-32 matches.
func (reader Reader) ReadFileData(filename string, index int64, length int64) ([]byte, error) {
	fileNameEntry, ok := reader.fileEntries[filename]
	if !ok {
		return nil, errZipFileNotFound
	}

	// index comes from manifest segment sizes, so it must be bounded as well as
	// length. The length clauses run first, so the subtraction cannot go
	// negative.
	if length < 0 || length > fileNameEntry.size ||
		index < 0 || index > fileNameEntry.size-length {
		return nil, fmt.Errorf("%w: %s: read of %d bytes at %d does not fit an entry of %d bytes",
			errZipFileSizeError, filename, length, index, fileNameEntry.size)
	}

	// There is no override here. Payload ciphertext does not compress, so a
	// legitimate deflated payload never declares more than the archive holds;
	// and archive/zip stops one byte past the declared size, so bounding it
	// bounds inflation.
	if fileNameEntry.deflated != nil && fileNameEntry.size > reader.inflateBudget {
		return nil, inflateBudgetError(filename, fileNameEntry.size, reader.inflateBudget,
			"a deflated payload cannot be larger than its archive")
	}

	// An empty read of a deflated entry needs no data; producing it by
	// inflating up to index would be wasted work. One at the declared end
	// still goes through, since reaching the end is what checks it.
	if fileNameEntry.deflated != nil && length == 0 && index != fileNameEntry.size {
		return []byte{}, nil
	}

	reader.mu.Lock()
	defer reader.mu.Unlock()
	if fileNameEntry.deflated != nil {
		return fileNameEntry.deflated.read(index, length)
	}
	return readBytes(reader.readSeeker, fileNameEntry.index+index, length)
}

// ReadAllFileData Return all the data of the file if the file is available and below the specified size.
// NOTE: Use this method for small file sizes.
//
// maxSize applies to the uncompressed size, and is checked before any data
// is read. math.MaxInt64, which is what TDFReader passes when no manifest size
// limit is configured, means no explicit limit: a deflated entry is then held
// to the Reader's inflation budget instead. Any other maxSize applies as given,
// even above the budget; that is how a caller admits a legitimately large
// deflated manifest.
func (reader Reader) ReadAllFileData(filename string, maxSize int64) ([]byte, error) {
	fileNameEntry, ok := reader.fileEntries[filename]
	if !ok {
		return nil, errZipFileNotFound
	}
	if fileNameEntry.size > maxSize {
		return nil, fmt.Errorf("%s size too large: %d KiB", filename, fileNameEntry.size/1024) //nolint:mnd // convert byte->kb
	}
	if fileNameEntry.deflated != nil && maxSize == math.MaxInt64 && fileNameEntry.size > reader.inflateBudget {
		return nil, inflateBudgetError(filename, fileNameEntry.size, reader.inflateBudget,
			"set an explicit manifest size limit to read it")
	}

	reader.mu.Lock()
	defer reader.mu.Unlock()
	if fileNameEntry.deflated != nil {
		return fileNameEntry.deflated.readAll()
	}
	return readBytes(reader.readSeeker, fileNameEntry.index, fileNameEntry.length)
}

// ReadFileSize Return the file size of the filename. For a deflated entry
// this is its declared uncompressed size.
func (reader Reader) ReadFileSize(filename string) (int64, error) {
	fileNameEntry, ok := reader.fileEntries[filename]
	if !ok {
		return -1, errZipFileNotFound
	}

	return fileNameEntry.size, nil
}

// readBytes reads exactly size bytes at index, or fails.
// Unlike most golang io read methods, this function leaves
// the byte array empty on error states to simplify reader logic.
func readBytes(readerSeeker io.ReadSeeker, index, size int64) ([]byte, error) {
	if _, err := readerSeeker.Seek(index, io.SeekStart); err != nil {
		return nil, fmt.Errorf("readerSeeker.Seek failed: %w", err)
	}

	buf := make([]byte, size)
	if _, err := io.ReadFull(readerSeeker, buf); err != nil {
		// Promote io.EOF to io.ErrUnexpectedEOF
		// due to short (e.g. incorrect CD) archive files.
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, fmt.Errorf("reading %d bytes at %d failed: %w", size, index, err)
	}

	return buf, nil
}
