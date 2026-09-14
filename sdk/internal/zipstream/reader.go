// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package zipstream

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
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

// zipFileEntry locates one entry's stored bytes. Both fields are signed
// because every consumer is -- io.ReadSeeker.Seek, make(), and the int64 the
// exported methods hand back.
//
// A holder may rely on index and length being non-negative and on index+length
// addressing bytes inside the archive. NewReader, the only producer, places
// that range at or before the start of the central directory as well, since
// that is where all file data lives.
type zipFileEntry struct {
	index  int64
	length int64
}

type Reader struct {
	readSeeker  io.ReadSeeker
	fileEntries map[string]zipFileEntry
}

// NewReader Create archive reader instance.
func NewReader(readSeeker io.ReadSeeker) (Reader, error) {
	reader := Reader{}
	reader.fileEntries = make(map[string]zipFileEntry)

	// The seek that positions us at the end of central directory record also
	// reports the archive length, which becomes the outermost bound below: the
	// offsets and sizes this function goes on to read are 64-bit values taken
	// straight off disk, and nothing else in the file constrains them.
	//
	// Records at or after the central directory -- the ZIP64 end of central
	// directory record and the central directory entries themselves -- are
	// measured against that length. Local file headers and file data, which
	// must precede the central directory, get the tighter cdStart below.
	eocdStart, err := readSeeker.Seek(-endOfCDRecordSize, io.SeekEnd)
	if err != nil {
		return reader, fmt.Errorf("readSeeker.Seek failed: %w", err)
	}
	archive, err := archiveBound(eocdStart)
	if err != nil {
		return reader, err
	}

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

		// read zip64 end of central directory record. This one is bounded by
		// the archive and not by the central directory: it sits after it, and
		// centralDirectoryStart is what this record is being read to find.
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

	// Every local file header and every byte of file data precedes the central
	// directory, so centralDirectoryStart -- not the archive length -- is the
	// bound for each of them below. It is itself a raw uint64 off disk, so it
	// has to be placed inside the archive before it can serve as a limit.
	cdStart, err := archive.narrow(boundCDStart, centralDirectoryStart)
	if err != nil {
		return reader, err
	}

	// Every central directory record is at least cdFileHeaderSize bytes, so an
	// archive cannot hold more entries than it has room for. This is an
	// early-out on an impossible ZIP64 count rather than the bound that makes
	// the loop safe: the offset check below already caps iterations at the same
	// archive/cdFileHeaderSize, and the signature check stops the walk on the
	// first record that does not parse.
	if maxEntries := archive.limit / cdFileHeaderSize; entryCount > maxEntries {
		return reader, fmt.Errorf(
			"%w: %d central directory entries declared, but a %d byte archive has room for at most %d",
			errZipFormat, entryCount, archive.limit, maxEntries)
	}

	nextCD := uint64(0)
	cdFileHeader := CDFileHeader{}

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
		offset, bytesToRead, err := resolveEntryLocation(readSeeker, cdFileHeader)
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
			return reader, fmt.Errorf("readSeeker.Seek failed: %w", err)
		}

		if localFileHeader.Signature != fileHeaderSignature {
			return reader, errZipFormatFileHeader
		}

		// The data starts after the local header, whose own filename and
		// extra-field lengths are authoritative here -- the central directory
		// copies are allowed to differ.
		dataStart, err := cdStart.offset("file data start", offset,
			localFileHeaderSize+uint64(localFileHeader.FilenameLength)+uint64(localFileHeader.ExtraFieldLength))
		if err != nil {
			return reader, err
		}

		// bytesToRead is a ZIP64 value read off disk, so it is bounded here
		// rather than trusted. Nothing downstream checks its sign:
		// ReadAllFileData only compares the length against maxSize, which a
		// negative value passes, and readBytes then panics in
		// make([]byte, size). Deriving length from two bounded positions keeps
		// every conversion inside offset.
		//
		// The bound is the central directory rather than the end of the
		// archive. Stopping at EOF would still let a forged size swallow the
		// central directory and the EOCD, and ReadAllFileData would hand that
		// ZIP metadata back as file content.
		dataEnd, err := cdStart.offset("file data", uint64(dataStart), bytesToRead)
		if err != nil {
			return reader, err
		}

		reader.fileEntries[string(fileNameByteArray)] = zipFileEntry{
			index:  dataStart,
			length: dataEnd - dataStart,
		}

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

// The two limits every offset in an archive is measured against, named for the
// error messages they appear in.
const (
	boundArchiveEnd = "end of the archive"
	boundCDStart    = "start of the central directory"
)

// bound is a limit already known to lie inside the archive, and so to fit in
// an int64. That precondition is what makes offset's conversion safe, so the
// only ways to obtain a bound are archiveBound, which derives one from a length
// the io.ReadSeeker reported, and narrow, which cannot widen one. A raw uint64
// read off disk cannot become a limit without passing through narrow.
//
// Carrying the name alongside the limit keeps the two from being paired up by
// hand at each call site, where a mismatch would yield a correct check
// reporting the wrong reason.
type bound struct {
	name  string
	limit uint64
}

// archiveBound derives the outermost bound from the offset of the end of
// central directory record.
//
// The guard is against a hostile io.ReadSeeker rather than a hostile file: a
// Seek reporting a negative position, or one large enough that adding the
// record size pushes the total above MaxInt64, would break the invariant every
// bound below depends on.
func archiveBound(eocdStart int64) (bound, error) {
	if eocdStart < 0 || eocdStart > math.MaxInt64-endOfCDRecordSize {
		return bound{}, fmt.Errorf(
			"%w: readSeeker reported an implausible end of central directory offset %d",
			errZipFormat, eocdStart)
	}
	return bound{name: boundArchiveEnd, limit: uint64(eocdStart) + endOfCDRecordSize}, nil
}

// narrow returns a tighter bound named for limit, refusing one that does not
// fit inside b. This is the only way a value read off disk becomes usable as a
// limit.
func (b bound) narrow(name string, limit uint64) (bound, error) {
	if limit > b.limit {
		return bound{}, fmt.Errorf("%w: %s at %d lies past the %s at %d",
			errZipFormat, name, limit, b.name, b.limit)
	}
	return bound{name: name, limit: limit}, nil
}

// offset bounds the position base+delta against b and returns it as a seek
// offset. field names what is being located, for the error message.
//
// A single check rules out both hazards a 64-bit value off disk presents: one
// above MaxInt64, which would narrow to a negative seek or a negative make()
// that panics, and one merely past the limit, which addresses bytes belonging
// to another record. Because b.limit is at most the archive length and so at
// most MaxInt64, base+delta <= b.limit implies the sum is a non-negative
// int64. The remaining space is computed by subtraction so the addition cannot
// wrap before it is checked.
//
// The comparison is inclusive because in any conformant archive the last
// entry's data abuts the central directory, so a range ending exactly on its
// limit is well-formed. Every archive this package emits is such a case --
// Finalize places the central directory on the byte immediately after the
// manifest data -- and a strict comparison would reject all of them, along
// with the equivalent archives from the java and js SDKs.
//
// A delta of 0 bounds only the first byte of what follows. Callers reading a
// multi-byte record there rely on the subsequent binary.Read to catch a record
// the end of the archive truncates.
func (b bound) offset(field string, base, delta uint64) (int64, error) {
	if base > b.limit || delta > b.limit-base {
		return 0, fmt.Errorf("%w: %s at %d+%d runs past the %s at %d",
			errZipFormat, field, base, delta, b.name, b.limit)
	}
	return int64(base + delta), nil
}

// resolveEntryLocation returns the local header offset and the number of
// stored bytes for a central directory entry, reading the ZIP64 extended
// information extra field when the 32-bit fields carry the sentinel.
//
// That field is a property of the entry, not of the archive: APPNOTE permits
// one on an entry whose EOCD is not ZIP64, so the lookup is driven off this
// entry's own sentinel values rather than an archive-wide flag. The reader
// must be positioned at the start of the entry's extra-field area, and the
// area is only consumed when the entry declares one -- reading
// unconditionally would eat the bytes of whatever record follows.
func resolveEntryLocation(readSeeker io.Reader, cdFileHeader CDFileHeader) (uint64, uint64, error) {
	offset := uint64(cdFileHeader.LocalHeaderOffset)
	bytesToRead := uint64(cdFileHeader.CompressedSize)

	if cdFileHeader.ExtraFieldLength == 0 || !cdHeaderHasZip64Sentinel(cdFileHeader) {
		return offset, bytesToRead, nil
	}

	extraFields := make([]byte, cdFileHeader.ExtraFieldLength)
	if _, err := io.ReadFull(readSeeker, extraFields); err != nil {
		return 0, 0, fmt.Errorf("io.ReadFull failed: %w", err)
	}

	zip64, err := parseZip64ExtraField(extraFields, cdFileHeader)
	if err != nil {
		return 0, 0, err
	}

	if zip64.found {
		if cdFileHeader.CompressedSize == zip64MagicVal {
			bytesToRead = zip64.compressedSize
		}
		if cdFileHeader.LocalHeaderOffset == zip64MagicVal {
			offset = zip64.localHeaderOffset
		}
	}

	return offset, bytesToRead, nil
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
// 0xFFFFFFFF sentinel, so the uncompressed size has to be stepped over even
// though nothing here consumes it -- reading the compressed size first
// would hand back the wrong value for any entry where the two differ.
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
			if _, ok := read(); !ok {
				return values, errZipFormat
			}
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
func (reader Reader) ReadFileData(filename string, index int64, length int64) ([]byte, error) {
	fileNameEntry, ok := reader.fileEntries[filename]
	if !ok {
		return nil, errZipFileNotFound
	}

	// index is caller-supplied and, for a TDF, accumulated from the segment
	// sizes the manifest declares -- so bounding the length alone leaves a
	// manifest free to walk the offset off the end of the entry and read
	// whatever the archive stores next. The length clauses run first, so the
	// subtraction on the right cannot go negative.
	if length < 0 || length > fileNameEntry.length ||
		index < 0 || index > fileNameEntry.length-length {
		return nil, errZipFileSizeError
	}

	return readBytes(reader.readSeeker, fileNameEntry.index+index, length)
}

// ReadAllFileData Return all the data of the file if the file is available and below the specified size.
// NOTE: Use this method for small file sizes.
func (reader Reader) ReadAllFileData(filename string, maxSize int64) ([]byte, error) {
	fileNameEntry, ok := reader.fileEntries[filename]
	if !ok {
		return nil, errZipFileNotFound
	}
	if fileNameEntry.length > maxSize {
		return nil, fmt.Errorf("%s size too large: %d KiB", filename, fileNameEntry.length/1024) //nolint:mnd // convert byte->kb
	}

	return readBytes(reader.readSeeker, fileNameEntry.index, fileNameEntry.length)
}

// ReadFileSize Return the file size of the filename.
func (reader Reader) ReadFileSize(filename string) (int64, error) {
	fileNameEntry, ok := reader.fileEntries[filename]
	if !ok {
		return -1, errZipFileNotFound
	}

	return fileNameEntry.length, nil
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
