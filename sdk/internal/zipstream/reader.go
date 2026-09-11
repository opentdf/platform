// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package zipstream

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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

type ZipFileEntry struct {
	index  int64
	length int64
}

type Reader struct {
	readSeeker  io.ReadSeeker
	fileEntries map[string]ZipFileEntry
}

// NewReader Create archive reader instance.
func NewReader(readSeeker io.ReadSeeker) (Reader, error) {
	reader := Reader{}
	reader.fileEntries = make(map[string]ZipFileEntry)

	// read end of central directory record
	_, err := readSeeker.Seek(-endOfCDRecordSize, io.SeekEnd)
	if err != nil {
		return reader, fmt.Errorf("readSeeker.Seek failed: %w", err)
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

		// read zip64 end of central directory record
		_, err = readSeeker.Seek(int64(zip64EndOfCDRecordLocator.CDOffset), io.SeekStart)
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

	nextCD := uint64(0)
	cdFileHeader := CDFileHeader{}

	reader.readSeeker = readSeeker
	for i := uint64(0); i < entryCount; i++ {
		// read central directory header of index(i)
		_, err = readSeeker.Seek(int64(nextCD+centralDirectoryStart), io.SeekStart)
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
		_, err = readSeeker.Seek(int64(offset), io.SeekStart)
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

		zipFileEntry := ZipFileEntry{}
		zipFileEntry.length = int64(bytesToRead)
		zipFileEntry.index = int64(offset) + localFileHeaderSize +
			int64(localFileHeader.FilenameLength) + int64(localFileHeader.ExtraFieldLength)

		reader.fileEntries[string(fileNameByteArray)] = zipFileEntry

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

	if length < 0 || length > fileNameEntry.length {
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

// Read bytes reads up to size from input providers
// and return the buffer with the read bytes.
func readBytes(readerSeeker io.ReadSeeker, index, size int64) ([]byte, error) {
	_, err := readerSeeker.Seek(index, 0)
	if err != nil {
		return nil, fmt.Errorf("readerSeeker.Seek failed: %w", err)
	}

	buf := make([]byte, size)
	n, err := readerSeeker.Read(buf)
	if errors.Is(err, io.EOF) {
		return buf[:n], io.EOF
	}

	if err != nil {
		return buf[:n], fmt.Errorf("readerSeeker.Read failed: %w", err)
	}

	return buf, nil
}
