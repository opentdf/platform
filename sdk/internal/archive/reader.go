package archive

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
	var entryCount uint64
	var centralDirectoryStart uint64
	isZip64 := false
	if endOfCDRecord.CentralDirectoryOffset != zip64MagicVal { //nolint:nestif // pkzip is complicated
		entryCount = uint64(endOfCDRecord.NumberOfCDRecordEntries)
		centralDirectoryStart = uint64(endOfCDRecord.CentralDirectoryOffset)
	} else {
		isZip64 = true

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

		offset := uint64(cdFileHeader.LocalHeaderOffset)
		bytesToRead := uint64(cdFileHeader.CompressedSize)

		if isZip64 { //nolint:nestif // pkzip is complicated
			// read Zip64 Extended Information extra field id
			headerTag := uint16(0)
			err = binary.Read(readSeeker, binary.LittleEndian, &headerTag)
			if err != nil {
				return reader, fmt.Errorf("binary.Read failed: %w", err)
			}

			// read Zip64 Extended Information Extra Field Block Size
			blockSize := uint16(0)
			err = binary.Read(readSeeker, binary.LittleEndian, &blockSize)
			if err != nil {
				return reader, fmt.Errorf("binary.Read failed: %w", err)
			}

			if headerTag == zip64ExternalID {
				if cdFileHeader.CompressedSize == zip64MagicVal {
					compressedSize := uint64(0)
					err = binary.Read(readSeeker, binary.LittleEndian, &compressedSize)
					if err != nil {
						return reader, fmt.Errorf("binary.Read failed: %w", err)
					}

					bytesToRead = compressedSize
				}

				if cdFileHeader.UncompressedSize == zip64MagicVal {
					uncompressedSize := uint64(0)
					err = binary.Read(readSeeker, binary.LittleEndian, &uncompressedSize)
					if err != nil {
						return reader, fmt.Errorf("binary.Read failed: %w", err)
					}
				}

				if cdFileHeader.LocalHeaderOffset == zip64MagicVal {
					localHeaderOffset := uint64(0)
					err = binary.Read(readSeeker, binary.LittleEndian, &localHeaderOffset)
					if err != nil {
						return reader, fmt.Errorf("binary.Read failed: %w", err)
					}
					offset = localHeaderOffset
				}
			}
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

		nextCD += uint64(cdFileHeader.ExtraFieldLength + cdFileHeader.FilenameLength + cdFileHeaderSize)
	}

	return reader, nil
}

// ReadFileData Read data from file of given length of size.
func (reader Reader) ReadFileData(filename string, index int64, length int64) ([]byte, error) {
	fileNameEntry, ok := reader.fileEntries[filename]
	if !ok {
		return nil, errZipFileNotFound
	}

	if length > fileNameEntry.length {
		return nil, errZipFileSizeError
	}

	return readBytes(reader.readSeeker, fileNameEntry.index+index, length)
}

// ReadAllFileData Return all the data of the file
// NOTE: Use this method for small file sizes.
func (reader Reader) ReadAllFileData(filename string) ([]byte, error) {
	fileNameEntry, ok := reader.fileEntries[filename]
	if !ok {
		return nil, errZipFileNotFound
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
