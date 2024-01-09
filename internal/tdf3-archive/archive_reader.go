package tdf3_archiver

import (
	"bytes"
	"encoding/binary"
	"errors"
	"unsafe"
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
	errInputProvider       = errors.New("InputProvider: not a valid input provider")
	errZipFormat           = errors.New("zip: not a valid zip file")
	errZipFileNotFound     = errors.New("zip: file not found")
	errZipFileSizeError    = errors.New("zip: not a valid file size")
	errZipFormatFileHeader = errors.New("zip: unable to read local file header")
)

type ZipFileEntry struct {
	index  int64
	length int64
}

type IArchiveReader interface {
	ReadFileData(string, int64, int64) ([]byte, error)
	ReadAllFileData(string) ([]byte, error)
	ReadFileSize(string) (int64, error)
}

type ArchiveReader struct {
	inputProvider IInputProvider
	fileEntries   map[string]ZipFileEntry
}

// CreateArchiveReader Create archive reader instance
func CreateArchiveReader(inputProvider IInputProvider) (ArchiveReader, error) {

	archiveReader := ArchiveReader{}
	archiveReader.fileEntries = make(map[string]ZipFileEntry)

	fileSize := inputProvider.GetSize()
	if fileSize <= 0 {
		return archiveReader, errInputProvider
	}

	// read end of central directory record
	index := fileSize - endOfCDRecordSize
	buf, err := inputProvider.ReadBytes(index, endOfCDRecordSize)
	if err != nil {
		return archiveReader, err
	}

	endOfCDRecord := EndOfCDRecord{}
	err = binary.Read(bytes.NewBuffer(buf[:]), binary.LittleEndian, &endOfCDRecord)
	if err != nil {
		return archiveReader, err
	}

	// check if it's valid zip format
	if endOfCDRecord.Signature != endOfCentralDirectorySignature {
		return archiveReader, errZipFormat
	}

	// check if zip is zip64 or zip32 format
	var entryCount uint64
	var centralDirectoryStart uint64
	isZip64 := false
	if endOfCDRecord.CentralDirectoryOffset != zip64MagicVal {
		entryCount = uint64(endOfCDRecord.NumberOfCDRecordEntries)
		centralDirectoryStart = uint64(endOfCDRecord.CentralDirectoryOffset)
	} else {
		isZip64 = true

		// read zip64 end of central directory locator
		index = fileSize - (endOfCDRecordSize + zip64EndOfCDRecordLocatorSize)
		buf, err := inputProvider.ReadBytes(index, zip64EndOfCDRecordLocatorSize)
		if err != nil {
			return archiveReader, err
		}

		zip64EndOfCDRecordLocator := Zip64EndOfCDRecordLocator{}
		err = binary.Read(bytes.NewBuffer(buf[:]), binary.LittleEndian, &zip64EndOfCDRecordLocator)
		if err != nil {
			return archiveReader, err
		}

		if zip64EndOfCDRecordLocator.Signature != zip64EndOfCDLocatorSignature {
			return archiveReader, errZipFormat
		}

		// read zip64 end of central directory record
		buf, err = inputProvider.ReadBytes(int64(zip64EndOfCDRecordLocator.CDOffset), zip64EndOfCDRecordSize)
		if err != nil {
			return archiveReader, err
		}

		zip64EndOfCDRecord := Zip64EndOfCDRecord{}
		err = binary.Read(bytes.NewBuffer(buf[:]), binary.LittleEndian, &zip64EndOfCDRecord)
		if err != nil {
			return archiveReader, err
		}

		if zip64EndOfCDRecord.Signature != zip64EndOfCDSignature {
			return archiveReader, errZipFormat
		}

		entryCount = zip64EndOfCDRecord.NumberOfCDRecordEntries
		centralDirectoryStart = zip64EndOfCDRecord.StartingDiskCentralDirectoryOffset
	}

	nextCD := uint64(0)
	cdFileHeader := CDFileHeader{}

	archiveReader.inputProvider = inputProvider
	for i := uint64(0); i < entryCount; i++ {

		// read central directory header of index(i)
		index = int64(nextCD + centralDirectoryStart)
		buf, err = inputProvider.ReadBytes(index, cdFileHeaderSize)
		if err != nil {
			return archiveReader, err
		}

		err = binary.Read(bytes.NewBuffer(buf[:]), binary.LittleEndian, &cdFileHeader)
		if err != nil {
			return archiveReader, err
		}

		if cdFileHeader.Signature != centralDirectoryHeaderSignature {
			return archiveReader, errZipFormat
		}

		// read the filename
		fileNameByteArray := make([]byte, cdFileHeader.FilenameLength)
		index += cdFileHeaderSize
		buf, err = inputProvider.ReadBytes(index, int64(cdFileHeader.FilenameLength))
		if err != nil {
			return archiveReader, err
		}

		err = binary.Read(bytes.NewBuffer(buf[:]), binary.LittleEndian, fileNameByteArray)
		if err != nil {
			return archiveReader, err
		}

		offset := uint64(cdFileHeader.LocalHeaderOffset)
		bytesToRead := uint64(cdFileHeader.CompressedSize)

		if isZip64 {

			// read Zip64 Extended Information Extra Field Id
			headerTag := uint16(0)

			index += int64(cdFileHeader.FilenameLength)
			buf, err = inputProvider.ReadBytes(index, int64(unsafe.Sizeof(headerTag)))
			if err != nil {
				return archiveReader, err
			}

			err = binary.Read(bytes.NewBuffer(buf[:]), binary.LittleEndian, &headerTag)
			if err != nil {
				return archiveReader, err
			}

			// read Zip64 Extended Information Extra Field Block Size
			blockSize := uint16(0)

			index += int64(unsafe.Sizeof(blockSize))
			buf, err = inputProvider.ReadBytes(index, int64(unsafe.Sizeof(blockSize)))
			if err != nil {
				return archiveReader, err
			}

			err = binary.Read(bytes.NewBuffer(buf[:]), binary.LittleEndian, &blockSize)
			if err != nil {
				return archiveReader, err
			}

			if headerTag == zip64ExternalId {
				index += int64(unsafe.Sizeof(blockSize))

				if cdFileHeader.CompressedSize == zip64MagicVal {

					compressedSize := uint64(0)
					buf, err = inputProvider.ReadBytes(index, int64(unsafe.Sizeof(compressedSize)))
					if err != nil {
						return archiveReader, err
					}

					err = binary.Read(bytes.NewBuffer(buf[:]), binary.LittleEndian, &compressedSize)
					if err != nil {
						return archiveReader, err
					}

					bytesToRead = compressedSize
					index += int64(unsafe.Sizeof(compressedSize))
				}

				if cdFileHeader.UncompressedSize == zip64MagicVal {
					uncompressedSize := uint64(0)
					buf, err = inputProvider.ReadBytes(index, int64(unsafe.Sizeof(uncompressedSize)))
					if err != nil {
						return archiveReader, err
					}

					err = binary.Read(bytes.NewBuffer(buf[:]), binary.LittleEndian, &uncompressedSize)
					if err != nil {
						return archiveReader, err
					}

					index += int64(unsafe.Sizeof(uncompressedSize))
				}

				if cdFileHeader.LocalHeaderOffset == zip64MagicVal {
					localHeaderOffset := uint64(0)
					buf, err = inputProvider.ReadBytes(index, int64(unsafe.Sizeof(localHeaderOffset)))
					if err != nil {
						return archiveReader, err
					}

					err = binary.Read(bytes.NewBuffer(buf[:]), binary.LittleEndian, &localHeaderOffset)
					if err != nil {
						return archiveReader, err
					}

					offset = localHeaderOffset
				}
			}
		}

		// Read each file
		localFileHeader := LocalFileHeader{}
		buf, err := inputProvider.ReadBytes(int64(offset), int64(localFileHeaderSize))
		if err != nil {
			return archiveReader, err
		}

		err = binary.Read(bytes.NewBuffer(buf[:]), binary.LittleEndian, &localFileHeader)
		if err != nil {
			return archiveReader, err
		}

		if localFileHeader.Signature != fileHeaderSignature {
			return archiveReader, errZipFormatFileHeader
		}

		zipFileEntry := ZipFileEntry{}
		zipFileEntry.length = int64(bytesToRead)
		zipFileEntry.index = int64(offset) + localFileHeaderSize + int64(localFileHeader.FilenameLength) + int64(localFileHeader.ExtraFieldLength)

		archiveReader.fileEntries[string(fileNameByteArray)] = zipFileEntry

		nextCD += uint64(cdFileHeader.ExtraFieldLength + cdFileHeader.FilenameLength + cdFileHeaderSize)
	}

	return archiveReader, nil
}

// ReadFileData Read data from file of given length of size
func (archiveReader ArchiveReader) ReadFileData(filename string, index int64, length int64) ([]byte, error) {

	fileNameEntry, ok := archiveReader.fileEntries[filename]
	if !ok {
		return nil, errZipFileNotFound
	}

	if length > fileNameEntry.length {
		return nil, errZipFileSizeError
	}

	return archiveReader.inputProvider.ReadBytes(fileNameEntry.index+index, length)
}

// ReadAllFileData Return all the data of the file
// NOTE: Use this method for small file sizes
func (archiveReader ArchiveReader) ReadAllFileData(filename string) ([]byte, error) {
	fileNameEntry, ok := archiveReader.fileEntries[filename]
	if !ok {
		return nil, errZipFileNotFound
	}

	return archiveReader.inputProvider.ReadBytes(fileNameEntry.index, fileNameEntry.length)
}

// ReadFileSize Return the file size of the filename
func (archiveReader ArchiveReader) ReadFileSize(filename string) (int64, error) {
	fileNameEntry, ok := archiveReader.fileEntries[filename]
	if !ok {
		return -1, errZipFileNotFound
	}

	return fileNameEntry.length, nil
}
