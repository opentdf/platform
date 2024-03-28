package archive

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"time"
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

// Usage of IArchiveWriter interface:
//
// NOTE: Make sure write the largest file first so the implementation can decide zip32 vs zip64

type WriteState int

const (
	Initial WriteState = iota
	Appending
	Finished
)

type FileInfo struct {
	crc      uint32
	size     int64
	offset   int64
	filename string
	fileTime uint16
	fileDate uint16
	flag     uint16
}

type Writer struct {
	writer                                io.Writer
	currentOffset, lastOffsetCDFileHeader uint64
	FileInfo
	fileInfoEntries []FileInfo
	writeState      WriteState
	isZip64         bool
	totalBytes      int64
}

// NewWriter Create tdf3 writer instance.
func NewWriter(writer io.Writer) *Writer {
	archiveWriter := Writer{}

	archiveWriter.writer = writer
	archiveWriter.writeState = Initial
	archiveWriter.currentOffset = 0
	archiveWriter.lastOffsetCDFileHeader = 0
	archiveWriter.fileInfoEntries = make([]FileInfo, 0)

	return &archiveWriter
}

// EnableZip64 Enable zip 64.
func (writer *Writer) EnableZip64() {
	writer.isZip64 = true
}

// AddHeader set size of the file. calling this method means finished writing
// the previous file and starting a new file.
func (writer *Writer) AddHeader(filename string, size int64) error {
	if len(writer.FileInfo.filename) != 0 {
		err := fmt.Errorf("writer: cannot add a new file until the current "+
			"file write is not completed:%s", writer.FileInfo.filename)
		return err
	}

	if !writer.isZip64 {
		writer.isZip64 = size > zip64MagicVal
	}

	writer.writeState = Initial
	writer.FileInfo.size = size
	writer.FileInfo.filename = filename

	return nil
}

// AddData Add data to the zip archive.
func (writer *Writer) AddData(data []byte) error {
	localFileHeader := LocalFileHeader{}
	fileTime, fileDate := writer.getTimeDateUnMSDosFormat()

	if writer.writeState == Initial {
		localFileHeader.Signature = fileHeaderSignature
		localFileHeader.Version = zipVersion
		// since payload is added by chunks we set General purpose bit flag to 0x08
		localFileHeader.GeneralPurposeBitFlag = 0x08
		localFileHeader.CompressionMethod = 0 // no compression
		localFileHeader.LastModifiedTime = fileTime
		localFileHeader.LastModifiedDate = fileDate
		localFileHeader.Crc32 = 0

		localFileHeader.CompressedSize = 0
		localFileHeader.UncompressedSize = 0
		localFileHeader.ExtraFieldLength = 0

		if writer.isZip64 {
			localFileHeader.CompressedSize = zip64MagicVal
			localFileHeader.UncompressedSize = zip64MagicVal
			localFileHeader.ExtraFieldLength = zip64ExtendedLocalInfoExtraFieldSize
		}

		localFileHeader.FilenameLength = uint16(len(writer.FileInfo.filename))

		// write localFileHeader
		buf := new(bytes.Buffer)
		err := binary.Write(buf, binary.LittleEndian, localFileHeader)
		if err != nil {
			return fmt.Errorf("binary.Write failed: %w", err)
		}

		err = writer.writeData(buf.Bytes())
		if err != nil {
			return fmt.Errorf("io.Writer.Write failed: %w", err)
		}

		// write the file name
		err = writer.writeData([]byte(writer.FileInfo.filename))
		if err != nil {
			return fmt.Errorf("io.Writer.Write failed: %w", err)
		}

		if writer.isZip64 {
			zip64ExtendedLocalInfoExtraField := Zip64ExtendedLocalInfoExtraField{}
			zip64ExtendedLocalInfoExtraField.Signature = zip64ExternalID
			zip64ExtendedLocalInfoExtraField.Size = zip64ExtendedLocalInfoExtraFieldSize - 4
			zip64ExtendedLocalInfoExtraField.OriginalSize = uint64(writer.FileInfo.size)
			zip64ExtendedLocalInfoExtraField.CompressedSize = uint64(writer.FileInfo.size)

			buf = new(bytes.Buffer)
			err := binary.Write(buf, binary.LittleEndian, zip64ExtendedLocalInfoExtraField)
			if err != nil {
				return fmt.Errorf("binary.Write failed: %w", err)
			}

			err = writer.writeData(buf.Bytes())
			if err != nil {
				return fmt.Errorf("io.Writer.Write failed: %w", err)
			}
		}

		writer.writeState = Appending

		// calculate the initial crc
		writer.FileInfo.crc = crc32.Checksum([]byte(""), crc32.MakeTable(crc32.IEEE))
		writer.FileInfo.fileTime = fileTime
		writer.FileInfo.fileDate = fileDate
	}

	// now write the contents
	err := writer.writeData(data)
	if err != nil {
		return fmt.Errorf("io.Writer.Write failed: %w", err)
	}

	// calculate the crc32
	writer.FileInfo.crc = crc32.Update(writer.FileInfo.crc,
		crc32.MakeTable(crc32.IEEE), data)

	// update the file size
	writer.FileInfo.offset += int64(len(data))

	// check if we reached end
	if writer.FileInfo.offset >= writer.FileInfo.size {
		writer.writeState = Finished

		writer.FileInfo.offset = int64(writer.currentOffset)
		writer.FileInfo.flag = 0x08

		writer.fileInfoEntries = append(writer.fileInfoEntries, writer.FileInfo)
	}

	if writer.writeState == Finished {
		if writer.isZip64 {
			zip64DataDescriptor := Zip64DataDescriptor{}
			zip64DataDescriptor.Signature = dataDescriptorSignature
			zip64DataDescriptor.Crc32 = writer.FileInfo.crc
			zip64DataDescriptor.CompressedSize = uint64(writer.FileInfo.size)
			zip64DataDescriptor.UncompressedSize = uint64(writer.FileInfo.size)

			// write the data descriptor
			buf := new(bytes.Buffer)
			err := binary.Write(buf, binary.LittleEndian, zip64DataDescriptor)
			if err != nil {
				return fmt.Errorf("binary.Write failed: %w", err)
			}

			err = writer.writeData(buf.Bytes())
			if err != nil {
				return fmt.Errorf("io.Writer.Write failed: %w", err)
			}

			writer.currentOffset += localFileHeaderSize
			writer.currentOffset += uint64(len(writer.FileInfo.filename))
			writer.currentOffset += uint64(writer.FileInfo.size)
			writer.currentOffset += zip64DataDescriptorSize
			writer.currentOffset += zip64ExtendedLocalInfoExtraFieldSize
		} else {
			zip32DataDescriptor := Zip32DataDescriptor{}
			zip32DataDescriptor.Signature = dataDescriptorSignature
			zip32DataDescriptor.Crc32 = writer.FileInfo.crc
			zip32DataDescriptor.CompressedSize = uint32(writer.FileInfo.size)
			zip32DataDescriptor.UncompressedSize = uint32(writer.FileInfo.size)

			// write the data descriptor
			buf := new(bytes.Buffer)
			err := binary.Write(buf, binary.LittleEndian, zip32DataDescriptor)
			if err != nil {
				return fmt.Errorf("binary.Write failed: %w", err)
			}

			err = writer.writeData(buf.Bytes())
			if err != nil {
				return fmt.Errorf("io.Writer.Write failed: %w", err)
			}

			writer.currentOffset += localFileHeaderSize
			writer.currentOffset += uint64(len(writer.FileInfo.filename))
			writer.currentOffset += uint64(writer.FileInfo.size)
			writer.currentOffset += zip32DataDescriptorSize
		}

		// reset the current file info since we reached the total size of the file
		writer.FileInfo = FileInfo{}
	}

	return nil
}

// Finish Finished adding all the files in zip archive.
func (writer *Writer) Finish() (int64, error) {
	err := writer.writeCentralDirectory()
	if err != nil {
		return writer.totalBytes, err
	}

	err = writer.writeEndOfCentralDirectory()
	if err != nil {
		return writer.totalBytes, fmt.Errorf("io.Writer.Write failed: %w", err)
	}

	return writer.totalBytes, nil
}

// WriteCentralDirectory write central directory struct into archive.
func (writer *Writer) writeCentralDirectory() error {
	writer.lastOffsetCDFileHeader = writer.currentOffset

	for i := 0; i < len(writer.fileInfoEntries); i++ {
		cdFileHeader := CDFileHeader{}
		cdFileHeader.Signature = centralDirectoryHeaderSignature
		cdFileHeader.VersionCreated = zipVersion
		cdFileHeader.VersionNeeded = zipVersion
		cdFileHeader.GeneralPurposeBitFlag = writer.fileInfoEntries[i].flag
		cdFileHeader.CompressionMethod = 0 // No compression
		cdFileHeader.LastModifiedTime = writer.fileInfoEntries[i].fileTime
		cdFileHeader.LastModifiedDate = writer.fileInfoEntries[i].fileDate

		cdFileHeader.Crc32 = writer.fileInfoEntries[i].crc
		cdFileHeader.FilenameLength = uint16(len(writer.fileInfoEntries[i].filename))
		cdFileHeader.FileCommentLength = 0

		cdFileHeader.DiskNumberStart = 0
		cdFileHeader.InternalFileAttributes = 0
		cdFileHeader.ExternalFileAttributes = 0

		cdFileHeader.CompressedSize = uint32(writer.fileInfoEntries[i].size)
		cdFileHeader.UncompressedSize = uint32(writer.fileInfoEntries[i].size)
		cdFileHeader.LocalHeaderOffset = uint32(writer.fileInfoEntries[i].offset)
		cdFileHeader.ExtraFieldLength = 0

		if writer.isZip64 {
			cdFileHeader.CompressedSize = zip64MagicVal
			cdFileHeader.UncompressedSize = zip64MagicVal
			cdFileHeader.LocalHeaderOffset = zip64MagicVal
			cdFileHeader.ExtraFieldLength = zip64ExtendedInfoExtraFieldSize
		}

		// write central directory file header struct
		buf := new(bytes.Buffer)
		err := binary.Write(buf, binary.LittleEndian, cdFileHeader)
		if err != nil {
			return fmt.Errorf("binary.Write failed: %w", err)
		}

		err = writer.writeData(buf.Bytes())
		if err != nil {
			return fmt.Errorf("io.Writer.Write failed: %w", err)
		}

		// write the filename
		err = writer.writeData([]byte(writer.fileInfoEntries[i].filename))
		if err != nil {
			return fmt.Errorf("io.Writer.Write failed: %w", err)
		}

		if writer.isZip64 {
			zip64ExtendedInfoExtraField := Zip64ExtendedInfoExtraField{}
			zip64ExtendedInfoExtraField.Signature = zip64ExternalID
			zip64ExtendedInfoExtraField.Size = zip64ExtendedInfoExtraFieldSize - 4
			zip64ExtendedInfoExtraField.OriginalSize = uint64(writer.fileInfoEntries[i].size)
			zip64ExtendedInfoExtraField.CompressedSize = uint64(writer.fileInfoEntries[i].size)
			zip64ExtendedInfoExtraField.LocalFileHeaderOffset = uint64(writer.fileInfoEntries[i].offset)

			// write zip64 extended info extra field struct
			buf = new(bytes.Buffer)
			err := binary.Write(buf, binary.LittleEndian, zip64ExtendedInfoExtraField)
			if err != nil {
				return fmt.Errorf("binary.Write failed: %w", err)
			}

			err = writer.writeData(buf.Bytes())
			if err != nil {
				return fmt.Errorf("io.Writer.Write failed: %w", err)
			}
		}

		writer.lastOffsetCDFileHeader += cdFileHeaderSize
		writer.lastOffsetCDFileHeader += uint64(len(writer.fileInfoEntries[i].filename))

		if writer.isZip64 {
			writer.lastOffsetCDFileHeader += zip64ExtendedInfoExtraFieldSize
		}
	}

	return nil
}

// writeEndOfCentralDirectory write end of central directory struct into archive.
func (writer *Writer) writeEndOfCentralDirectory() error {
	if writer.isZip64 {
		err := writer.WriteZip64EndOfCentralDirectory()
		if err != nil {
			return err
		}

		err = writer.WriteZip64EndOfCentralDirectoryLocator()
		if err != nil {
			return err
		}
	}

	endOfCDRecord := EndOfCDRecord{}
	endOfCDRecord.Signature = endOfCentralDirectorySignature
	endOfCDRecord.DiskNumber = 0
	endOfCDRecord.StartDiskNumber = 0
	endOfCDRecord.CentralDirectoryOffset = uint32(writer.currentOffset)
	endOfCDRecord.NumberOfCDRecordEntries = uint16(len(writer.fileInfoEntries))
	endOfCDRecord.TotalCDRecordEntries = uint16(len(writer.fileInfoEntries))
	endOfCDRecord.SizeOfCentralDirectory = uint32(writer.lastOffsetCDFileHeader - writer.currentOffset)
	endOfCDRecord.CommentLength = 0

	if writer.isZip64 {
		endOfCDRecord.CentralDirectoryOffset = zip64MagicVal
	}

	// write the end of central directory record struct
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, endOfCDRecord)
	if err != nil {
		return fmt.Errorf("binary.Write failed: %w", err)
	}

	err = writer.writeData(buf.Bytes())
	if err != nil {
		return fmt.Errorf("io.Writer.Write failed: %w", err)
	}

	return nil
}

// WriteZip64EndOfCentralDirectory write the zip64 end of central directory record struct to the archive.
func (writer *Writer) WriteZip64EndOfCentralDirectory() error {
	zip64EndOfCDRecord := Zip64EndOfCDRecord{}
	zip64EndOfCDRecord.Signature = zip64EndOfCDSignature
	zip64EndOfCDRecord.RecordSize = zip64EndOfCDRecordSize - 12
	zip64EndOfCDRecord.VersionMadeBy = zipVersion
	zip64EndOfCDRecord.VersionToExtract = zipVersion
	zip64EndOfCDRecord.DiskNumber = 0
	zip64EndOfCDRecord.StartDiskNumber = 0
	zip64EndOfCDRecord.NumberOfCDRecordEntries = uint64(len(writer.fileInfoEntries))
	zip64EndOfCDRecord.TotalCDRecordEntries = uint64(len(writer.fileInfoEntries))
	zip64EndOfCDRecord.CentralDirectorySize = writer.lastOffsetCDFileHeader - writer.currentOffset
	zip64EndOfCDRecord.StartingDiskCentralDirectoryOffset = writer.currentOffset

	// write the zip64 end of central directory record struct
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, zip64EndOfCDRecord)
	if err != nil {
		return fmt.Errorf("binary.Write failed: %w", err)
	}

	err = writer.writeData(buf.Bytes())
	if err != nil {
		return fmt.Errorf("io.Writer.Write failed: %w", err)
	}

	return nil
}

// WriteZip64EndOfCentralDirectoryLocator write the zip64 end of central directory locator struct
// to the archive.
func (writer *Writer) WriteZip64EndOfCentralDirectoryLocator() error {
	zip64EndOfCDRecordLocator := Zip64EndOfCDRecordLocator{}
	zip64EndOfCDRecordLocator.Signature = zip64EndOfCDLocatorSignature
	zip64EndOfCDRecordLocator.CDStartDiskNumber = 0
	zip64EndOfCDRecordLocator.CDOffset = writer.lastOffsetCDFileHeader
	zip64EndOfCDRecordLocator.NumberOfDisks = 1

	// write the zip64 end of central directory locator struct
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, zip64EndOfCDRecordLocator)
	if err != nil {
		return fmt.Errorf("binary.Write failed: %w", err)
	}

	err = writer.writeData(buf.Bytes())
	if err != nil {
		return fmt.Errorf("io.Writer.Write failed: %w", err)
	}

	return nil
}

// GetTimeDateUnMSDosFormat Get the time and date in MSDOS format.
func (writer *Writer) getTimeDateUnMSDosFormat() (uint16, uint16) {
	t := time.Now().UTC()
	timeInDos := t.Hour()<<11 | t.Minute()<<5 | int(math.Max(float64(t.Second()/2), 29))
	dateInDos := (t.Year()-80)<<9 | int((t.Month()+1)<<5) | t.Day()
	return uint16(timeInDos), uint16(dateInDos)
}

func (writer *Writer) writeData(data []byte) error {
	n, err := writer.writer.Write(data)
	if err != nil {
		return err
	}

	writer.totalBytes += int64(n)
	return nil
}
