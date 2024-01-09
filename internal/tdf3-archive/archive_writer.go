package tdf3_archiver

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
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

type IArchiveWriter interface {
	SetFileSize(string, int64) error
	AddDataToFile(string, []byte) error
	Finish() error
}

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

type ArchiveWriter struct {
	outputProvider                        IOutputProvider
	currentOffset, lastOffsetCDFileHeader uint64
	FileInfo
	fileInfoEntries []FileInfo
	writeState      WriteState
	isZip64         bool
}

// CreateArchiveWriter Create tdf3 writer instance
func CreateArchiveWriter(outputProvider IOutputProvider) *ArchiveWriter {
	archiveWriter := ArchiveWriter{}

	archiveWriter.outputProvider = outputProvider
	archiveWriter.writeState = Initial
	archiveWriter.currentOffset = 0
	archiveWriter.lastOffsetCDFileHeader = 0
	archiveWriter.fileInfoEntries = make([]FileInfo, 0)

	return &archiveWriter
}

// EnableZip64 Enable zip 64
func (archiveWriter *ArchiveWriter) EnableZip64() {
	archiveWriter.isZip64 = true
}

// SetFileSize set size of the file. calling this method means finished writing
// the previous file and starting a new file.
func (archiveWriter *ArchiveWriter) SetFileSize(filename string, size int64) error {

	if len(archiveWriter.FileInfo.filename) != 0 {
		err := fmt.Errorf("ArchiveWriter: cannot add a new file until the current "+
			"file write is not completed:%s", archiveWriter.FileInfo.filename)
		return err
	}

	if !archiveWriter.isZip64 {
		archiveWriter.isZip64 = size > zip64MagicVal
	}

	archiveWriter.writeState = Initial
	archiveWriter.FileInfo.size = size
	archiveWriter.FileInfo.filename = filename

	return nil
}

// AddDataToFile Add data to file in zip archive
func (archiveWriter *ArchiveWriter) AddDataToFile(filename string, data []byte) error {

	if archiveWriter.FileInfo.filename != filename {
		err := fmt.Errorf("ArchiveWriter: cannot add data to file before setting the"+
			" file size, expected:%s actual:%s", archiveWriter.FileInfo.filename, filename)
		return err
	}

	localFileHeader := LocalFileHeader{}
	fileTime, fileDate := archiveWriter.getTimeDateUnMSDosFormat()

	if archiveWriter.writeState == Initial {
		localFileHeader.Signature = fileHeaderSignature
		localFileHeader.Version = 45
		//since payload is added by chunks we set General purpose bit flag to 0x08
		localFileHeader.GeneralPurposeBitFlag = 0x08
		localFileHeader.CompressionMethod = 0 // no compression
		localFileHeader.LastModifiedTime = fileTime
		localFileHeader.LastModifiedDate = fileDate
		localFileHeader.Crc32 = 0

		localFileHeader.CompressedSize = 0
		localFileHeader.UncompressedSize = 0
		localFileHeader.ExtraFieldLength = 0

		if archiveWriter.isZip64 {
			localFileHeader.CompressedSize = zip64MagicVal
			localFileHeader.UncompressedSize = zip64MagicVal
			localFileHeader.ExtraFieldLength = zip64ExtendedLocalInfoExtraFieldSize
		}

		localFileHeader.FilenameLength = uint16(len(archiveWriter.FileInfo.filename))

		// write localFileHeader
		buf := new(bytes.Buffer)
		err := binary.Write(buf, binary.LittleEndian, localFileHeader)
		if err != nil {
			return err
		}

		err = archiveWriter.outputProvider.WriteBytes(buf.Bytes())
		if err != nil {
			return err
		}

		// write the file name
		err = archiveWriter.outputProvider.WriteBytes([]byte(archiveWriter.FileInfo.filename))
		if err != nil {
			return err
		}

		if archiveWriter.isZip64 {

			zip64ExtendedLocalInfoExtraField := Zip64ExtendedLocalInfoExtraField{}
			zip64ExtendedLocalInfoExtraField.Signature = zip64ExternalId
			zip64ExtendedLocalInfoExtraField.Size = zip64ExtendedLocalInfoExtraFieldSize - 4
			zip64ExtendedLocalInfoExtraField.OriginalSize = uint64(archiveWriter.FileInfo.size)
			zip64ExtendedLocalInfoExtraField.CompressedSize = uint64(archiveWriter.FileInfo.size)

			buf := new(bytes.Buffer)
			err := binary.Write(buf, binary.LittleEndian, zip64ExtendedLocalInfoExtraField)
			if err != nil {
				return err
			}

			err = archiveWriter.outputProvider.WriteBytes(buf.Bytes())
			if err != nil {
				return err
			}
		}

		archiveWriter.writeState = Appending

		// calculate the initial crc
		archiveWriter.FileInfo.crc = crc32.Checksum([]byte(""), crc32.MakeTable(crc32.IEEE))
		archiveWriter.FileInfo.fileTime = fileTime
		archiveWriter.FileInfo.fileDate = fileDate
	}

	// now write the contents
	err := archiveWriter.outputProvider.WriteBytes(data)
	if err != nil {
		return err
	}

	// calculate the crc32
	archiveWriter.FileInfo.crc = crc32.Update(archiveWriter.FileInfo.crc,
		crc32.MakeTable(crc32.IEEE), data)

	// update the file size
	archiveWriter.FileInfo.offset += int64(len(data))

	// check if we reached end
	if archiveWriter.FileInfo.offset >= archiveWriter.FileInfo.size {
		archiveWriter.writeState = Finished

		archiveWriter.FileInfo.offset = int64(archiveWriter.currentOffset)
		archiveWriter.FileInfo.flag = 0x08

		newFileInfoEntries := append(archiveWriter.fileInfoEntries, archiveWriter.FileInfo)
		archiveWriter.fileInfoEntries = newFileInfoEntries
	}

	if archiveWriter.writeState == Finished {

		if archiveWriter.isZip64 {
			zip64DataDescriptor := Zip64DataDescriptor{}
			zip64DataDescriptor.Signature = dataDescriptorSignature
			zip64DataDescriptor.Crc32 = archiveWriter.FileInfo.crc
			zip64DataDescriptor.CompressedSize = uint64(archiveWriter.FileInfo.size)
			zip64DataDescriptor.UncompressedSize = uint64(archiveWriter.FileInfo.size)

			// write the data descriptor
			buf := new(bytes.Buffer)
			err := binary.Write(buf, binary.LittleEndian, zip64DataDescriptor)
			if err != nil {
				return err
			}

			err = archiveWriter.outputProvider.WriteBytes(buf.Bytes())
			if err != nil {
				return err
			}

			archiveWriter.currentOffset += localFileHeaderSize
			archiveWriter.currentOffset += uint64(len(archiveWriter.FileInfo.filename))
			archiveWriter.currentOffset += uint64(archiveWriter.FileInfo.size)
			archiveWriter.currentOffset += zip64DataDescriptorSize
			archiveWriter.currentOffset += zip64ExtendedLocalInfoExtraFieldSize
		} else {
			zip32DataDescriptor := Zip32DataDescriptor{}
			zip32DataDescriptor.Signature = dataDescriptorSignature
			zip32DataDescriptor.Crc32 = archiveWriter.FileInfo.crc
			zip32DataDescriptor.CompressedSize = uint32(archiveWriter.FileInfo.size)
			zip32DataDescriptor.UncompressedSize = uint32(archiveWriter.FileInfo.size)

			// write the data descriptor
			buf := new(bytes.Buffer)
			err := binary.Write(buf, binary.LittleEndian, zip32DataDescriptor)
			if err != nil {
				return err
			}

			err = archiveWriter.outputProvider.WriteBytes(buf.Bytes())
			if err != nil {
				return err
			}

			archiveWriter.currentOffset += localFileHeaderSize
			archiveWriter.currentOffset += uint64(len(archiveWriter.FileInfo.filename))
			archiveWriter.currentOffset += uint64(archiveWriter.FileInfo.size)
			archiveWriter.currentOffset += zip32DataDescriptorSize
		}

		// reset the current file info since we reached the total size of the file
		archiveWriter.FileInfo = FileInfo{}
	}

	return nil
}

// Finish Completed adding all the files in zip archive
func (archiveWriter *ArchiveWriter) Finish() error {
	err := archiveWriter.writeCentralDirectory()
	if err != nil {
		return err
	}

	err = archiveWriter.writeEndOfCentralDirectory()
	if err != nil {
		return err
	}

	return nil
}

// WriteCentralDirectory write central directory struct into archive
func (archiveWriter *ArchiveWriter) writeCentralDirectory() error {

	archiveWriter.lastOffsetCDFileHeader = archiveWriter.currentOffset

	for i := 0; i < len(archiveWriter.fileInfoEntries); i++ {
		cdFileHeader := CDFileHeader{}
		cdFileHeader.Signature = centralDirectoryHeaderSignature
		cdFileHeader.VersionCreated = zipVersion
		cdFileHeader.VersionNeeded = zipVersion
		cdFileHeader.GeneralPurposeBitFlag = archiveWriter.fileInfoEntries[i].flag
		cdFileHeader.CompressionMethod = 0 // No compression
		cdFileHeader.LastModifiedTime = archiveWriter.fileInfoEntries[i].fileTime
		cdFileHeader.LastModifiedDate = archiveWriter.fileInfoEntries[i].fileDate

		cdFileHeader.Crc32 = archiveWriter.fileInfoEntries[i].crc
		cdFileHeader.FilenameLength = uint16(len(archiveWriter.fileInfoEntries[i].filename))
		cdFileHeader.FileCommentLength = 0

		cdFileHeader.DiskNumberStart = 0
		cdFileHeader.InternalFileAttributes = 0
		cdFileHeader.ExternalFileAttributes = 0

		cdFileHeader.CompressedSize = uint32(archiveWriter.fileInfoEntries[i].size)
		cdFileHeader.UncompressedSize = uint32(archiveWriter.fileInfoEntries[i].size)
		cdFileHeader.LocalHeaderOffset = uint32(archiveWriter.fileInfoEntries[i].offset)
		cdFileHeader.ExtraFieldLength = 0

		if archiveWriter.isZip64 {
			cdFileHeader.CompressedSize = zip64MagicVal
			cdFileHeader.UncompressedSize = zip64MagicVal
			cdFileHeader.LocalHeaderOffset = zip64MagicVal
			cdFileHeader.ExtraFieldLength = zip64ExtendedInfoExtraFieldSize
		}

		// write central directory file header struct
		buf := new(bytes.Buffer)
		err := binary.Write(buf, binary.LittleEndian, cdFileHeader)
		if err != nil {
			return err
		}

		err = archiveWriter.outputProvider.WriteBytes(buf.Bytes())
		if err != nil {
			return err
		}

		// write the filename
		err = archiveWriter.outputProvider.WriteBytes([]byte(archiveWriter.fileInfoEntries[i].filename))
		if err != nil {
			return err
		}

		if archiveWriter.isZip64 {

			zip64ExtendedInfoExtraField := Zip64ExtendedInfoExtraField{}
			zip64ExtendedInfoExtraField.Signature = zip64ExternalId
			zip64ExtendedInfoExtraField.Size = zip64ExtendedInfoExtraFieldSize - 4
			zip64ExtendedInfoExtraField.OriginalSize = uint64(archiveWriter.fileInfoEntries[i].size)
			zip64ExtendedInfoExtraField.CompressedSize = uint64(archiveWriter.fileInfoEntries[i].size)
			zip64ExtendedInfoExtraField.LocalFileHeaderOffset = uint64(archiveWriter.fileInfoEntries[i].offset)

			// write zip64 extended info extra field struct
			buf := new(bytes.Buffer)
			err := binary.Write(buf, binary.LittleEndian, zip64ExtendedInfoExtraField)
			if err != nil {
				return err
			}

			err = archiveWriter.outputProvider.WriteBytes(buf.Bytes())
			if err != nil {
				return err
			}
		}

		archiveWriter.lastOffsetCDFileHeader += cdFileHeaderSize
		archiveWriter.lastOffsetCDFileHeader += uint64(len(archiveWriter.fileInfoEntries[i].filename))

		if archiveWriter.isZip64 {
			archiveWriter.lastOffsetCDFileHeader += zip64ExtendedInfoExtraFieldSize
		}
	}

	return nil
}

// writeEndOfCentralDirectory write end of central directory struct into archive
func (archiveWriter *ArchiveWriter) writeEndOfCentralDirectory() error {
	if archiveWriter.isZip64 {

		err := archiveWriter.WriteZip64EndOfCentralDirectory()
		if err != nil {
			return nil
		}

		err = archiveWriter.WriteZip64EndOfCentralDirectoryLocator()
		if err != nil {
			return nil
		}
	}

	endOfCDRecord := EndOfCDRecord{}
	endOfCDRecord.Signature = endOfCentralDirectorySignature
	endOfCDRecord.DiskNumber = 0
	endOfCDRecord.StartDiskNumber = 0
	endOfCDRecord.CentralDirectoryOffset = uint32(archiveWriter.currentOffset)
	endOfCDRecord.NumberOfCDRecordEntries = uint16(len(archiveWriter.fileInfoEntries))
	endOfCDRecord.TotalCDRecordEntries = uint16(len(archiveWriter.fileInfoEntries))
	endOfCDRecord.SizeOfCentralDirectory = uint32(archiveWriter.lastOffsetCDFileHeader - archiveWriter.currentOffset)
	endOfCDRecord.CommentLength = 0

	if archiveWriter.isZip64 {
		endOfCDRecord.CentralDirectoryOffset = zip64MagicVal
	}

	// write the end of central directory record struct
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, endOfCDRecord)
	if err != nil {
		return err
	}

	err = archiveWriter.outputProvider.WriteBytes(buf.Bytes())
	if err != nil {
		return err
	}

	return nil
}

// WriteZip64EndOfCentralDirectory write the zip64 end of central directory record struct to the archive
func (archiveWriter *ArchiveWriter) WriteZip64EndOfCentralDirectory() error {

	zip64EndOfCDRecord := Zip64EndOfCDRecord{}
	zip64EndOfCDRecord.Signature = zip64EndOfCDSignature
	zip64EndOfCDRecord.RecordSize = zip64EndOfCDRecordSize - 12
	zip64EndOfCDRecord.VersionMadeBy = zipVersion
	zip64EndOfCDRecord.VersionToExtract = zipVersion
	zip64EndOfCDRecord.DiskNumber = 0
	zip64EndOfCDRecord.StartDiskNumber = 0
	zip64EndOfCDRecord.NumberOfCDRecordEntries = uint64(len(archiveWriter.fileInfoEntries))
	zip64EndOfCDRecord.TotalCDRecordEntries = uint64(len(archiveWriter.fileInfoEntries))
	zip64EndOfCDRecord.CentralDirectorySize = archiveWriter.lastOffsetCDFileHeader - archiveWriter.currentOffset
	zip64EndOfCDRecord.StartingDiskCentralDirectoryOffset = archiveWriter.currentOffset

	// write the zip64 end of central directory record struct
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, zip64EndOfCDRecord)
	if err != nil {
		return err
	}

	err = archiveWriter.outputProvider.WriteBytes(buf.Bytes())
	if err != nil {
		return err
	}

	return nil
}

// WriteZip64EndOfCentralDirectoryLocator write the zip64 end of central directory locator struct to the archive
func (archiveWriter *ArchiveWriter) WriteZip64EndOfCentralDirectoryLocator() error {

	zip64EndOfCDRecordLocator := Zip64EndOfCDRecordLocator{}
	zip64EndOfCDRecordLocator.Signature = zip64EndOfCDLocatorSignature
	zip64EndOfCDRecordLocator.CDStartDiskNumber = 0
	zip64EndOfCDRecordLocator.CDOffset = archiveWriter.lastOffsetCDFileHeader
	zip64EndOfCDRecordLocator.NumberOfDisks = 1

	// write the zip64 end of central directory locator struct
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, zip64EndOfCDRecordLocator)
	if err != nil {
		return err
	}

	err = archiveWriter.outputProvider.WriteBytes(buf.Bytes())
	if err != nil {
		return err
	}

	return nil
}

// GetTimeDateUnMSDosFormat Get the time and date in MSDOS format
func (archiveWriter *ArchiveWriter) getTimeDateUnMSDosFormat() (uint16, uint16) {
	t := time.Now().UTC()
	timeInDos := t.Hour()<<11 | t.Minute()<<5 | int(math.Max(float64(t.Second()/2), 29))
	dateInDos := (t.Year()-80)<<9 | int((t.Month()+1)<<5) | t.Day()
	return uint16(timeInDos), uint16(dateInDos)

}
