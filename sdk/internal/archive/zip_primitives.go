package archive

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"time"
)

// FileEntry represents a file in the ZIP archive with metadata
type FileEntry struct {
	Name           string    // Filename in the archive
	Offset         uint64    // Offset of local file header in archive
	Size           uint64    // Uncompressed size
	CompressedSize uint64    // Compressed size (same as Size for no compression)
	CRC32          uint32    // CRC32 checksum of uncompressed data
	ModTime        time.Time // Last modification time
	IsStreaming    bool      // Whether this uses data descriptor pattern
}

// SegmentEntry represents a single segment in out-of-order writing
type SegmentEntry struct {
	Index   int       // Segment index (0-based)
	Data    []byte    // Encrypted segment data
	Size    uint64    // Size of original plaintext data
	CRC32   uint32    // CRC32 of original plaintext data
	Written time.Time // When this segment was written
}

// SegmentMetadata tracks overall segment state
type SegmentMetadata struct {
	ExpectedCount int                   // Total number of expected segments
	Segments      map[int]*SegmentEntry // Map of index to segment
	TotalSize     uint64                // Cumulative size of all segments
	TotalCRC32    uint32                // Cumulative CRC32 of all segments
	NextIndex     int                   // Next expected segment index for validation
}

// NewSegmentMetadata creates metadata for tracking segments
func NewSegmentMetadata(expectedCount int) *SegmentMetadata {
	return &SegmentMetadata{
		ExpectedCount: expectedCount,
		Segments:      make(map[int]*SegmentEntry),
		TotalCRC32:    crc32.NewIEEE().Sum32(), // Initialize empty checksum
	}
}

// AddSegment adds a segment to the metadata
func (sm *SegmentMetadata) AddSegment(index int, data []byte, originalSize uint64, originalCRC32 uint32) error {
	if index < 0 {
		return ErrInvalidSegment
	}

	// Allow dynamic expansion beyond ExpectedCount for streaming use cases
	if index >= sm.ExpectedCount {
		sm.ExpectedCount = index + 1
	}

	if _, exists := sm.Segments[index]; exists {
		return ErrDuplicateSegment
	}

	sm.Segments[index] = &SegmentEntry{
		Index:   index,
		Data:    data,
		Size:    originalSize,
		CRC32:   originalCRC32,
		Written: time.Now(),
	}

	sm.TotalSize += originalSize
	// Recalculate total CRC32 for all segments in logical order
	sm.TotalCRC32 = sm.calculateTotalCRC32()

	return nil
}

// IsComplete returns true if all expected segments have been written
func (sm *SegmentMetadata) IsComplete() bool {
	return len(sm.Segments) == sm.ExpectedCount
}

// GetMissingSegments returns a list of missing segment indices
func (sm *SegmentMetadata) GetMissingSegments() []int {
	missing := make([]int, 0)
	for i := 0; i < sm.ExpectedCount; i++ {
		if _, exists := sm.Segments[i]; !exists {
			missing = append(missing, i)
		}
	}
	return missing
}

// calculateTotalCRC32 computes the total CRC32 by processing all segments in logical order
func (sm *SegmentMetadata) calculateTotalCRC32() uint32 {
	crc32Table := crc32.MakeTable(crc32.IEEE)
	totalCRC := uint32(0)

	// Process segments in logical order (0, 1, 2, ...) regardless of write order
	for i := 0; i < sm.ExpectedCount; i++ {
		if segment, exists := sm.Segments[i]; exists {
			// Update CRC with this segment's data
			totalCRC = crc32.Update(totalCRC, crc32Table, segment.Data)
		}
	}

	return totalCRC
}

// CentralDirectory manages the ZIP central directory structure
type CentralDirectory struct {
	Entries []FileEntry // File entries in the archive
	Offset  uint64      // Offset where central directory starts
	Size    uint64      // Size of central directory
}

// NewCentralDirectory creates a new central directory
func NewCentralDirectory() *CentralDirectory {
	return &CentralDirectory{
		Entries: make([]FileEntry, 0),
	}
}

// AddFile adds a file entry to the central directory
func (cd *CentralDirectory) AddFile(entry FileEntry) {
	cd.Entries = append(cd.Entries, entry)
}

// GenerateBytes generates the central directory bytes
func (cd *CentralDirectory) GenerateBytes(isZip64 bool) ([]byte, error) {
	buf := &bytes.Buffer{}

	// First pass: calculate the size of central directory entries only
	cdEntriesSize := uint64(0)
	for _, entry := range cd.Entries {
		entrySize := cdFileHeaderSize + uint64(len(entry.Name))
		if isZip64 || entry.Size >= uint64(^uint32(0)) || entry.CompressedSize >= uint64(^uint32(0)) {
			entrySize += zip64ExtendedInfoExtraFieldSize
		}
		cdEntriesSize += entrySize
	}

	// Set size excluding end-of-CD records
	cd.Size = cdEntriesSize

	// Second pass: write the actual entries
	for _, entry := range cd.Entries {
		if err := cd.writeCDFileHeader(buf, entry, isZip64); err != nil {
			return nil, err
		}
	}

	// Write end of central directory record
	if err := cd.writeEndOfCDRecord(buf, isZip64); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// writeCDFileHeader writes a central directory file header
func (cd *CentralDirectory) writeCDFileHeader(buf *bytes.Buffer, entry FileEntry, isZip64 bool) error {
	header := CDFileHeader{
		Signature:              centralDirectoryHeaderSignature,
		VersionCreated:         zipVersion,
		VersionNeeded:          zipVersion,
		GeneralPurposeBitFlag:  0,
		CompressionMethod:      0, // No compression
		LastModifiedTime:       uint16(entry.ModTime.Hour()<<11 | entry.ModTime.Minute()<<5 | entry.ModTime.Second()>>1),
		LastModifiedDate:       uint16((entry.ModTime.Year()-1980)<<9 | int(entry.ModTime.Month())<<5 | entry.ModTime.Day()),
		Crc32:                  entry.CRC32,
		CompressedSize:         uint32(entry.CompressedSize),
		UncompressedSize:       uint32(entry.Size),
		FilenameLength:         uint16(len(entry.Name)),
		ExtraFieldLength:       0,
		FileCommentLength:      0,
		DiskNumberStart:        0,
		InternalFileAttributes: 0,
		ExternalFileAttributes: 0,
		LocalHeaderOffset:      uint32(entry.Offset),
	}

	// Set streaming flag if using data descriptor
	if entry.IsStreaming {
		header.GeneralPurposeBitFlag = 0x08
	}

	// Handle ZIP64 if needed
	if isZip64 || entry.Size >= uint64(^uint32(0)) || entry.CompressedSize >= uint64(^uint32(0)) {
		header.CompressedSize = zip64MagicVal
		header.UncompressedSize = zip64MagicVal
		header.LocalHeaderOffset = zip64MagicVal
		header.ExtraFieldLength = zip64ExtendedInfoExtraFieldSize
	}

	if err := binary.Write(buf, binary.LittleEndian, header); err != nil {
		return err
	}

	// Write filename
	if _, err := buf.WriteString(entry.Name); err != nil {
		return err
	}

	// Write ZIP64 extended info if needed
	if header.ExtraFieldLength > 0 {
		zip64Extra := Zip64ExtendedInfoExtraField{
			Signature:             zip64ExternalID,
			Size:                  zip64ExtendedInfoExtraFieldSize - 4,
			OriginalSize:          entry.Size,
			CompressedSize:        entry.CompressedSize,
			LocalFileHeaderOffset: entry.Offset,
		}
		if err := binary.Write(buf, binary.LittleEndian, zip64Extra); err != nil {
			return err
		}
	}

	return nil
}

// writeEndOfCDRecord writes the end of central directory record
func (cd *CentralDirectory) writeEndOfCDRecord(buf *bytes.Buffer, isZip64 bool) error {
	if isZip64 {
		// Remember where the ZIP64 end-of-central-directory record starts
		zip64EndOfCDOffset := cd.Offset + cd.Size

		// Write ZIP64 end of central directory record
		zip64EndOfCD := Zip64EndOfCDRecord{
			Signature:                          zip64EndOfCDSignature,
			RecordSize:                         zip64EndOfCDRecordSize - 12, // Size excluding signature and size field
			VersionMadeBy:                      zipVersion,
			VersionToExtract:                   zipVersion,
			DiskNumber:                         0,
			StartDiskNumber:                    0,
			NumberOfCDRecordEntries:            uint64(len(cd.Entries)),
			TotalCDRecordEntries:               uint64(len(cd.Entries)),
			CentralDirectorySize:               cd.Size,
			StartingDiskCentralDirectoryOffset: cd.Offset,
		}

		if err := binary.Write(buf, binary.LittleEndian, zip64EndOfCD); err != nil {
			return err
		}

		// Write ZIP64 end of central directory locator
		zip64Locator := Zip64EndOfCDRecordLocator{
			Signature:         zip64EndOfCDLocatorSignature,
			CDStartDiskNumber: 0,
			CDOffset:          zip64EndOfCDOffset, // Points to ZIP64 end-of-CD record, not CD start
			NumberOfDisks:     1,
		}

		if err := binary.Write(buf, binary.LittleEndian, zip64Locator); err != nil {
			return err
		}
	}

	// Write standard end of central directory record
	endOfCD := EndOfCDRecord{
		Signature:               endOfCentralDirectorySignature,
		DiskNumber:              0,
		StartDiskNumber:         0,
		NumberOfCDRecordEntries: uint16(len(cd.Entries)),
		TotalCDRecordEntries:    uint16(len(cd.Entries)),
		SizeOfCentralDirectory:  uint32(cd.Size),
		CentralDirectoryOffset:  uint32(cd.Offset),
		CommentLength:           0,
	}

	// Use ZIP64 values if needed
	if isZip64 {
		endOfCD.NumberOfCDRecordEntries = 0xFFFF
		endOfCD.TotalCDRecordEntries = 0xFFFF
		endOfCD.SizeOfCentralDirectory = zip64MagicVal
		endOfCD.CentralDirectoryOffset = zip64MagicVal
	}

	return binary.Write(buf, binary.LittleEndian, endOfCD)
}
