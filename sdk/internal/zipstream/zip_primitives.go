// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package zipstream

import (
	"bytes"
	"encoding/binary"
	"time"
)

// Note: CRC32 calculation for the payload is performed using a combine
// approach over per-segment CRCs and sizes to avoid buffering segments.

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
	Size    uint64    // Size of stored segment bytes (no compression)
	CRC32   uint32    // CRC32 of stored segment bytes
	Written time.Time // When this segment was written
}

// SegmentMetadata tracks per-segment metadata for out-of-order writing.
// It stores only plaintext size and CRC for each index and computes the
// final CRC via CRC32-combine at finalize time (no payload buffering).
type SegmentMetadata struct {
	ExpectedCount int                   // Total number of expected segments (unused when Order set)
	Segments      map[int]*SegmentEntry // Map of segments by index
	TotalSize     uint64                // Cumulative size of all segments
	presentCount  int                   // Number of segments recorded
	TotalCRC32    uint32                // Final CRC32 when all segments are processed
	// Order, when set, defines the exact logical order of segments for
	// completeness checks and CRC computation. Indices may be sparse.
	Order []int
}

// NewSegmentMetadata creates metadata for tracking segments using combine-based CRC.
func NewSegmentMetadata(expectedCount int) *SegmentMetadata {
	return &SegmentMetadata{
		ExpectedCount: expectedCount,
		Segments:      make(map[int]*SegmentEntry),
		presentCount:  0,
		TotalCRC32:    0,
	}
}

// AddSegment records metadata for a segment (size + CRC) without retaining payload bytes.
func (sm *SegmentMetadata) AddSegment(index int, originalSize uint64, originalCRC32 uint32) error {
	if index < 0 {
		return ErrInvalidSegment
	}

	if _, exists := sm.Segments[index]; exists {
		return ErrDuplicateSegment
	}

	// Record per-segment metadata only (no buffering of data)
	sm.Segments[index] = &SegmentEntry{
		Index:   index,
		Size:    originalSize,
		CRC32:   originalCRC32,
		Written: time.Now(),
	}

	sm.TotalSize += originalSize
	sm.presentCount++

	return nil
}

// IsComplete returns true if all expected segments have been processed
func (sm *SegmentMetadata) IsComplete() bool {
	// If an explicit order is set, require that every index in Order exists.
	if len(sm.Order) > 0 {
		for _, idx := range sm.Order {
			if _, ok := sm.Segments[idx]; !ok {
				return false
			}
		}
		return true
	}
	if sm.ExpectedCount <= 0 {
		return false
	}
	return sm.presentCount == sm.ExpectedCount
}

// GetMissingSegments returns a list of missing segment indices
func (sm *SegmentMetadata) GetMissingSegments() []int {
	missing := make([]int, 0)
	if len(sm.Order) > 0 {
		for _, idx := range sm.Order {
			if _, exists := sm.Segments[idx]; !exists {
				missing = append(missing, idx)
			}
		}
		return missing
	}
	for i := 0; i < sm.ExpectedCount; i++ {
		if _, exists := sm.Segments[i]; !exists {
			missing = append(missing, i)
		}
	}
	return missing
}

// GetTotalCRC32 returns the final CRC32 value (only valid when IsComplete() is true)
func (sm *SegmentMetadata) GetTotalCRC32() uint32 { return sm.TotalCRC32 }

// FinalizeCRC computes the total CRC32 by combining per-segment CRCs in index order.
func (sm *SegmentMetadata) FinalizeCRC() {
	// If an explicit order is set, use it for CRC combine.
	if len(sm.Order) > 0 {
		var total uint32
		var initialized bool
		for _, idx := range sm.Order {
			seg, ok := sm.Segments[idx]
			if !ok {
				// Incomplete; leave TotalCRC32 as zero
				sm.TotalCRC32 = 0
				return
			}
			if !initialized {
				total = seg.CRC32
				initialized = true
			} else {
				total = CRC32CombineIEEE(total, seg.CRC32, int64(seg.Size))
			}
		}
		sm.TotalCRC32 = total
		return
	}
	if sm.ExpectedCount <= 0 {
		sm.TotalCRC32 = 0
		return
	}
	var total uint32
	var initialized bool
	for i := 0; i < sm.ExpectedCount; i++ {
		seg, ok := sm.Segments[i]
		if !ok {
			// Incomplete; leave TotalCRC32 as zero
			return
		}
		if !initialized {
			total = seg.CRC32
			initialized = true
		} else {
			total = CRC32CombineIEEE(total, seg.CRC32, int64(seg.Size))
		}
	}
	sm.TotalCRC32 = total
}

// SetOrder defines the exact logical order of segments. Duplicates are not allowed.
// When set, completeness/CRC use this order; ExpectedCount is ignored.
func (sm *SegmentMetadata) SetOrder(order []int) error {
	if len(order) == 0 {
		sm.Order = nil
		return nil
	}
	seen := make(map[int]struct{}, len(order))
	for _, idx := range order {
		if idx < 0 {
			return ErrInvalidSegment
		}
		if _, dup := seen[idx]; dup {
			return ErrDuplicateSegment
		}
		seen[idx] = struct{}{}
	}
	sm.Order = append([]int(nil), order...)
	return nil
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
		LastModifiedDate:       uint16((entry.ModTime.Year()-zipBaseYear)<<9 | int(entry.ModTime.Month())<<5 | entry.ModTime.Day()),
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
			Size:                  zip64ExtendedInfoExtraFieldSize - extraFieldHeaderSize,
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
			RecordSize:                         zip64EndOfCDRecordSize - zip64RecordHeaderSize, // Size excluding signature and size field
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
