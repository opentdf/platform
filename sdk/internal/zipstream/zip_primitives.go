// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package zipstream

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

// maxNonZip64Value is the largest value this writer will place in a 32-bit
// ZIP field before switching the entry to ZIP64. The fields are unsigned on
// the wire and would hold up to 0xFFFFFFFF, but readers that widen them with
// a signed read -- every java-sdk released before opentdf/java-sdk#393, and
// those stay in the field indefinitely -- see anything above 2 GiB as
// negative. Switching at Integer.MAX_VALUE instead, matching java-sdk's
// MAX_NON_ZIP64_VALUE, costs 28 bytes per affected entry and keeps archives
// in the 2-4 GiB band readable by those clients.
const maxNonZip64Value = math.MaxInt32

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
	// now is the injected time source used to stamp SegmentEntry.Written.
	now func() time.Time
}

// NewSegmentMetadata creates metadata for tracking segments using
// combine-based CRC. now stamps SegmentEntry.Written; pass time.Now
// for production or a pinned clock for deterministic tests.
func NewSegmentMetadata(expectedCount int, now func() time.Time) *SegmentMetadata {
	if now == nil {
		now = time.Now
	}
	return &SegmentMetadata{
		ExpectedCount: expectedCount,
		Segments:      make(map[int]*SegmentEntry),
		presentCount:  0,
		TotalCRC32:    0,
		now:           now,
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
		Written: sm.now(),
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
	// MaxNonZip64Value is the largest value written into a 32-bit field
	// before the entry switches to ZIP64. Zero means maxNonZip64Value.
	// Lowering it is a test seam: it exercises the ZIP64 path without
	// materializing a multi-gigabyte archive.
	MaxNonZip64Value uint64
}

// NewCentralDirectory creates a new central directory
func NewCentralDirectory() *CentralDirectory {
	return &CentralDirectory{
		Entries: make([]FileEntry, 0),
	}
}

// checkFitsInCentralDirectory guards a narrowing conversion into a 32-bit
// central directory field. The surrounding ZIP64 conditions already keep
// these values in range, so a failure here means one of them is wrong;
// erroring out beats silently emitting a truncated -- and therefore corrupt
// -- archive.
func checkFitsInCentralDirectory(field string, value uint64) error {
	if value >= zip64MagicVal {
		return fmt.Errorf("%w: %s is %d, which does not fit in a 32-bit zip field", ErrFieldOverflow, field, value)
	}
	return nil
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
		if isZip64 || cd.entryNeedsZip64(entry) {
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

// maxNonZip64 resolves the ZIP64 switch point for this directory.
func (cd *CentralDirectory) maxNonZip64() uint64 {
	if cd.MaxNonZip64Value == 0 {
		return maxNonZip64Value
	}
	return cd.MaxNonZip64Value
}

// entryNeedsZip64 reports whether an entry cannot be described by the 32-bit
// central directory fields alone. Offsets count as well as sizes: an entry
// starting past the switch point needs the ZIP64 extra field even when the
// entry itself is small.
func (cd *CentralDirectory) entryNeedsZip64(entry FileEntry) bool {
	maxValue := cd.maxNonZip64()
	return entry.Size > maxValue ||
		entry.CompressedSize > maxValue ||
		entry.Offset > maxValue
}

// msDosTimeDate encodes t as the (time, date) pair ZIP headers carry.
//
// The date packs the year as a 7-bit offset from zipBaseYear, so only
// zipBaseYear..zipMaxYear is representable. An out-of-range year would
// wrap through the uint16 conversion into a plausible but wrong date --
// the zero time.Time lands on 2049-01-01 and the Unix epoch on
// 2098-01-01 -- so clamp to the endpoints instead. time.Now is always in
// range; a clock injected via WithClock is the only way to get here.
func msDosTimeDate(t time.Time) (uint16, uint16) {
	const (
		hourShift   = 11
		minuteShift = 5
		monthShift  = 5
		yearShift   = 9
	)

	// Compare on calendar fields, not instants: DOS timestamps are local
	// wall-clock with no zone, and those fields are what get encoded.
	switch {
	case t.Year() < zipBaseYear:
		t = time.Date(zipBaseYear, time.January, 1, 0, 0, 0, 0, t.Location())
	case t.Year() > zipMaxYear:
		t = time.Date(zipMaxYear, time.December, 31, 23, 59, 58, 0, t.Location())
	}

	timeInDos := t.Hour()<<hourShift | t.Minute()<<minuteShift | t.Second()>>1
	dateInDos := (t.Year()-zipBaseYear)<<yearShift | int(t.Month())<<monthShift | t.Day()

	return uint16(timeInDos), uint16(dateInDos)
}

// writeCDFileHeader writes a central directory file header
func (cd *CentralDirectory) writeCDFileHeader(buf *bytes.Buffer, entry FileEntry, isZip64 bool) error {
	lastModifiedTime, lastModifiedDate := msDosTimeDate(entry.ModTime)

	useZip64 := isZip64 || cd.entryNeedsZip64(entry)
	if !useZip64 {
		// Only the 32-bit path narrows these; the ZIP64 path overwrites
		// them with the sentinel below.
		for _, f := range []struct {
			name  string
			value uint64
		}{
			{"compressed size of " + entry.Name, entry.CompressedSize},
			{"uncompressed size of " + entry.Name, entry.Size},
			{"local header offset of " + entry.Name, entry.Offset},
		} {
			if err := checkFitsInCentralDirectory(f.name, f.value); err != nil {
				return err
			}
		}
	}

	header := CDFileHeader{
		Signature:              centralDirectoryHeaderSignature,
		VersionCreated:         zipVersion,
		VersionNeeded:          zipVersion,
		GeneralPurposeBitFlag:  0,
		CompressionMethod:      0, // No compression
		LastModifiedTime:       lastModifiedTime,
		LastModifiedDate:       lastModifiedDate,
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
	if useZip64 {
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

	if !isZip64 {
		// The 32-bit EOCD carries these verbatim. Same reasoning as
		// checkFitsInCentralDirectory: fail loudly rather than emit a
		// trailer that points somewhere else in the archive.
		if err := checkFitsInCentralDirectory("central directory size", cd.Size); err != nil {
			return err
		}
		if err := checkFitsInCentralDirectory("central directory offset", cd.Offset); err != nil {
			return err
		}
		if len(cd.Entries) >= zip64MagicVal16 {
			return fmt.Errorf("%w: entry count is %d, which does not fit in a 16-bit zip field",
				ErrFieldOverflow, len(cd.Entries))
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
		endOfCD.NumberOfCDRecordEntries = zip64MagicVal16
		endOfCD.TotalCDRecordEntries = zip64MagicVal16
		endOfCD.SizeOfCentralDirectory = zip64MagicVal
		endOfCD.CentralDirectoryOffset = zip64MagicVal
	}

	return binary.Write(buf, binary.LittleEndian, endOfCD)
}
