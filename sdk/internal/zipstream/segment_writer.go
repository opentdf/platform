// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package zipstream

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"sort"
	"sync"
	"time"

	"github.com/opentdf/platform/lib/ocrypto"
)

// segmentWriter implements the SegmentWriter interface for out-of-order segment writing
type segmentWriter struct {
	*baseWriter
	metadata     *SegmentMetadata
	centralDir   *CentralDirectory
	payloadEntry *FileEntry
	finalized    bool
	mu           sync.RWMutex
}

// NewSegmentTDFWriter creates a new SegmentWriter for out-of-order segment writing
func NewSegmentTDFWriter(expectedSegments int, opts ...Option) SegmentWriter {
	cfg := applyOptions(opts)

	// Validate expectedSegments
	if expectedSegments <= 0 || expectedSegments > cfg.MaxSegments {
		expectedSegments = 1
	}

	base := newBaseWriter(cfg)

	return &segmentWriter{
		baseWriter: base,
		metadata:   NewSegmentMetadata(expectedSegments),
		centralDir: NewCentralDirectory(),
		payloadEntry: &FileEntry{
			Name:        TDFPayloadFileName,
			Offset:      0,
			ModTime:     time.Now(),
			IsStreaming: true, // Use data descriptor pattern
		},
		finalized: false,
	}
}

// WriteSegment writes a segment with deterministic output based on segment index
func (sw *segmentWriter) WriteSegment(ctx context.Context, index int, data []byte) ([]byte, error) {
	// CRC32 over stored segment bytes (what goes into the ZIP entry)
	originalCRC := crc32.ChecksumIEEE(data)

	sw.mu.Lock()
	defer sw.mu.Unlock()

	// Check if writer is closed or finalized
	if err := sw.checkClosed(); err != nil {
		return nil, &Error{Op: "write-segment", Type: "segment", Err: err}
	}

	if sw.finalized {
		return nil, &Error{Op: "write-segment", Type: "segment", Err: ErrWriterClosed}
	}

	// Validate segment index (allow dynamic expansion for streaming use cases)
	if index < 0 {
		return nil, &Error{Op: "write-segment", Type: "segment", Err: ErrInvalidSegment}
	}

	// Check for duplicate segment
	if _, exists := sw.metadata.Segments[index]; exists {
		return nil, &Error{Op: "write-segment", Type: "segment", Err: ErrDuplicateSegment}
	}

	// Check context cancellation
	select {
	case <-ctx.Done():
		return nil, &Error{Op: "write-segment", Type: "segment", Err: ctx.Err()}
	default:
	}

	originalSize := uint64(len(data)) + ocrypto.GcmStandardNonceSize

	// Create segment buffer for this segment's output
	buffer := &bytes.Buffer{}

	// Deterministic behavior: segment 0 gets ZIP header, others get raw data
	if index == 0 {
		// Segment 0: Write local file header + encrypted data
		if err := sw.writeLocalFileHeader(buffer); err != nil {
			return nil, &Error{Op: "write-segment", Type: "segment", Err: err}
		}
	}


	// Record segment metadata only (no payload retention). Payload bytes are returned
	// to the caller and may be uploaded; we keep only CRC and size for finalize.
	if err := sw.metadata.AddSegment(index, data, originalSize, originalCRC); err != nil {
		return nil, &Error{Op: "write-segment", Type: "segment", Err: err}
	}

	// Update payload entry metadata
	sw.payloadEntry.Size += originalSize
	sw.payloadEntry.CompressedSize += originalSize // Encrypted size

	// Return the bytes for this segment
	return buffer.Bytes(), nil
}

// Finalize completes the TDF creation with manifest and ZIP structures
func (sw *segmentWriter) Finalize(ctx context.Context, manifest []byte) ([]byte, error) {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	// Check if writer is closed or already finalized
	if err := sw.checkClosed(); err != nil {
		return nil, &Error{Op: "finalize", Type: "segment", Err: err}
	}

	if sw.finalized {
		return nil, &Error{Op: "finalize", Type: "segment", Err: ErrWriterClosed}
	}

	// Check context cancellation
	select {
	case <-ctx.Done():
		return nil, &Error{Op: "finalize", Type: "segment", Err: ctx.Err()}
	default:
	}

	// If no explicit order was provided, derive order from present indices (sorted).
	if len(sw.metadata.Order) == 0 {
		order := make([]int, 0, len(sw.metadata.Segments))
		for idx := range sw.metadata.Segments {
			order = append(order, idx)
		}
		sort.Ints(order)
		if err := sw.metadata.SetOrder(order); err != nil {
			// This should be an unreachable state, but handle it defensively.
			return nil, &Error{Op: "finalize", Type: "segment", Err: fmt.Errorf("internal error setting segment order: %w", err)}
		}
	}

	// Verify all segments are present
	if !sw.metadata.IsComplete() {
		return nil, &Error{Op: "finalize", Type: "segment", Err: ErrSegmentMissing}
	}

	// Compute final CRC32 by combining per-segment CRCs now that all are present
	sw.metadata.FinalizeCRC()

	// Create finalization buffer
	buffer := &bytes.Buffer{}

	// Since segments have already been written and assembled, we need to calculate
	// the total payload size that will exist when all segments are concatenated.
	// This is complex because segment 0 includes the local file header, but we need
	// to account for the data descriptor that gets added during finalization.

	// The total payload size is: header + data (data descriptor is separate)
	headerSize := localFileHeaderSize + uint64(len(sw.payloadEntry.Name))
	// Only include ZIP64 local extra when forcing ZIP64 in headers
	if sw.config.Zip64 == Zip64Always {
		headerSize += zip64ExtendedLocalInfoExtraFieldSize
	}

	// Total payload size = header + all data (no data descriptor in this calculation)
	totalPayloadSize := headerSize + sw.payloadEntry.CompressedSize

	// Decide whether payload descriptor must be ZIP64
	const max32 = ^uint32(0)
	needZip64ForPayload := sw.config.Zip64 == Zip64Always ||
		sw.payloadEntry.Size > uint64(max32) ||
		sw.payloadEntry.CompressedSize > uint64(max32)

	// 1. Write data descriptor for payload (fail if Zip64Never but required)
	if sw.config.Zip64 == Zip64Never && needZip64ForPayload {
		return nil, &Error{Op: "finalize", Type: "segment", Err: ErrZip64Required}
	}
	if err := sw.writeDataDescriptor(buffer, needZip64ForPayload); err != nil {
		return nil, &Error{Op: "finalize", Type: "segment", Err: err}
	}

	// 2. Update payload entry CRC32 and add to central directory
	sw.payloadEntry.CRC32 = sw.metadata.TotalCRC32
	sw.centralDir.AddFile(*sw.payloadEntry)

	// 3. Write manifest file (local header + data)
	manifestEntry := FileEntry{
		Name:           TDFManifestFileName,
		Offset:         totalPayloadSize + uint64(buffer.Len()), // Offset from start of complete file
		Size:           uint64(len(manifest)),
		CompressedSize: uint64(len(manifest)),
		CRC32:          crc32.ChecksumIEEE(manifest),
		ModTime:        time.Now(),
		IsStreaming:    false,
	}

	if err := sw.writeManifestFile(buffer, manifest, manifestEntry); err != nil {
		return nil, &Error{Op: "finalize", Type: "segment", Err: err}
	}

	// 4. Add manifest entry to central directory
	sw.centralDir.AddFile(manifestEntry)

	// 5. Write central directory
	sw.centralDir.Offset = totalPayloadSize + uint64(buffer.Len())
	// Decide if ZIP64 is needed for central directory/EOCD based on offset or forced mode
	needZip64ForCD := needZip64ForPayload || sw.config.Zip64 == Zip64Always || sw.centralDir.Offset > uint64(max32) || len(sw.centralDir.Entries) > int(^uint16(0))
	if sw.config.Zip64 == Zip64Never && needZip64ForCD {
		return nil, &Error{Op: "finalize", Type: "segment", Err: ErrZip64Required}
	}
	cdBytes, err := sw.centralDir.GenerateBytes(needZip64ForCD)
	if err != nil {
		return nil, &Error{Op: "finalize", Type: "segment", Err: err}
	}

	if _, err := buffer.Write(cdBytes); err != nil {
		return nil, &Error{Op: "finalize", Type: "segment", Err: err}
	}

	sw.finalized = true

	return buffer.Bytes(), nil
}

// CleanupSegment removes the presence marker for a segment index. Since payload
// bytes are not retained, this only affects metadata tracking. Calling this
// before Finalize will cause IsComplete() to fail for that index.
func (sw *segmentWriter) CleanupSegment(index int) error {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	// Remove segment from unprocessed map (no-op if already processed or not found)
	if _, ok := sw.metadata.Segments[index]; ok {
		delete(sw.metadata.Segments, index)
		if sw.metadata.presentCount > 0 {
			sw.metadata.presentCount--
		}
	}

	return nil
}

// writeDataDescriptor writes the data descriptor for the payload
func (sw *segmentWriter) writeDataDescriptor(buf *bytes.Buffer, zip64 bool) error {
	if zip64 {
		dataDesc := Zip64DataDescriptor{
			Signature:        dataDescriptorSignature,
			Crc32:            sw.metadata.TotalCRC32,
			CompressedSize:   sw.payloadEntry.CompressedSize,
			UncompressedSize: sw.payloadEntry.Size,
		}
		return binary.Write(buf, binary.LittleEndian, dataDesc)
	}

	dataDesc := Zip32DataDescriptor{
		Signature:        dataDescriptorSignature,
		Crc32:            sw.metadata.TotalCRC32,
		CompressedSize:   uint32(sw.payloadEntry.CompressedSize),
		UncompressedSize: uint32(sw.payloadEntry.Size),
	}
	return binary.Write(buf, binary.LittleEndian, dataDesc)
}

// writeManifestFile writes the manifest as a complete file entry
func (sw *segmentWriter) writeManifestFile(buf *bytes.Buffer, manifest []byte, entry FileEntry) error {
	fileTime, fileDate := sw.getTimeDateInMSDosFormat(entry.ModTime)

	// Write local file header for manifest
	header := LocalFileHeader{
		Signature:             fileHeaderSignature,
		Version:               zipVersion,
		GeneralPurposeBitFlag: 0, // Known size, no data descriptor
		CompressionMethod:     0, // No compression
		LastModifiedTime:      fileTime,
		LastModifiedDate:      fileDate,
		Crc32:                 entry.CRC32,
		CompressedSize:        uint32(entry.CompressedSize),
		UncompressedSize:      uint32(entry.Size),
		FilenameLength:        uint16(len(entry.Name)),
		ExtraFieldLength:      0,
	}

	if err := binary.Write(buf, binary.LittleEndian, header); err != nil {
		return err
	}

	// Write filename
	if _, err := buf.WriteString(entry.Name); err != nil {
		return err
	}

	// Write manifest data
	if _, err := buf.Write(manifest); err != nil {
		return err
	}

	return nil
}

// getTimeDateInMSDosFormat converts time to MS-DOS format
func (sw *segmentWriter) getTimeDateInMSDosFormat(t time.Time) (uint16, uint16) {
	const monthShift = 5

	timeInDos := t.Hour()<<11 | t.Minute()<<5 | t.Second()>>1
	dateInDos := (t.Year()-zipBaseYear)<<9 | int((t.Month())<<monthShift) | t.Day()

	return uint16(timeInDos), uint16(dateInDos)
}

// writeLocalFileHeader writes the ZIP local file header for the payload
func (sw *segmentWriter) writeLocalFileHeader(buf *bytes.Buffer) error {
	fileTime, fileDate := sw.getTimeDateInMSDosFormat(sw.payloadEntry.ModTime)

	header := LocalFileHeader{
		Signature:             fileHeaderSignature,
		Version:               zipVersion,
		GeneralPurposeBitFlag: dataDescriptorBitFlag,
		CompressionMethod:     0, // No compression
		LastModifiedTime:      fileTime,
		LastModifiedDate:      fileDate,
		Crc32:                 0, // Will be in data descriptor
		CompressedSize:        0, // Will be in data descriptor
		UncompressedSize:      0, // Will be in data descriptor
		FilenameLength:        uint16(len(sw.payloadEntry.Name)),
		ExtraFieldLength:      0,
	}

	// Only force ZIP64 markers in the local header when Zip64Always is set.
	if sw.config.Zip64 == Zip64Always {
		header.CompressedSize = zip64MagicVal
		header.UncompressedSize = zip64MagicVal
		header.ExtraFieldLength = zip64ExtendedLocalInfoExtraFieldSize
	}

	// Write local file header
	if err := binary.Write(buf, binary.LittleEndian, header); err != nil {
		return err
	}

	// Write filename
	if _, err := buf.WriteString(sw.payloadEntry.Name); err != nil {
		return err
	}

	// Write ZIP64 extra field if needed
	if header.ExtraFieldLength > 0 {
		zip64Extra := Zip64ExtendedLocalInfoExtraField{
			Signature:      zip64ExternalID,
			Size:           zip64ExtendedLocalInfoExtraFieldSize - extraFieldHeaderSize,
			OriginalSize:   0, // Will be in data descriptor
			CompressedSize: 0, // Will be in data descriptor
		}
		if err := binary.Write(buf, binary.LittleEndian, zip64Extra); err != nil {
			return err
		}
	}

	return nil
}
