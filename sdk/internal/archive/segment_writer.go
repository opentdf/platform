package archive

import (
	"bytes"
	"context"
	"encoding/binary"
	"hash/crc32"
	"sync"
	"time"
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

	// Calculate original data CRC32 (before encryption)
	originalCRC := crc32.ChecksumIEEE(data)
	originalSize := uint64(len(data))

	// Create segment buffer for this segment's output
	segmentBuf := sw.getBuffer()
	defer sw.putBuffer(segmentBuf)

	buffer := bytes.NewBuffer(segmentBuf)

	// Deterministic behavior: segment 0 gets ZIP header, others get raw data
	if index == 0 {
		// Segment 0: Write local file header + encrypted data
		if err := sw.writeLocalFileHeader(buffer); err != nil {
			return nil, &Error{Op: "write-segment", Type: "segment", Err: err}
		}
	}

	// All segments: write the encrypted data
	if _, err := buffer.Write(data); err != nil {
		return nil, &Error{Op: "write-segment", Type: "segment", Err: err}
	}

	// AddSegment now handles memory management efficiently with contiguous processing
	// Only unprocessed segments are stored, processed segments are immediately freed
	if err := sw.metadata.AddSegment(index, data, originalSize, originalCRC); err != nil {
		return nil, &Error{Op: "write-segment", Type: "segment", Err: err}
	}

	// Update payload entry metadata
	sw.payloadEntry.Size += originalSize
	sw.payloadEntry.CompressedSize += uint64(len(data)) // Encrypted size
	sw.payloadEntry.CRC32 = crc32.Update(sw.payloadEntry.CRC32, crc32IEEETable, data)

	// Don't track totalPayloadBytes here - calculate deterministically during finalization

	// Return the bytes for this segment (copy to avoid buffer reuse issues)
	result := make([]byte, buffer.Len())
	copy(result, buffer.Bytes())

	return result, nil
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

	// Verify all segments are present
	if !sw.metadata.IsComplete() {
		return nil, &Error{Op: "finalize", Type: "segment", Err: ErrSegmentMissing}
	}

	// With contiguous processing, CRC32 is automatically calculated as segments are processed
	// TotalCRC32 is ready when IsComplete() returns true

	// Create finalization buffer
	finalBuf := sw.getBuffer()
	defer sw.putBuffer(finalBuf)

	buffer := bytes.NewBuffer(finalBuf)

	// Since segments have already been written and assembled, we need to calculate
	// the total payload size that will exist when all segments are concatenated.
	// This is complex because segment 0 includes the local file header, but we need
	// to account for the data descriptor that gets added during finalization.

	// The total payload size is: header + data (data descriptor is separate)
	headerSize := localFileHeaderSize + uint64(len(sw.payloadEntry.Name))
	if sw.config.EnableZip64 {
		headerSize += zip64ExtendedLocalInfoExtraFieldSize
	}

	// Total payload size = header + all data (no data descriptor in this calculation)
	totalPayloadSize := headerSize + sw.payloadEntry.CompressedSize

	// Remove debug output

	// 1. Write data descriptor for payload
	if err := sw.writeDataDescriptor(buffer); err != nil {
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
	cdBytes, err := sw.centralDir.GenerateBytes(sw.config.EnableZip64)
	if err != nil {
		return nil, &Error{Op: "finalize", Type: "segment", Err: err}
	}

	if _, err := buffer.Write(cdBytes); err != nil {
		return nil, &Error{Op: "finalize", Type: "segment", Err: err}
	}

	sw.finalized = true

	// Return the final bytes
	result := make([]byte, buffer.Len())
	copy(result, buffer.Bytes())

	return result, nil
}

// CleanupSegment clears unprocessed segment data from memory after it's been uploaded
// With the new contiguous processing approach, most segments are automatically cleaned
// up as they're processed. Only unprocessed (non-contiguous) segments remain in memory.
func (sw *segmentWriter) CleanupSegment(index int) error {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	// Check if segment is still unprocessed (stored in Segments map)
	if _, exists := sw.metadata.Segments[index]; exists {
		// Clear the data to free memory and remove from map
		// Note: This means the segment cannot be processed later for contiguous chunks
		// Only call CleanupSegment if you're sure you won't need this segment again
		delete(sw.metadata.Segments, index)
	}

	// If segment was already processed (not in Segments map), no action needed
	// Processed segments are automatically cleaned up during contiguous processing

	return nil
}

// writeDataDescriptor writes the data descriptor for the payload
func (sw *segmentWriter) writeDataDescriptor(buf *bytes.Buffer) error {
	if sw.config.EnableZip64 {
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
	fileTime, fileDate := sw.getTimeDateUnMSDosFormat(entry.ModTime)

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

// getTimeDateUnMSDosFormat converts time to MS-DOS format
func (sw *segmentWriter) getTimeDateUnMSDosFormat(t time.Time) (uint16, uint16) {
	const monthShift = 5

	timeInDos := t.Hour()<<11 | t.Minute()<<5 | t.Second()>>1
	dateInDos := (t.Year()-zipBaseYear)<<9 | int((t.Month())<<monthShift) | t.Day()

	return uint16(timeInDos), uint16(dateInDos)
}

// writeLocalFileHeader writes the ZIP local file header for the payload
func (sw *segmentWriter) writeLocalFileHeader(buf *bytes.Buffer) error {
	fileTime, fileDate := sw.getTimeDateUnMSDosFormat(sw.payloadEntry.ModTime)

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

	// Enable ZIP64 if needed
	if sw.config.EnableZip64 {
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
