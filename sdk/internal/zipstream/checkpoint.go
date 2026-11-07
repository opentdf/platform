package zipstream

import (
	"context"
	"errors"
	"time"
)

// SegmentCheckpoint contains archive metadata only, never payload bytes.
// SegmentCheckpointEntry describes accepted ciphertext without retaining it.
type SegmentCheckpointEntry struct {
	Index int    `json:"index"`
	Size  uint64 `json:"size"`
	CRC32 uint32 `json:"crc32"`
}

type SegmentCheckpoint struct {
	Zip64            Zip64Mode                       `json:"zip64"`
	MaxSegments      int                             `json:"maxSegments"`
	MaxNonZip64Value uint64                          `json:"maxNonZip64Value"`
	ModTime          time.Time                       `json:"modTime"`
	Segments         map[int]*SegmentCheckpointEntry `json:"segments"`
}

// SnapshotSegments requires a quiescent, unfinalized standard writer.
func SnapshotSegments(writer SegmentWriter) (*SegmentCheckpoint, error) {
	sw, ok := writer.(*segmentWriter)
	if !ok {
		return nil, errors.New("unsupported archive writer")
	}
	sw.mu.RLock()
	defer sw.mu.RUnlock()
	if sw.finalized {
		return nil, ErrWriterClosed
	}
	if err := sw.checkClosed(); err != nil {
		return nil, err
	}
	cp := &SegmentCheckpoint{Zip64: sw.config.Zip64, MaxSegments: sw.config.MaxSegments, MaxNonZip64Value: sw.config.MaxNonZip64Value, ModTime: sw.payloadEntry.ModTime, Segments: make(map[int]*SegmentCheckpointEntry)}
	for i, entry := range sw.metadata.Segments {
		cp.Segments[i] = &SegmentCheckpointEntry{Index: entry.Index, Size: entry.Size, CRC32: entry.CRC32}
	}
	return cp, nil
}

// RestoreSegments rebuilds archive accounting without retaining ciphertext.
func RestoreSegments(cp *SegmentCheckpoint) (SegmentWriter, error) {
	if cp == nil || cp.Zip64 < Zip64Auto || cp.Zip64 > Zip64Never || cp.MaxSegments <= 0 {
		return nil, ErrInvalidSegment
	}
	sw := NewSegmentTDFWriter(1, WithZip64Mode(cp.Zip64), WithMaxSegments(cp.MaxSegments), WithMaxNonZip64Value(cp.MaxNonZip64Value), WithClock(func() time.Time { return cp.ModTime }))
	for i, entry := range cp.Segments {
		if entry == nil || i < 0 || entry.Index != i {
			return nil, ErrInvalidSegment
		}
		if _, err := sw.WriteSegment(context.Background(), i, entry.Size, entry.CRC32); err != nil {
			return nil, err
		}
	}
	return sw, nil
}
