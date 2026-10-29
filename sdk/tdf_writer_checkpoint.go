package sdk

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/opentdf/platform/sdk/internal/zipstream"
)

// ResumableTDFWriter produces TDF segments with exportable encryption state.
// Experimental. Callers must serialize access to its methods.
type ResumableTDFWriter struct {
	writer   *chunkedWriter
	mimeType string
}

// NewResumableTDFWriter resolves key access before emitting ciphertext.
// Custom assertions are currently unsupported.
func (s SDK) NewResumableTDFWriter(ctx context.Context, opts ...TDFOption) (*ResumableTDFWriter, error) {
	cfg, err := newTDFConfig(opts...)
	if err != nil {
		return nil, err
	}
	if len(cfg.assertions) != 0 || cfg.addDefaultAssertion {
		return nil, errors.New("resumable writer: assertions are unsupported")
	}
	if err = cfg.initKAOTemplate(ctx, s); err != nil {
		return nil, err
	}
	w, err := s.newTDFChunkedWriter(ctx, cfg, zipstream.Zip64Always, 0)
	if err != nil {
		return nil, err
	}
	return &ResumableTDFWriter{writer: w, mimeType: cfg.mimeType}, nil
}

// WriteSegment emits ciphertext and any ZIP prefix.
func (w *ResumableTDFWriter) WriteSegment(ctx context.Context, index int, data []byte) (*ChunkedSegmentResult, error) {
	return w.writer.WriteSegment(ctx, index, data)
}

// Finalize emits the manifest and archive footer.
func (w *ResumableTDFWriter) Finalize(ctx context.Context) (*ChunkedFinalizeResult, error) {
	return w.writer.Finalize(ctx, WithChunkedMimeType(w.mimeType))
}

// SegmentSize returns the configured plaintext segment size.
func (w *ResumableTDFWriter) SegmentSize() int64 { return w.writer.segmentSize }

const maxTDFWriterCheckpointBytes = 256 << 20

type tdfWriterState struct {
	Version        int                          `json:"version"`
	DEK            []byte                       `json:"dek"`
	Encryptions    uint64                       `json:"encryptions"`
	MaxEncryptions uint64                       `json:"maxEncryptions"`
	SegmentSize    int64                        `json:"segmentSize"`
	UseHex         bool                         `json:"useHex"`
	ExcludeVersion bool                         `json:"excludeVersion"`
	Policy         string                       `json:"policy"`
	KeyAccess      []KeyAccess                  `json:"keyAccess"`
	Segments       map[int]Segment              `json:"segments"`
	Archive        *zipstream.SegmentCheckpoint `json:"archive"`
	MimeType       string                       `json:"mimeType"`
}

// Snapshot captures a quiescent writer. The returned bytes contain the plaintext
// DEK: keep them private in memory or authenticate and encrypt before saving.
// Never log the payload. No cipher, client, reader or worker is retained.
func (w *ResumableTDFWriter) Snapshot() ([]byte, error) {
	cw := w.writer
	cw.mu.RLock()
	defer cw.mu.RUnlock()
	if cw.finalized {
		return nil, ErrChunkedAlreadyFinalized
	}
	if cw.unusable != nil {
		return nil, cw.unusable
	}
	ka, ok := cw.keyAccess.(staticKeyAccess)
	if !ok {
		return nil, errors.New("resumable writer: unsupported key access")
	}
	cp := tdfWriterState{Version: 1, DEK: cw.dek, Encryptions: cw.encryptions, MaxEncryptions: cw.maxEncryptions, SegmentSize: cw.segmentSize, UseHex: cw.useHex, ExcludeVersion: cw.excludeVersion, Policy: ka.policy, KeyAccess: ka.kaos, Segments: make(map[int]Segment), MimeType: w.mimeType}
	for i, slot := range cw.segments {
		if !slot.written {
			return nil, ErrChunkedWriteInFlight
		}
		cp.Segments[i] = slot.seg
	}
	var err error
	cp.Archive, err = zipstream.SnapshotSegments(cw.archiveWriter)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(cp)
	if err != nil {
		return nil, err
	}
	if len(encoded) > maxTDFWriterCheckpointBytes {
		return nil, errors.New("resumable writer: oversized checkpoint")
	}
	return encoded, nil
}

// RestoreResumableTDFWriter reconstructs state without a client or KAS call.
// Input must be a trusted Snapshot or authenticated storage. Previously emitted
// ciphertext must be replayed verbatim; only new segments are encrypted again.
func RestoreResumableTDFWriter(data []byte) (*ResumableTDFWriter, error) {
	if len(data) > maxTDFWriterCheckpointBytes {
		return nil, errors.New("resumable writer: oversized checkpoint")
	}
	var cp tdfWriterState
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, errors.New("resumable writer: invalid checkpoint")
	}
	if cp.Version != 1 || len(cp.DEK) != kKeySize || cp.SegmentSize < minSegmentSize || cp.SegmentSize > maxSegmentSize || cp.MaxEncryptions == 0 || cp.MaxEncryptions > maxAESGCMSegmentsPerDEK || cp.Encryptions > cp.MaxEncryptions || cp.Encryptions < uint64(len(cp.Segments)) || cp.Policy == "" || len(cp.KeyAccess) == 0 || cp.Archive == nil || len(cp.Archive.Segments) != len(cp.Segments) {
		return nil, errors.New("resumable writer: invalid checkpoint state")
	}
	archive, err := zipstream.RestoreSegments(cp.Archive)
	if err != nil {
		return nil, err
	}
	w, err := newChunkedWriter(chunkedWriterConfig{cipherFactory: defaultSegmentCipherFactory, archiveFactory: defaultArchiveWriterFactory, clock: systemClock{}, dek: cp.DEK, segmentSize: cp.SegmentSize, maxEncryptions: cp.MaxEncryptions, useHex: cp.UseHex, excludeVersion: cp.ExcludeVersion, keyAccess: staticKeyAccess{policy: cp.Policy, kaos: cp.KeyAccess}})
	if err != nil {
		return nil, err
	}
	w.archiveWriter = archive
	w.encryptions = cp.Encryptions
	for i, seg := range cp.Segments {
		entry, ok := cp.Archive.Segments[i]
		if !ok || entry == nil || seg.EncryptedSize != int64(entry.Size) {
			return nil, errors.New("resumable writer: inconsistent segment")
		}
		w.segments[i] = &segmentSlot{seg: seg, written: true}
	}
	return &ResumableTDFWriter{writer: w, mimeType: cp.MimeType}, nil
}
