// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package tdf

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/sdk"
)

// SegmentResult contains the result of writing a segment
type SegmentResult struct {
	TDFData       io.Reader // Reader for the full TDF segment (nonce + encrypted data + zip structures)
	Index         int       `json:"index"`         // Segment index
	Hash          string    `json:"hash"`          // Base64-encoded integrity hash
	PlaintextSize int64     `json:"plaintextSize"` // Original data size
	EncryptedSize int64     `json:"encryptedSize"` // Encrypted data size
}

// FinalizeResult contains the complete TDF creation result
type FinalizeResult struct {
	Data          []byte    `json:"data"`          // Final TDF bytes (manifest + metadata)
	Manifest      *Manifest `json:"manifest"`      // Complete manifest object
	TotalSegments int       `json:"totalSegments"` // Number of segments written
	TotalSize     int64     `json:"totalSize"`     // Total plaintext size
	EncryptedSize int64     `json:"encryptedSize"` // Total encrypted size
}

// These are the stable SDK's error values rather than copies of them,
// so errors.Is matches whether a caller compares against the
// experimental or the sdk-scoped name.
var (
	// ErrAlreadyFinalized is returned when attempting operations on a finalized writer
	ErrAlreadyFinalized = sdk.ErrChunkedAlreadyFinalized
	// ErrInvalidSegmentIndex is returned for negative segment indices
	ErrInvalidSegmentIndex = sdk.ErrChunkedInvalidSegmentIndex
	// ErrMissingSegmentZero is returned when Finalize is called without segment 0
	ErrMissingSegmentZero = sdk.ErrChunkedMissingSegmentZero
	// ErrSegmentAlreadyWritten is returned when trying to write to an existing segment index
	ErrSegmentAlreadyWritten = sdk.ErrChunkedSegmentAlreadyWritten
)

// Writer provides streaming TDF creation with out-of-order segment support.
//
// The Writer enables creation of TDF files by writing individual segments
// that can arrive in any order. It handles encryption, integrity verification,
// and proper ZIP archive structure generation.
//
// Key features:
//   - Variable-length segments with sparse index support above index 0
//   - Out-of-order segment writing without buffering payloads
//   - Memory-efficient handling through segment cleanup
//   - Cryptographic assertions and integrity verification
//   - Custom attribute-based access controls
//
// Thread safety: WriteSegment may be called concurrently for distinct
// indices, but not twice for the same index.
//
// The writing itself is [sdk.ChunkedWriter]; this type adds the
// multi-KAS ABAC key splitting in [xorSplitter] and this package's
// option style. Callers that only need a single KAS can use
// [sdk.NewChunkedWriter] directly.
//
// Example usage:
//
//	writer, err := NewWriter(ctx, WithIntegrityAlgorithm(HS256))
//	if err != nil {
//		return err
//	}
//
//	// Write segments (can be out-of-order)
//	_, err = writer.WriteSegment(ctx, 1, []byte("second"))
//	_, err = writer.WriteSegment(ctx, 0, []byte("first"))
//
//	// Finalize with attributes
//	result, err := writer.Finalize(ctx, WithAttributeValues(attrs))
type Writer struct {
	// WriterConfig embeds configuration options for the TDF writer
	WriterConfig

	// inner is the stable per-segment writer this type delegates to.
	inner sdk.ChunkedWriter

	// finalized mirrors inner's state so GetManifest can warn that a
	// pre-finalize manifest is a stub. inner does not expose it.
	finalized atomic.Bool
}

// NewWriter creates a new experimental TDF Writer with streaming support.
//
// The writer is initialized with secure defaults:
//   - HS256 integrity algorithms for both root and segment verification
//   - AES-256-GCM encryption for all segments
//   - Dynamic segment expansion supporting sparse indices (index 0 always required)
//   - Memory-efficient segment processing
//
// Configuration options can be provided to customize:
//   - Integrity algorithm selection (HS256, GMAC)
//   - Segment integrity algorithm (independent of root algorithm)
//   - Attributes and default KAS to fall back on at Finalize time
//
// Returns an error if:
//   - DEK generation fails (cryptographic entropy issues)
//   - AES-GCM cipher initialization fails (invalid key)
//   - Archive writer creation fails (resource constraints)
//
// Example:
//
//	// Default configuration
//	writer, err := NewWriter(ctx)
//
//	// Custom integrity algorithms
//	writer, err := NewWriter(ctx,
//		WithIntegrityAlgorithm(GMAC),
//		WithSegmentIntegrityAlgorithm(HS256),
//	)
func NewWriter(ctx context.Context, opts ...Option[*WriterConfig]) (*Writer, error) {
	config := &WriterConfig{
		integrityAlgorithm:        HS256,
		segmentIntegrityAlgorithm: HS256,
	}
	for _, opt := range opts {
		opt(config)
	}

	// A nil KAS means "unset" here -- WithDefaultKASForWriter has always
	// accepted one -- but the stable option rejects nil, so leave it off
	// rather than forwarding. The splitter reports the missing KAS at
	// Finalize as ErrNoDefaultKAS, which is what callers already handle.
	chunkedOpts := []sdk.ChunkedWriterOption{
		sdk.WithChunkedIntegrityAlgorithm(sdk.IntegrityAlgorithm(config.integrityAlgorithm)),
		sdk.WithChunkedSegmentIntegrityAlgorithm(sdk.IntegrityAlgorithm(config.segmentIntegrityAlgorithm)),
		sdk.WithChunkedInitialAttributes(config.initialAttributes),
		sdk.WithChunkedKeySplitter(xorSplitter{}),
		sdk.WithChunkedTargetMode(config.targetMode),
	}
	if config.initialDefaultKAS != nil {
		chunkedOpts = append(chunkedOpts, sdk.WithChunkedDefaultKAS(config.initialDefaultKAS))
	}

	inner, err := sdk.NewChunkedWriter(ctx, chunkedOpts...)
	if err != nil {
		return nil, err
	}

	return &Writer{WriterConfig: *config, inner: inner}, nil
}

// WriteSegment encrypts and writes a data segment at the specified index.
//
// Segments can be written in any order and will be properly assembled during
// finalization. Each segment is independently encrypted with AES-256-GCM and
// has its integrity hash calculated for verification.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - index: Zero-based segment index (must be non-negative; sparse indices supported,
//     but index 0 must eventually be written)
//   - data: Raw data to encrypt and store in this segment
//
// Returns the encrypted segment bytes that should be stored/uploaded, and any error.
// The returned bytes include ZIP structure elements. They must be concatenated in
// ascending index order to form the payload, whatever order they were produced in.
//
// Error conditions:
//   - ErrAlreadyFinalized: Writer has been finalized, no more segments accepted
//   - ErrInvalidSegmentIndex: Negative index provided
//   - ErrSegmentAlreadyWritten: Segment index already contains data
//   - Encryption errors: AES-GCM operation failures
//   - Archive errors: ZIP structure creation failures
//
// Example:
//
//	// Write segments out-of-order
//	segment1, err := writer.WriteSegment(ctx, 1, []byte("second part"))
//	segment0, err := writer.WriteSegment(ctx, 0, []byte("first part"))
//
//	// Store/upload segment bytes (e.g., to S3)
//	uploadToS3(segment0, "part-000")
//	uploadToS3(segment1, "part-001")
func (w *Writer) WriteSegment(ctx context.Context, index int, data []byte) (*SegmentResult, error) {
	res, err := w.inner.WriteSegment(ctx, index, data)
	if err != nil {
		return nil, err
	}
	return &SegmentResult{
		TDFData:       res.TDFData,
		Index:         res.Index,
		Hash:          res.Hash,
		PlaintextSize: res.PlaintextSize,
		EncryptedSize: res.EncryptedSize,
	}, nil
}

// Finalize completes TDF creation and returns the final bytes and manifest.
//
// This method must be called after all segments have been written. It
// generates the key splits for attribute-based access control, builds the
// policy, signs any assertions, calculates the root integrity signature over
// all segment hashes, and closes the ZIP archive.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - opts: Configuration options for finalization behavior
//
// Available options:
//   - WithAttributeValues: Set attribute-based access controls
//   - WithEncryptedMetadata: Include encrypted metadata
//   - WithPayloadMimeType: Specify payload MIME type
//   - WithAssertions: Add cryptographic assertions
//   - WithDefaultKAS: Set default Key Access Server
//   - WithSegments: Choose which written segments the manifest describes
//
// Error conditions:
//   - ErrAlreadyFinalized: Finalize already called
//   - ErrMissingSegmentZero: segment 0 was never written; it carries the payload's
//     ZIP local file header, which every recorded offset is measured from
//   - Missing segments: an index named by WithSegments that was never written
//   - Key splitting failures: Invalid attributes or KAS configuration
//   - Manifest generation errors: JSON marshaling failures
//   - Archive finalization errors: ZIP structure generation failures
//
// Example:
//
//	// Basic finalization
//	result, err := writer.Finalize(ctx)
//
//	// With attributes and metadata
//	result, err := writer.Finalize(ctx,
//		WithAttributeValues(attrs),
//		WithEncryptedMetadata("sensitive info"),
//		WithPayloadMimeType("application/json"),
//	)
//
// Performance note: Finalization is O(n) where n is the number of segments.
// Memory usage is proportional to manifest size, not total data size.
func (w *Writer) Finalize(ctx context.Context, opts ...Option[*WriterFinalizeConfig]) (*FinalizeResult, error) {
	res, err := w.inner.Finalize(ctx, finalizeOptions(opts)...)
	if err != nil {
		return nil, err
	}
	w.finalized.Store(true)
	return &FinalizeResult{
		Data:          res.Data,
		Manifest:      res.Manifest,
		TotalSegments: res.TotalSegments,
		TotalSize:     res.TotalSize,
		EncryptedSize: res.EncryptedSize,
	}, nil
}

// GetManifest returns the current manifest snapshot.
//
// Behavior:
//   - If Finalize has completed, this returns the finalized manifest.
//   - If called before Finalize, this returns a stub manifest synthesized
//     from the writer's current state (segments present so far, algorithm
//     selections, and payload defaults). This pre-finalize manifest is not
//     complete and must not be used for verification; it is provided for
//     informational or client-side pre-calculation purposes only. A
//     warning is logged in that case.
func (w *Writer) GetManifest(ctx context.Context, opts ...Option[*WriterFinalizeConfig]) (*Manifest, error) {
	if !w.finalized.Load() {
		slog.Warn("getmanifest called before finalize; returned manifest is a stub and not complete, pre-finalize state may not include all segments or attributes.")
	}
	return w.inner.GetManifest(ctx, finalizeOptions(opts)...)
}

// finalizeOptions translates this package's finalize options into the
// stable writer's equivalents.
//
// The two option sets are applied in sequence rather than mapped
// one-to-one: this package's Option is a plain mutator over a config
// struct, so the config is materialized first and then read off. That
// also preserves the defaults callers have always seen -- notably the
// "application/octet-stream" MIME type -- independent of whichever
// defaults the stable writer happens to use.
func finalizeOptions(opts []Option[*WriterFinalizeConfig]) []sdk.ChunkedFinalizeOption {
	cfg := &WriterFinalizeConfig{
		attributes:        make([]*policy.Value, 0),
		encryptedMetadata: "",
		payloadMimeType:   "application/octet-stream",
	}
	for _, opt := range opts {
		opt(cfg)
	}
	out := []sdk.ChunkedFinalizeOption{
		sdk.WithChunkedAttributes(cfg.attributes),
		sdk.WithChunkedEncryptedMetadata(cfg.encryptedMetadata),
		sdk.WithChunkedMimeType(cfg.payloadMimeType),
		sdk.WithChunkedSegments(cfg.keepSegments),
		sdk.WithChunkedAssertions(cfg.assertions),
	}
	// Omitted rather than forwarded as nil, for the reason given in
	// NewWriter: the stable option rejects nil, this package's does not.
	if cfg.defaultKas != nil {
		out = append(out, sdk.WithChunkedDefaultKASForFinalize(cfg.defaultKas))
	}
	return out
}
