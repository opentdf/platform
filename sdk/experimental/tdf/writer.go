// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package tdf

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"log/slog"
	"sort"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/sdk/experimental/tdf/keysplit"
	"github.com/opentdf/platform/sdk/internal/archive2"
)

const (
	// kKeySize is the AES key size in bytes (256-bit key)
	kKeySize = 32
	// kGCMCipherAlgorithm specifies the encryption algorithm used for TDF payloads
	kGCMCipherAlgorithm = "AES-256-GCM"
	// tdfAsZip indicates the TDF uses ZIP as the container format
	tdfAsZip = "zip"
	// tdfZipReference indicates the payload is stored as a reference in the ZIP
	tdfZipReference = "reference"
)

// SegmentResult contains the result of writing a segment
type SegmentResult struct {
	Data          []byte `json:"data"`          // Encrypted segment bytes (for streaming)
	Index         int    `json:"index"`         // Segment index
	Hash          string `json:"hash"`          // Base64-encoded integrity hash
	PlaintextSize int64  `json:"plaintextSize"` // Original data size
	EncryptedSize int64  `json:"encryptedSize"` // Encrypted data size
	CRC32         uint32 `json:"crc32"`         // CRC32 checksum
}

// FinalizeResult contains the complete TDF creation result
type FinalizeResult struct {
	Data          []byte    `json:"data"`          // Final TDF bytes (manifest + metadata)
	Manifest      *Manifest `json:"manifest"`      // Complete manifest object
	TotalSegments int       `json:"totalSegments"` // Number of segments written
	TotalSize     int64     `json:"totalSize"`     // Total plaintext size
	EncryptedSize int64     `json:"encryptedSize"` // Total encrypted size
}

var (
	// ErrAlreadyFinalized is returned when attempting operations on a finalized writer
	ErrAlreadyFinalized = errors.New("tdf is already finalized")
	// ErrInvalidSegmentIndex is returned for negative segment indices
	ErrInvalidSegmentIndex = errors.New("invalid segment index")
	// ErrSegmentAlreadyWritten is returned when trying to write to an existing segment index
	ErrSegmentAlreadyWritten = errors.New("segment already written")
)

// Writer provides streaming TDF creation with out-of-order segment support.
//
// The Writer enables creation of TDF files by writing individual segments
// that can arrive in any order. It handles encryption, integrity verification,
// and proper ZIP archive structure generation.
//
// Key features:
//   - Variable-length segments with sparse index support
//   - Out-of-order segment writing without buffering payloads
//   - Memory-efficient handling through segment cleanup
//   - Cryptographic assertions and integrity verification
//   - Custom attribute-based access controls
//
// Thread safety: Writers require external synchronization for concurrent access.
// Each WriteSegment call must be serialized, but multiple Writers can operate
// independently.
//
// Example usage:
//
//	writer, err := NewWriter(ctx, WithIntegrityAlgorithm(HS256))
//	if err != nil {
//		return err
//	}
//	defer writer.Close()
//
//	// Write segments (can be out-of-order)
//	_, err = writer.WriteSegment(ctx, 1, []byte("second"))
//	_, err = writer.WriteSegment(ctx, 0, []byte("first"))
//
//	// Finalize with attributes
//	finalBytes, manifest, err := writer.Finalize(ctx, WithAttributeValues(attrs))
type Writer struct {
	// WriterConfig embeds configuration options for the TDF writer
	WriterConfig

	// archiveWriter handles the underlying ZIP archive creation
	archiveWriter archive2.SegmentWriter

	// State management
	mutex     sync.RWMutex // Protects concurrent access to writer state
	finalized bool         // Whether Finalize() has been called

	// manifest holds the finalized manifest after Finalize() is called.
	// Before finalization, GetManifest() will synthesize a stub manifest
	// from the current writer state. Do not rely on the stub for
	// verification — it is informational only until Finalize completes.
	manifest *Manifest

	// segments stores segment metadata using sparse map for memory efficiency
	// Maps segment index to Segment metadata (hash, size information)
	segments map[int]Segment
	// maxSegmentIndex tracks the highest segment index written
	maxSegmentIndex int

	// Cryptographic state
	dek   []byte         // Data Encryption Key (32-byte AES key)
	block ocrypto.AesGcm // AES-GCM cipher for segment encryption

	// Initial settings provided at Writer creation; used by Finalize if not overridden
	initialAttributes []*policy.Value
	initialDefaultKAS *policy.SimpleKasKey
}

// NewWriter creates a new experimental TDF Writer with streaming support.
//
// The writer is initialized with secure defaults:
//   - HS256 integrity algorithms for both root and segment verification
//   - AES-256-GCM encryption for all segments
//   - Dynamic segment expansion supporting sparse indices
//   - Memory-efficient segment processing
//
// Configuration options can be provided to customize:
//   - Integrity algorithm selection (HS256, GMAC)
//   - Segment integrity algorithm (independent of root algorithm)
//
// The writer generates a unique Data Encryption Key (DEK) and initializes
// the underlying archive writer for ZIP structure management.
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
func NewWriter(_ context.Context, opts ...Option[*WriterConfig]) (*Writer, error) {
	// Initialize Config
	config := &WriterConfig{
		integrityAlgorithm:        HS256,
		segmentIntegrityAlgorithm: HS256,
	}

	for _, opt := range opts {
		opt(config)
	}

	// Initialize archive writer - start with 1 segment and expand dynamically
	archiveWriter := archive2.NewSegmentTDFWriter(1, archive2.WithZip64())

	// Generate DEK
	dek, err := ocrypto.RandomBytes(kKeySize)
	if err != nil {
		return nil, err
	}

	// Initialize AES GCM Provider
	block, err := ocrypto.NewAESGcm(dek)
	if err != nil {
		return nil, err
	}

	return &Writer{
		WriterConfig:      *config,
		archiveWriter:     archiveWriter,
		dek:               dek,
		segments:          make(map[int]Segment), // Initialize sparse storage
		block:             block,
		initialAttributes: config.initialAttributes,
		initialDefaultKAS: config.initialDefaultKAS,
	}, nil
}

// WriteSegment encrypts and writes a data segment at the specified index.
//
// Segments can be written in any order and will be properly assembled during
// finalization. Each segment is independently encrypted with AES-256-GCM and
// has its integrity hash calculated for verification.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - index: Zero-based segment index (must be non-negative, sparse indices supported)
//   - data: Raw data to encrypt and store in this segment
//
// Returns the encrypted segment bytes that should be stored/uploaded, and any error.
// The returned bytes include ZIP structure elements and can be assembled in any order.
//
// The function performs:
//  1. Input validation (index >= 0, writer not finalized, no duplicate segments)
//  2. AES-256-GCM encryption of the segment data
//  3. HMAC signature calculation for integrity verification
//  4. ZIP archive segment creation through the archive layer
//
// Memory optimization: Uses sparse storage to avoid O(n²) memory growth
// for high or non-contiguous segment indices.
//
// Error conditions:
//   - ErrAlreadyFinalized: Writer has been finalized, no more segments accepted
//   - ErrInvalidSegmentIndex: Negative index provided
//   - ErrSegmentAlreadyWritten: Segment index already contains data
//   - Context cancellation: If ctx.Done() is signaled
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
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if w.finalized {
		return nil, ErrAlreadyFinalized
	}

	if index < 0 {
		return nil, ErrInvalidSegmentIndex
	}

	// Check for duplicate segments using map lookup
	if _, exists := w.segments[index]; exists {
		return nil, ErrSegmentAlreadyWritten
	}

	if index > w.maxSegmentIndex {
		w.maxSegmentIndex = index
	}

	// Calculate CRC32 before encryption for integrity tracking
	crc32Checksum := crc32.ChecksumIEEE(data)

	// Encrypt directly without unnecessary copying - the archive layer will handle copying if needed
	segmentCipher, err := w.block.Encrypt(data)
	if err != nil {
		return nil, err
	}

	segmentSig, err := calculateSignature(segmentCipher, w.dek, w.segmentIntegrityAlgorithm, false) // Don't ever hex encode new tdf's
	if err != nil {
		return nil, err
	}

	segmentHash := string(ocrypto.Base64Encode([]byte(segmentSig)))
	w.segments[index] = Segment{
		Hash:          segmentHash,
		Size:          int64(len(data)), // Use original data length
		EncryptedSize: int64(len(segmentCipher)),
	}

	zipBytes, err := w.archiveWriter.WriteSegment(ctx, index, segmentCipher)
	if err != nil {
		return nil, err
	}

	return &SegmentResult{
		Data:          zipBytes,
		Index:         index,
		Hash:          segmentHash,
		PlaintextSize: int64(len(data)),
		EncryptedSize: int64(len(segmentCipher)),
		CRC32:         crc32Checksum,
	}, nil
}

// Finalize completes TDF creation and returns the final bytes and manifest.
//
// This method must be called after all segments have been written. It performs:
//  1. Validates all segments are present (no missing indices from 0 to maxSegmentIndex)
//  2. Generates cryptographic splits for key access controls
//  3. Builds the TDF policy from provided attributes
//  4. Creates cryptographic assertions if specified
//  5. Calculates root integrity signature over all segment hashes
//  6. Generates the complete TDF manifest
//  7. Finalizes the ZIP archive structure
//
// The finalization process handles:
//   - Key splitting for attribute-based access controls
//   - Policy generation from attribute values
//   - Encrypted metadata storage in key access objects
//   - Manifest JSON generation and validation
//   - ZIP central directory and data descriptor creation
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
//
// Returns:
//   - finalBytes: Complete ZIP archive bytes ready for storage/transmission
//   - manifest: TDF manifest containing encryption and integrity information
//   - error: Any error during finalization process
//
// Error conditions:
//   - ErrAlreadyFinalized: Finalize already called
//   - Missing segments: Gaps in segment indices (e.g., segments 0,1,3 written but 2 missing)
//   - Key splitting failures: Invalid attributes or KAS configuration
//   - Manifest generation errors: JSON marshaling failures
//   - Archive finalization errors: ZIP structure generation failures
//   - Context cancellation: If ctx.Done() is signaled
//
// Example:
//
//	// Basic finalization
//	finalBytes, manifest, err := writer.Finalize(ctx)
//
//	// With attributes and metadata
//	finalBytes, manifest, err := writer.Finalize(ctx,
//		WithAttributeValues(attrs),
//		WithEncryptedMetadata("sensitive info"),
//		WithPayloadMimeType("application/json"),
//	)
//
// Performance note: Finalization is O(n) where n is the number of segments.
// Memory usage is proportional to manifest size, not total data size.

func (w *Writer) Finalize(ctx context.Context, opts ...Option[*WriterFinalizeConfig]) (*FinalizeResult, error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if w.finalized {
		return nil, ErrAlreadyFinalized
	}

	cfg := &WriterFinalizeConfig{
		attributes:        make([]*policy.Value, 0),
		encryptedMetadata: "",
		payloadMimeType:   "application/octet-stream",
	}
	for _, opt := range opts {
		opt(cfg)
	}
	manifest, totalPlaintextSize, totalEncryptedSize, err := w.getManifest(ctx, cfg)
	if err != nil {
		return nil, err
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}

	finalBytes, err := w.archiveWriter.Finalize(ctx, manifestBytes)
	if err != nil {
		return nil, err
	}

	if err := w.archiveWriter.Close(); err != nil {
		return nil, err
	}

	// Persist the final manifest for later retrieval via GetManifest.
	w.manifest = manifest
	w.finalized = true
	return &FinalizeResult{
		Data:          finalBytes,
		Manifest:      manifest,
		TotalSegments: len(manifest.EncryptionInformation.IntegrityInformation.Segments),
		TotalSize:     totalPlaintextSize,
		EncryptedSize: totalEncryptedSize,
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
//     informational or client-side pre-calculation purposes only.
//
// No logging is performed; callers should consult this documentation for
// the caveat about pre-finalize state.
func (w *Writer) GetManifest(ctx context.Context, opts ...Option[*WriterFinalizeConfig]) (*Manifest, error) {
	w.mutex.RLock()
	defer w.mutex.RUnlock()
	cfg := &WriterFinalizeConfig{
		attributes:        make([]*policy.Value, 0),
		encryptedMetadata: "",
		payloadMimeType:   "application/octet-stream",
	}
	for _, opt := range opts {
		opt(cfg)
	}
	if !w.finalized {
		slog.Warn("GetManifest called before Finalize; returned manifest is a stub and not complete, pre-finalize state may not include all segments or attributes.")
	}

	manifest, _, _, err := w.getManifest(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return manifest, nil
}

func (w *Writer) getManifest(ctx context.Context, cfg *WriterFinalizeConfig) (*Manifest, int64, int64, error) {
	// If already finalized and we have the final manifest, return a copy.
	if w.finalized && w.manifest != nil {
		return cloneManifest(w.manifest), 0, 0, nil
	}
	// Archive layer will infer the same order by sorting present indices.
	// Merge writer-level initial settings if finalize options omitted them.
	if len(cfg.attributes) == 0 && len(w.initialAttributes) > 0 {
		cfg.attributes = w.initialAttributes
	}
	if cfg.defaultKas == nil && w.initialDefaultKAS != nil {
		cfg.defaultKas = w.initialDefaultKAS
	}

	manifest := &Manifest{
		TDFVersion: TDFSpecVersion,
		Payload: Payload{
			MimeType:    cfg.payloadMimeType,
			Protocol:    tdfAsZip,
			Type:        tdfZipReference,
			URL:         archive2.TDFPayloadFileName,
			IsEncrypted: true,
		},
	}
	// Determine finalize order by collecting all present segment indices and sorting.
	// This densifies sparse indices automatically and ignores any gaps.
	order := make([]int, 0, len(w.segments))
	for idx := range w.segments {
		order = append(order, idx)
	}
	sort.Ints(order)
	// If caller provided keepSegments, restrict to that subset and order.
	if len(cfg.keepSegments) > 0 {
		subset := make([]int, 0, len(cfg.keepSegments))
		seen := make(map[int]struct{}, len(cfg.keepSegments))
		for _, idx := range cfg.keepSegments {
			if idx < 0 {
				return nil, 0, 0, fmt.Errorf("WithSegments contains invalid index %d (must be >= 0)", idx)
			}
			if _, ok := w.segments[idx]; !ok {
				return nil, 0, 0, fmt.Errorf("WithSegments references segment %d which was not written", idx)
			}
			if _, dup := seen[idx]; dup {
				return nil, 0, 0, fmt.Errorf("WithSegments contains duplicate index %d", idx)
			}
			seen[idx] = struct{}{}
			subset = append(subset, idx)
		}
		order = subset
	}

	// Generate splits using the splitter
	splitter := keysplit.NewXORSplitter(keysplit.WithDefaultKAS(cfg.defaultKas))
	result, err := splitter.GenerateSplits(ctx, cfg.attributes, w.dek)
	if err != nil {
		return nil, 0, 0, err
	}

	// Build key access objects from the splits
	policyBytes, err := buildPolicy(cfg.attributes)
	if err != nil {
		return nil, 0, 0, err
	}

	encryptInfo := EncryptionInformation{
		KeyAccessType: kSplitKeyType,
		Policy:        string(ocrypto.Base64Encode(policyBytes)),
		Method: Method{
			Algorithm:    kGCMCipherAlgorithm,
			IsStreamable: true,
		},
		IntegrityInformation: IntegrityInformation{
			// Copy segments to manifest for integrity verification in finalize order
			Segments:      make([]Segment, len(order)),
			RootSignature: RootSignature{},
		},
	}

	// Copy segments to manifest in finalize order (pack densely)
	for i, idx := range order {
		if segment, exists := w.segments[idx]; exists {
			encryptInfo.IntegrityInformation.Segments[i] = segment
		}
	}

	// Set default segment sizes for reader compatibility
	// Use the first segment as the default (streaming TDFs have variable segment sizes)
	if firstSegment, exists := w.segments[0]; exists {
		encryptInfo.IntegrityInformation.DefaultSegmentSize = firstSegment.Size
		encryptInfo.IntegrityInformation.DefaultEncryptedSegSize = firstSegment.EncryptedSize
	}

	// Set segment hash algorithm
	encryptInfo.IntegrityInformation.SegmentHashAlgorithm = w.segmentIntegrityAlgorithm.String()

	var aggregateHash bytes.Buffer
	// Calculate totals and iterate through segments in finalize order
	var totalPlaintextSize, totalEncryptedSize int64
	for _, i := range order {
		segment, exists := w.segments[i]
		if !exists {
			return nil, 0, 0, fmt.Errorf("segment %d not written; cannot finalize", i)
		}
		if segment.Hash != "" {
			// Accumulate sizes for result
			totalPlaintextSize += segment.Size
			totalEncryptedSize += segment.EncryptedSize

			// Decode the base64-encoded segment hash to match reader validation
			decodedHash, err := ocrypto.Base64Decode([]byte(segment.Hash))
			if err != nil {
				return nil, 0, 0, fmt.Errorf("failed to decode segment hash: %w", err)
			}
			aggregateHash.Write(decodedHash)
			continue
		}
		return nil, 0, 0, errors.New("empty segment hash")
	}

	rootSignature, err := calculateSignature(aggregateHash.Bytes(), w.dek, w.integrityAlgorithm, false)
	if err != nil {
		return nil, 0, 0, err
	}
	encryptInfo.RootSignature = RootSignature{
		Algorithm: w.integrityAlgorithm.String(),
		Signature: string(ocrypto.Base64Encode([]byte(rootSignature))),
	}

	keyAccessList, err := buildKeyAccessObjects(result, policyBytes, cfg.encryptedMetadata)
	if err != nil {
		return nil, 0, 0, err
	}

	encryptInfo.KeyAccessObjs = keyAccessList
	manifest.EncryptionInformation = encryptInfo

	signedAssertions, err := w.buildAssertions(aggregateHash.Bytes(), cfg.assertions)
	if err != nil {
		return nil, 0, 0, err
	}

	manifest.Assertions = signedAssertions
	return manifest, totalPlaintextSize, totalEncryptedSize, nil
}

// cloneManifest makes a shallow-deep copy of a Manifest to avoid callers
// mutating internal writer state.
func cloneManifest(in *Manifest) *Manifest {
	if in == nil {
		return nil
	}
	out := *in // copy by value

	// Copy slices to new backing arrays
	if in.EncryptionInformation.KeyAccessObjs != nil {
		out.EncryptionInformation.KeyAccessObjs = append([]KeyAccess(nil), in.EncryptionInformation.KeyAccessObjs...)
	}
	if in.EncryptionInformation.Segments != nil {
		out.EncryptionInformation.Segments = append([]Segment(nil), in.EncryptionInformation.Segments...)
	}
	if in.Assertions != nil {
		out.Assertions = append([]Assertion(nil), in.Assertions...)
	}
	return &out
}

func buildPolicy(values []*policy.Value) ([]byte, error) {
	policy := &Policy{
		UUID: uuid.NewString(),
		Body: PolicyBody{
			DataAttributes: make([]PolicyAttribute, 0),
			Dissem:         make([]string, 0),
		},
	}

	for _, value := range values {
		policy.Body.DataAttributes = append(policy.Body.DataAttributes, PolicyAttribute{
			Attribute: value.GetFqn(),
		})
	}
	policyBytes, err := json.Marshal(policy)
	if err != nil {
		return nil, err
	}

	return policyBytes, nil
}

func (w *Writer) buildAssertions(aggregateHash []byte, assertions []AssertionConfig) ([]Assertion, error) {
	signedAssertion := make([]Assertion, 0)
	for _, assertion := range assertions {
		// Store a temporary assertion
		tmpAssertion := Assertion{}

		tmpAssertion.ID = assertion.ID
		tmpAssertion.Type = assertion.Type
		tmpAssertion.Scope = assertion.Scope
		tmpAssertion.Statement = assertion.Statement
		tmpAssertion.AppliesToState = assertion.AppliesToState

		hashOfAssertionAsHex, err := tmpAssertion.GetHash()
		if err != nil {
			return nil, err
		}

		hashOfAssertion := make([]byte, hex.DecodedLen(len(hashOfAssertionAsHex)))
		_, err = hex.Decode(hashOfAssertion, hashOfAssertionAsHex)
		if err != nil {
			return nil, fmt.Errorf("error decoding hex string: %w", err)
		}

		var completeHashBuilder strings.Builder
		completeHashBuilder.WriteString(string(aggregateHash))
		completeHashBuilder.Write(hashOfAssertion)

		encoded := ocrypto.Base64Encode([]byte(completeHashBuilder.String()))

		assertionSigningKey := AssertionKey{}

		// Set default to HS256 and payload key
		assertionSigningKey.Alg = AssertionKeyAlgHS256
		assertionSigningKey.Key = w.dek

		if !assertion.SigningKey.IsEmpty() {
			assertionSigningKey = assertion.SigningKey
		}

		if err := tmpAssertion.Sign(string(hashOfAssertionAsHex), string(encoded), assertionSigningKey); err != nil {
			return nil, fmt.Errorf("failed to sign assertion: %w", err)
		}

		signedAssertion = append(signedAssertion, tmpAssertion)
	}
	return signedAssertion, nil
}
