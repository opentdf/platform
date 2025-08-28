package tdf

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/sdk/internal/archive"
	"github.com/opentdf/platform/sdk/tdf/keysplit"
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
//   - Out-of-order segment writing with contiguous processing optimization
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
	archiveWriter archive.SegmentWriter

	// State management
	mutex     sync.RWMutex // Protects concurrent access to writer state
	finalized bool         // Whether Finalize() has been called

	// segments stores segment metadata using sparse map for memory efficiency
	// Maps segment index to Segment metadata (hash, size information)
	segments map[int]Segment
	// maxSegmentIndex tracks the highest segment index written
	maxSegmentIndex int

	// Cryptographic state
	dek   []byte           // Data Encryption Key (32-byte AES key)  
	block ocrypto.AesGcm   // AES-GCM cipher for segment encryption
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
	archiveWriter := archive.NewSegmentTDFWriter(1)

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
		WriterConfig:  *config,
		archiveWriter: archiveWriter,
		dek:           dek,
		segments:      make(map[int]Segment), // Initialize sparse storage
		block:         block,
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
//   1. Input validation (index >= 0, writer not finalized, no duplicate segments)
//   2. AES-256-GCM encryption of the segment data
//   3. HMAC signature calculation for integrity verification
//   4. ZIP archive segment creation through the archive layer
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
func (w *Writer) WriteSegment(ctx context.Context, index int, data []byte) ([]byte, error) {
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

	// Encrypt directly without unnecessary copying - the archive layer will handle copying if needed
	segmentCipher, err := w.block.Encrypt(data)
	if err != nil {
		return nil, err
	}

	segmentSig, err := calculateSignature(segmentCipher, w.dek, w.segmentIntegrityAlgorithm, false) // Don't ever hex encode new tdf's
	if err != nil {
		return nil, err
	}

	w.segments[index] = Segment{
		Hash:          string(ocrypto.Base64Encode([]byte(segmentSig))),
		Size:          int64(len(data)), // Use original data length
		EncryptedSize: int64(len(segmentCipher)),
	}

	zipBytes, err := w.archiveWriter.WriteSegment(ctx, index, segmentCipher)
	if err != nil {
		return nil, err
	}

	return zipBytes, nil
}

// Finalize completes TDF creation and returns the final bytes and manifest.
//
// This method must be called after all segments have been written. It performs:
//   1. Validates all segments are present (no missing indices from 0 to maxSegmentIndex)
//   2. Generates cryptographic splits for key access controls
//   3. Builds the TDF policy from provided attributes  
//   4. Creates cryptographic assertions if specified
//   5. Calculates root integrity signature over all segment hashes
//   6. Generates the complete TDF manifest
//   7. Finalizes the ZIP archive structure
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
func (w *Writer) Finalize(ctx context.Context, opts ...Option[*WriterFinalizeConfig]) ([]byte, *Manifest, error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if w.finalized {
		return nil, nil, ErrAlreadyFinalized
	}

	cfg := &WriterFinalizeConfig{
		attributes:        make([]*policy.Value, 0),
		encryptedMetadata: "",
		payloadMimeType:   "application/octet-stream",
	}
	for _, opt := range opts {
		opt(cfg)
	}

	manifest := &Manifest{
		TDFVersion: TDFSpecVersion,
		Payload: Payload{
			MimeType:    cfg.payloadMimeType,
			Protocol:    "zip",
			Type:        "reference",
			URL:         archive.TDFPayloadFileName,
			IsEncrypted: true,
		},
	}

	// Generate splits using the splitter
	splitter := keysplit.NewXORSplitter(keysplit.WithDefaultKAS(cfg.defaultKas))
	result, err := splitter.GenerateSplits(ctx, cfg.attributes, w.dek)
	if err != nil {
		return nil, nil, err
	}

	// Build key access objects from the splits
	policyBytes, err := buildPolicy(cfg.attributes)
	if err != nil {
		return nil, nil, err
	}

	encryptInfo := EncryptionInformation{
		Policy: policyBytes,
		Method: Method{
			Algorithm:    kGCMCipherAlgorithm,
			IsStreamable: true,
		},
		IntegrityInformation: IntegrityInformation{
			// Copy segments to manifest for integrity verification
			Segments:      make([]Segment, w.maxSegmentIndex+1),
			RootSignature: RootSignature{},
		},
	}

	// Copy segments to manifest in proper order (map -> slice)
	for i := 0; i <= w.maxSegmentIndex; i++ {
		if segment, exists := w.segments[i]; exists {
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
	// Iterate through segments in order (0 to maxSegmentIndex)
	for i := 0; i <= w.maxSegmentIndex; i++ {
		segment, exists := w.segments[i]
		if !exists {
			return nil, nil, fmt.Errorf("missing segment %d", i)
		}
		if segment.Hash != "" {
			// Decode the base64-encoded segment hash to match reader validation
			decodedHash, err := ocrypto.Base64Decode([]byte(segment.Hash))
			if err != nil {
				return nil, nil, fmt.Errorf("failed to decode segment hash: %w", err)
			}
			aggregateHash.Write(decodedHash)
			continue
		}
		return nil, nil, errors.New("empty segment hash")
	}

	rootSignature, err := calculateSignature(aggregateHash.Bytes(), w.dek, w.integrityAlgorithm, false)
	if err != nil {
		return nil, nil, err
	}
	encryptInfo.RootSignature = RootSignature{
		Algorithm: w.integrityAlgorithm.String(),
		Signature: string(ocrypto.Base64Encode([]byte(rootSignature))),
	}

	keyAccessList, err := buildKeyAccessObjects(result, policyBytes, cfg.encryptedMetadata)
	if err != nil {
		return nil, nil, err
	}

	encryptInfo.KeyAccessObjs = keyAccessList
	manifest.EncryptionInformation = encryptInfo

	signedAssertions, err := w.buildAssertions(aggregateHash.Bytes(), cfg.assertions)
	if err != nil {
		return nil, nil, err
	}

	manifest.Assertions = signedAssertions

	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return nil, nil, err
	}

	finalBytes, err := w.archiveWriter.Finalize(ctx, manifestBytes)
	if err != nil {
		return nil, nil, err
	}

	if err := w.archiveWriter.Close(); err != nil {
		return nil, nil, err
	}

	w.finalized = true
	return finalBytes, manifest, nil
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
