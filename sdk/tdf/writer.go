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
	kKeySize            = 32
	kGCMCipherAlgorithm = "AES-256-GCM"
	tdfAsZip            = "zip"
	tdfZipReference     = "reference"
)

var (
	ErrAlreadyFinalized      = errors.New("tdf is already finalized")
	ErrInvalidSegmentIndex   = errors.New("invalid segment index")
	ErrSegmentAlreadyWritten = errors.New("segment already written")
)

type Writer struct {
	// WriterConfig configuration for the TDF writer
	WriterConfig

	archiveWriter archive.SegmentWriter

	// State management
	mutex     sync.RWMutex
	finalized bool

	segments        map[int]Segment // Sparse storage for variable segment indices  
	maxSegmentIndex int

	dek   []byte
	block ocrypto.AesGcm
}

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
