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

	segments        []Segment
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
		segments:      make([]Segment, 0),
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

	// Extend the slice if needed and check for duplicate segments

	if newLen := index + 1; newLen > len(w.segments) {
		newSlice := make([]Segment, newLen)
		copy(newSlice, w.segments)
		w.segments = newSlice
	}

	// Check if segment is already populated (zero value check)
	if w.segments[index] != (Segment{}) {
		return nil, ErrSegmentAlreadyWritten
	}

	// copy data to new slice
	segmentCopy := make([]byte, len(data))
	copy(segmentCopy, data)

	if index > w.maxSegmentIndex {
		w.maxSegmentIndex = index
	}

	segmentCipher, err := w.block.Encrypt(segmentCopy)
	if err != nil {
		return nil, err
	}

	segmentSig, err := calculateSignature(segmentCipher, w.dek, w.segmentIntegrityAlgorithm, false) // Don't ever hex encode new tdf's
	if err != nil {
		return nil, err
	}

	w.segments[index] = Segment{
		Hash:          string(ocrypto.Base64Encode([]byte(segmentSig))),
		Size:          int64(len(segmentCopy)),
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
		addDefaultAssertion: false,
		attributes:          make([]*policy.Value, 0),
		encryptedMetadata:   "",
		payloadMimeType:     "application/octet-stream",
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
			Segments:      make([]Segment, len(w.segments)),
			RootSignature: RootSignature{},
		},
	}

	// Copy segments to manifest and calculate root signatures
	copy(encryptInfo.IntegrityInformation.Segments, w.segments)

	// Set default segment sizes for reader compatibility
	// Use the first segment as the default (streaming TDFs have variable segment sizes)
	if len(w.segments) > 0 {
		firstSegment := w.segments[0]
		encryptInfo.IntegrityInformation.DefaultSegmentSize = firstSegment.Size
		encryptInfo.IntegrityInformation.DefaultEncryptedSegSize = firstSegment.EncryptedSize
	}

	// Set segment hash algorithm
	encryptInfo.IntegrityInformation.SegmentHashAlgorithm = w.segmentIntegrityAlgorithm.String()

	var aggregateHash bytes.Buffer
	for _, segment := range w.segments {
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

	// Assertions
	if cfg.addDefaultAssertion {
		systemMeta, err := GetSystemMetadataAssertionConfig()
		if err != nil {
			return nil, nil, err
		}
		cfg.assertions = append(cfg.assertions, systemMeta)
	}

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
