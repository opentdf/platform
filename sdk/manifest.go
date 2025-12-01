package sdk

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/opentdf/platform/lib/ocrypto"
)

type Segment struct {
	Hash          string `json:"hash"`
	Size          int64  `json:"segmentSize"`
	EncryptedSize int64  `json:"encryptedSegmentSize"`
}

type RootSignature struct {
	Algorithm string `json:"alg"`
	Signature string `json:"sig"`
}

type IntegrityInformation struct {
	RootSignature           `json:"rootSignature"`
	SegmentHashAlgorithm    string    `json:"segmentHashAlg"`
	DefaultSegmentSize      int64     `json:"segmentSizeDefault"`
	DefaultEncryptedSegSize int64     `json:"encryptedSegmentSizeDefault"`
	Segments                []Segment `json:"segments"`
}

type KeyAccess struct {
	KeyType            string      `json:"type"`
	KasURL             string      `json:"url"`
	Protocol           string      `json:"protocol"`
	WrappedKey         string      `json:"wrappedKey"`
	PolicyBinding      interface{} `json:"policyBinding"`
	EncryptedMetadata  string      `json:"encryptedMetadata,omitempty"`
	KID                string      `json:"kid,omitempty"`
	SplitID            string      `json:"sid,omitempty"`
	SchemaVersion      string      `json:"schemaVersion,omitempty"`
	EphemeralPublicKey string      `json:"ephemeralPublicKey,omitempty"`
}

type PolicyBinding struct {
	Alg  string `json:"alg"`
	Hash string `json:"hash"`
}

type Method struct {
	Algorithm    string `json:"algorithm"`
	IV           string `json:"iv"`
	IsStreamable bool   `json:"isStreamable"`
}

type Payload struct {
	Type        string `json:"type"`
	URL         string `json:"url"`
	Protocol    string `json:"protocol"`
	MimeType    string `json:"mimeType"`
	IsEncrypted bool   `json:"isEncrypted"`
	// IntegrityInformation IntegrityInformation `json:"integrityInformation"`
}

type EncryptionInformation struct {
	KeyAccessType        string      `json:"type"`
	Policy               string      `json:"policy"`
	KeyAccessObjs        []KeyAccess `json:"keyAccess"`
	Method               Method      `json:"method"`
	IntegrityInformation `json:"integrityInformation"`
}

type Manifest struct {
	EncryptionInformation `json:"encryptionInformation"`
	Payload               `json:"payload"`
	Assertions            []Assertion `json:"assertions,omitempty"`
	TDFVersion            string      `json:"schemaVersion,omitempty"`
}

type attributeObject struct {
	Attribute   string `json:"attribute"`
	DisplayName string `json:"displayName"`
	IsDefault   bool   `json:"isDefault"`
	PubKey      string `json:"pubKey"`
	KasURL      string `json:"kasURL"`
}

type PolicyObject struct {
	UUID string `json:"uuid"`
	Body struct {
		DataAttributes []attributeObject `json:"dataAttributes"`
		Dissem         []string          `json:"dissem"`
	} `json:"body"`
}

type EncryptedMetadata struct {
	Cipher string `json:"ciphertext"`
	Iv     string `json:"iv"`
}

// ComputeAggregateHash computes the aggregate hash from all segment hashes.
// This is used as input to assertion signature calculation.
//
// The aggregate hash is computed by:
//  1. Base64 decoding each segment hash
//  2. Concatenating all decoded hashes in order
//
// Returns the aggregate hash as bytes, or error if base64 decoding fails.
func (m *Manifest) ComputeAggregateHash() ([]byte, error) {
	aggregateHash := &bytes.Buffer{}
	for _, segment := range m.EncryptionInformation.IntegrityInformation.Segments {
		decodedHash, err := ocrypto.Base64Decode([]byte(segment.Hash))
		if err != nil {
			return nil, fmt.Errorf("failed to decode segment hash: %w", err)
		}
		aggregateHash.Write(decodedHash)
	}
	return aggregateHash.Bytes(), nil
}

// ComputeAssertionSignature computes the assertion signature binding.
// Automatically determines the correct encoding format from the manifest.
//
// Format: base64(aggregateHash + assertionHash)
//
// The signature is computed by:
//  1. Computing the aggregate hash from manifest segments
//  2. Determining encoding format (hex vs raw bytes) from TDF version
//  3. Decoding the hex assertion hash to raw bytes
//  4. Concatenating aggregateHash + chosen hash bytes
//  5. Base64 encoding the result
//
// Parameters:
//   - assertionHash: The assertion hash as hex-encoded bytes
//
// Returns the base64-encoded signature string, or error if computation fails.
func (m *Manifest) ComputeAssertionSignature(assertionHash []byte) (string, error) {
	aggregateHash, err := m.ComputeAggregateHash()
	if err != nil {
		return "", err
	}

	// Determine encoding format from manifest
	useHex := m.TDFVersion == ""

	// Decode hex assertion hash to raw bytes
	hashOfAssertion := make([]byte, hex.DecodedLen(len(assertionHash)))
	_, err = hex.Decode(hashOfAssertion, assertionHash)
	if err != nil {
		return "", fmt.Errorf("error decoding hex string: %w", err)
	}

	// Use raw bytes or hex based on useHex flag (legacy TDF compatibility)
	var hashToUse []byte
	if useHex {
		hashToUse = assertionHash
	} else {
		hashToUse = hashOfAssertion
	}

	// Combine aggregate hash with assertion hash
	var completeHashBuilder bytes.Buffer
	completeHashBuilder.Write(aggregateHash)
	completeHashBuilder.Write(hashToUse)

	return string(ocrypto.Base64Encode(completeHashBuilder.Bytes())), nil
}
