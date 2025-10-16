package sdk

// System Metadata Assertion Provider

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"time"

	"github.com/opentdf/platform/lib/ocrypto"
)

const (
	SystemMetadataAssertionID = "system-metadata"
	SystemMetadataSchemaV1    = "system-metadata-v1"
	// SystemMetadataSchemaV2 use root signature instead of aggregateHash
	SystemMetadataSchemaV2 = "system-metadata-v2"
)

// systemMetadataAssertionPattern is pre-compiled regex for system metadata assertions
var systemMetadataAssertionPattern = regexp.MustCompile("^" + SystemMetadataAssertionID + "$")

// SystemMetadataAssertionProvider provides information about the system that is running the application.
// Implements AssertionBuilder and AssertionValidator
type SystemMetadataAssertionProvider struct {
	useHex        bool
	payloadKey    []byte
	aggregateHash string
}

func NewSystemMetadataAssertionProvider(useHex bool, payloadKey []byte, aggregateHash string) *SystemMetadataAssertionProvider {
	return &SystemMetadataAssertionProvider{
		useHex:        useHex,
		payloadKey:    payloadKey,
		aggregateHash: aggregateHash,
	}
}

func (p SystemMetadataAssertionProvider) Bind(_ context.Context, m Manifest) (Assertion, error) {
	// Get the assertion config
	ac, err := GetSystemMetadataAssertionConfig()
	if err != nil {
		return Assertion{}, fmt.Errorf("failed to get system metadata assertion config: %w", err)
	}

	// Build the assertion
	assertion := Assertion{
		ID:             ac.ID,
		Type:           ac.Type,
		Scope:          ac.Scope,
		Statement:      ac.Statement,
		AppliesToState: ac.AppliesToState,
	}

	hashOfAssertionAsHex, err := assertion.GetHash()
	if err != nil {
		return assertion, err
	}

	assertionSigningKey := AssertionKey{
		Alg: AssertionKeyAlgHS256,
		Key: p.payloadKey,
	}

	// aggregation hash replaced with manifest root signature
	if err := assertion.Sign(string(hashOfAssertionAsHex), m.RootSignature.Signature, assertionSigningKey); err != nil {
		return assertion, fmt.Errorf("failed to sign assertion: %w", err)
	}
	return assertion, nil
}

func (p SystemMetadataAssertionProvider) Verify(_ context.Context, a Assertion, r Reader) error {
	assertionKey := AssertionKey{
		Alg: AssertionKeyAlgHS256,
		Key: p.payloadKey,
	}

	assertionHash, assertionSig, err := a.Verify(assertionKey)
	if err != nil {
		if errors.Is(err, errAssertionVerifyKeyFailure) {
			return fmt.Errorf("assertion verification failed: %w", err)
		}
		return fmt.Errorf("%w: assertion verification failed: %w", ErrAssertionFailure{ID: a.ID}, err)
	}

	// Get the hash of the assertion
	hashOfAssertionAsHex, err := a.GetHash()
	if err != nil {
		return fmt.Errorf("%w: failed to get hash of assertion: %w", ErrAssertionFailure{ID: a.ID}, err)
	}
	if string(hashOfAssertionAsHex) != assertionHash {
		return fmt.Errorf("%w: assertion hash missmatch", ErrAssertionFailure{ID: a.ID})
	}

	// Dual-mode validation: support both v1 (legacy) and v2 (current) schemas
	// v1: assertion signed with base64(aggregateHash + assertionHash)
	// v2: assertion signed with rootSignature
	isLegacySchema := a.Statement.Schema == SystemMetadataSchemaV1 || a.Statement.Schema == ""

	if isLegacySchema {
		return p.verifyLegacyAssertion(a.ID, assertionSig, hashOfAssertionAsHex)
	} else if assertionSig != r.manifest.RootSignature.Signature {
		// Current validation (v2+ TDFs)
		// Expected signature format: rootSignature
		return fmt.Errorf("%w: failed integrity check on assertion signature", ErrAssertionFailure{ID: a.ID})
	}

	return nil
}

// Validate does nothing.
func (p SystemMetadataAssertionProvider) Validate(_ context.Context, _ Assertion, _ Reader) error {
	return nil
}

// verifyLegacyAssertion validates assertions using the pre-v2 schema format
// where signatures are base64(aggregateHash + assertionHash)
func (p SystemMetadataAssertionProvider) verifyLegacyAssertion(assertionID, assertionSig string, hashOfAssertionAsHex []byte) error {
	// Legacy validation (pre-v2 TDFs)
	// Expected signature format: base64(aggregateHash + assertionHash)
	hashOfAssertion := make([]byte, hex.DecodedLen(len(hashOfAssertionAsHex)))
	_, err := hex.Decode(hashOfAssertion, hashOfAssertionAsHex)
	if err != nil {
		return fmt.Errorf("%w: error decoding hex string: %w", ErrAssertionFailure{ID: assertionID}, err)
	}

	// Use raw bytes or hex based on useHex flag (legacy TDF compatibility)
	var hashToUse []byte
	if p.useHex {
		hashToUse = hashOfAssertionAsHex
	} else {
		hashToUse = hashOfAssertion
	}

	// Combine aggregate hash with assertion hash (legacy format)
	var completeHashBuilder bytes.Buffer
	completeHashBuilder.WriteString(p.aggregateHash)
	completeHashBuilder.Write(hashToUse)

	expectedSig := string(ocrypto.Base64Encode(completeHashBuilder.Bytes()))

	if assertionSig != expectedSig {
		return fmt.Errorf("%w: failed integrity check on legacy assertion signature", ErrAssertionFailure{ID: assertionID})
	}

	return nil
}

// GetSystemMetadataAssertionConfig adds information about the system that is running the application to the assertion.
func GetSystemMetadataAssertionConfig() (AssertionConfig, error) {
	// Define the JSON structure
	type Metadata struct {
		TDFSpecVersion string `json:"tdf_spec_version,omitempty"`
		CreationDate   string `json:"creation_date,omitempty"`
		OS             string `json:"operating_system,omitempty"`
		SDKVersion     string `json:"sdk_version,omitempty"`
		GoVersion      string `json:"go_version,omitempty"`
		Architecture   string `json:"architecture,omitempty"`
	}

	// Populate the metadata
	metadata := Metadata{
		TDFSpecVersion: TDFSpecVersion,
		CreationDate:   time.Now().Format(time.RFC3339),
		OS:             runtime.GOOS,
		SDKVersion:     "Go-" + Version,
		GoVersion:      runtime.Version(),
		Architecture:   runtime.GOARCH,
	}

	// Marshal the metadata to JSON
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return AssertionConfig{}, fmt.Errorf("failed to marshal system metadata: %w", err)
	}

	return AssertionConfig{
		ID:             SystemMetadataAssertionID,
		Type:           BaseAssertion,
		Scope:          PayloadScope,
		AppliesToState: Unencrypted,
		Statement: Statement{
			Format: StatementFormatJSON,
			Schema: SystemMetadataSchemaV2,
			Value:  string(metadataJSON),
		},
	}, nil
}
