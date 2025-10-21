package sdk

// System Metadata Assertion Provider

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/opentdf/platform/lib/ocrypto"
)

const (
	// SystemMetadataAssertionID is the standard identifier for system metadata assertions.
	SystemMetadataAssertionID = "system-metadata"

	// SystemMetadataSchemaV2 is the current schema URI for system metadata assertions.
	// This format uses the root signature directly as the binding signature.
	SystemMetadataSchemaV2 = "urn:opentdf:system:metadata:v2"

	// SystemMetadataSchemaV1 is the schema for system metadata assertions.
	// Compatible with Java and JS SDKs.
	SystemMetadataSchemaV1 = "system-metadata-v1"
)

// SystemMetadataAssertionProvider provides information about the system that is running the application.
// Implements AssertionBuilder and AssertionValidator
type SystemMetadataAssertionProvider struct {
	useHex           bool
	payloadKey       []byte
	aggregateHash    string
	verificationMode AssertionVerificationMode
}

func NewSystemMetadataAssertionProvider(useHex bool, payloadKey []byte, aggregateHash string) *SystemMetadataAssertionProvider {
	return &SystemMetadataAssertionProvider{
		useHex:           useHex,
		payloadKey:       payloadKey,
		aggregateHash:    aggregateHash,
		verificationMode: FailFast, // Default to secure mode
	}
}

// SetVerificationMode updates the verification mode for this validator.
// This is typically called by the SDK when registering validators to propagate
// the global verification mode setting.
func (p *SystemMetadataAssertionProvider) SetVerificationMode(mode AssertionVerificationMode) {
	p.verificationMode = mode
}

// Schema returns the schema URI this validator handles.
// Returns V1 for legacy TDFs (useHex=true) and V2 for modern TDFs (useHex=false).
// - V1 (system-metadata-v1): Compatible with Java/JS SDKs and legacy Go TDFs
// - V2 (urn:opentdf:system:metadata:v2): Modern URN format for TDF spec >= 4.3.0
// The validator accepts both schemas for backward/forward compatibility.
func (p *SystemMetadataAssertionProvider) Schema() string {
	if p.useHex {
		// Legacy TDF format (version < 4.3.0) - use V1 for compatibility
		return SystemMetadataSchemaV1
	}
	// Modern TDF format (version >= 4.3.0) - use V2
	return SystemMetadataSchemaV2
}

func (p SystemMetadataAssertionProvider) Bind(_ context.Context, m Manifest) (Assertion, error) {
	// Get the assertion config
	ac, err := GetSystemMetadataAssertionConfig()
	if err != nil {
		return Assertion{}, fmt.Errorf("failed to get system metadata assertion config: %w", err)
	}

	// Override schema based on useHex flag (legacy vs modern TDF)
	ac.Statement.Schema = p.Schema()

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

func (p SystemMetadataAssertionProvider) Verify(ctx context.Context, a Assertion, r Reader) error {
	// SECURITY: Validate schema is one of the supported schemas
	// This prevents routing assertions with unknown schemas to this validator
	// Defense in depth: checked here AND via hash verification later
	isValidSchema := a.Statement.Schema == SystemMetadataSchemaV1 ||
		a.Statement.Schema == SystemMetadataSchemaV2 ||
		a.Statement.Schema == ""

	if !isValidSchema {
		return fmt.Errorf("%w: unsupported schema %q (expected %q or %q)",
			ErrAssertionFailure{ID: a.ID}, a.Statement.Schema, SystemMetadataSchemaV1, SystemMetadataSchemaV2)
	}

	// Schema V1 or empty schema handling
	_ = ctx // unused context

	// Assertions without cryptographic bindings cannot be verified - this is a security issue
	if a.Binding.Signature == "" {
		return fmt.Errorf("%w: assertion has no cryptographic binding", ErrAssertionFailure{ID: a.ID})
	}

	assertionKey := AssertionKey{
		Alg: AssertionKeyAlgHS256,
		Key: p.payloadKey,
	}

	// Verify the JWT with key
	assertionHash, assertionSig, _, err := a.Verify(assertionKey)
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

	// Auto-detect binding format: check if assertionSig matches root signature
	// v2 format: assertionSig = rootSignature
	// v1 (legacy) format: assertionSig = base64(aggregateHash + assertionHash)
	//
	// This allows any assertion (regardless of schema) to use either format
	if assertionSig == r.manifest.RootSignature.Signature {
		// Current v2 format validation
		return nil
	}

	// Try legacy format verification
	// This handles assertions from Java SDK and other legacy implementations
	return p.verifyLegacyAssertion(a.ID, assertionSig, hashOfAssertionAsHex)
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
			Schema: SystemMetadataSchemaV1,
			Value:  string(metadataJSON),
		},
	}, nil
}
