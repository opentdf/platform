package sdk

// System Metadata Assertion Provider

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"time"
)

const (
	// SystemMetadataAssertionID is the standard identifier for system metadata assertions.
	SystemMetadataAssertionID = "system-metadata"

	// SystemMetadataSchemaV1 is the schema for system metadata assertions.
	// Compatible with Java, JS, and Go SDKs.
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
// Returns the current schema for cross-SDK compatibility with Java and JS.
func (p *SystemMetadataAssertionProvider) Schema() string {
	return SystemMetadataSchemaV1
}

func (p SystemMetadataAssertionProvider) Bind(_ context.Context, _ Manifest) (Assertion, error) {
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

	// Compute assertion signature using standard format
	assertionSignature, err := ComputeAssertionSignature(p.aggregateHash, hashOfAssertionAsHex, p.useHex)
	if err != nil {
		return assertion, fmt.Errorf("failed to compute assertion signature: %w", err)
	}

	if err := assertion.Sign(string(hashOfAssertionAsHex), assertionSignature, assertionSigningKey); err != nil {
		return assertion, fmt.Errorf("failed to sign assertion: %w", err)
	}
	return assertion, nil
}

func (p SystemMetadataAssertionProvider) Verify(ctx context.Context, a Assertion, _ Reader) error {
	// SECURITY: Validate schema is the supported schema
	// This prevents routing assertions with unknown schemas to this validator
	// Defense in depth: checked here AND via hash verification later
	isValidSchema := a.Statement.Schema == SystemMetadataSchemaV1 ||
		a.Statement.Schema == "" // Empty schema for legacy compatibility

	if !isValidSchema {
		return fmt.Errorf("%w: unsupported schema %q (expected %q)",
			ErrAssertionFailure{ID: a.ID}, a.Statement.Schema, SystemMetadataSchemaV1)
	}

	// Use shared DEK-based verification logic
	assertionKey := AssertionKey{
		Alg: AssertionKeyAlgHS256,
		Key: p.payloadKey,
	}

	return verifyDEKSignedAssertion(ctx, a, assertionKey, p.aggregateHash, p.useHex)
}

// Validate does nothing.
func (p SystemMetadataAssertionProvider) Validate(_ context.Context, _ Assertion, _ Reader) error {
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
