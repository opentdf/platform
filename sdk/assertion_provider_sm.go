package sdk

// System Metadata Assertion Provider

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/opentdf/platform/lib/ocrypto"
)

const (
	SystemMetadataAssertionID = "system-metadata"
	SystemMetadataSchemaV1    = "system-metadata-v1"
)

// SystemMetadataAssertionProvider provides information about the system that is running the application.
// Implements AssertionProvider
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

func (s SystemMetadataAssertionProvider) Configure(_ context.Context) (AssertionConfig, error) {
	return GetSystemMetadataAssertionConfig()
}

func (s SystemMetadataAssertionProvider) Bind(ctx context.Context, ac AssertionConfig, m Manifest) (Assertion, error) {
	tmpAssertion := Assertion{
		ID:             ac.ID,
		Type:           ac.Type,
		Scope:          ac.Scope,
		Statement:      ac.Statement,
		AppliesToState: ac.AppliesToState,
	}

	hashOfAssertionAsHex, err := tmpAssertion.GetHash()
	if err != nil {
		return tmpAssertion, err
	}

	hashOfAssertion := make([]byte, hex.DecodedLen(len(hashOfAssertionAsHex)))
	_, err = hex.Decode(hashOfAssertion, hashOfAssertionAsHex)
	if err != nil {
		return tmpAssertion, fmt.Errorf("error decoding hex string: %w", err)
	}

	var completeHashBuilder strings.Builder
	completeHashBuilder.WriteString(s.aggregateHash)
	if s.useHex {
		completeHashBuilder.Write(hashOfAssertionAsHex)
	} else {
		completeHashBuilder.Write(hashOfAssertion)
	}

	encoded := ocrypto.Base64Encode([]byte(completeHashBuilder.String()))

	// Fall back to default provider
	assertionSigningKey := AssertionKey{}
	// Set default to HS256 and payload key
	assertionSigningKey.Alg = AssertionKeyAlgHS256
	assertionSigningKey.Key = s.payloadKey[:]
	if !ac.SigningKey.IsEmpty() {
		assertionSigningKey = ac.SigningKey
	}

	signingProvider := NewPublicKeySigningProvider(assertionSigningKey)

	if err := tmpAssertion.SignWithProvider(ctx, string(hashOfAssertionAsHex), string(encoded), signingProvider); err != nil {
		return tmpAssertion, fmt.Errorf("failed to sign assertion: %w", err)
	}
	return tmpAssertion, nil
}

func (s SystemMetadataAssertionProvider) Verify(ctx context.Context, a Assertion, t TDFObject) error {
	// TODO implement me
	panic("implement me")
}

// Validate does nothing.
func (s SystemMetadataAssertionProvider) Validate(_ context.Context, _ Assertion) error {
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
