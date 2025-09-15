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

func (p SystemMetadataAssertionProvider) Configure(_ context.Context) (AssertionConfig, error) {
	return GetSystemMetadataAssertionConfig()
}

func (p SystemMetadataAssertionProvider) Bind(ctx context.Context, ac AssertionConfig, m Manifest) (Assertion, error) {
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

	hashOfAssertion := make([]byte, hex.DecodedLen(len(hashOfAssertionAsHex)))
	_, err = hex.Decode(hashOfAssertion, hashOfAssertionAsHex)
	if err != nil {
		return assertion, fmt.Errorf("error decoding hex string: %w", err)
	}

	var completeHashBuilder strings.Builder
	completeHashBuilder.WriteString(p.aggregateHash)
	if p.useHex {
		completeHashBuilder.Write(hashOfAssertionAsHex)
	} else {
		completeHashBuilder.Write(hashOfAssertion)
	}

	// Fall back to default provider
	assertionSigningKey := AssertionKey{}
	// Set default to HS256 and payload key
	assertionSigningKey.Alg = AssertionKeyAlgHS256
	assertionSigningKey.Key = p.payloadKey[:]
	if !ac.SigningKey.IsEmpty() {
		assertionSigningKey = ac.SigningKey
	}

	signingProvider := NewPublicKeySigningProvider(assertionSigningKey)
	// FIXME aggregation hash replaced with manifest root signature
	if err := assertion.SignWithProvider(ctx, string(hashOfAssertionAsHex), signingProvider); err != nil {
		return assertion, fmt.Errorf("failed to sign assertion: %w", err)
	}
	return assertion, nil
}

func (p SystemMetadataAssertionProvider) Verify(ctx context.Context, a Assertion, r Reader) error {
	assertionKey := AssertionKey{}
	// Set default to HS256
	assertionKey.Alg = AssertionKeyAlgHS256
	assertionKey.Key = p.payloadKey[:]

	if !r.config.verifiers.IsEmpty() {
		// Look up the key for the assertion
		foundKey, err := r.config.verifiers.Get(a.ID)

		if err != nil {
			return fmt.Errorf("%w: %w", ErrAssertionFailure{ID: a.ID}, err)
		} else if !foundKey.IsEmpty() {
			assertionKey.Alg = foundKey.Alg
			assertionKey.Key = foundKey.Key
		}
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

	hashOfAssertion := make([]byte, hex.DecodedLen(len(hashOfAssertionAsHex)))
	_, err = hex.Decode(hashOfAssertion, hashOfAssertionAsHex)
	if err != nil {
		return fmt.Errorf("error decoding hex string: %w", err)
	}

	isLegacyTDF := r.manifest.TDFVersion == ""
	if isLegacyTDF {
		hashOfAssertion = hashOfAssertionAsHex
	}

	var completeHashBuilder bytes.Buffer
	completeHashBuilder.Write([]byte(p.aggregateHash))
	completeHashBuilder.Write(hashOfAssertion)

	base64Hash := ocrypto.Base64Encode(completeHashBuilder.Bytes())

	if string(hashOfAssertionAsHex) != assertionHash {
		return fmt.Errorf("%w: assertion hash missmatch", ErrAssertionFailure{ID: a.ID})
	}

	if assertionSig != string(base64Hash) {
		return fmt.Errorf("%w: failed integrity check on assertion signature", ErrAssertionFailure{ID: a.ID})
	}
	return nil
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
