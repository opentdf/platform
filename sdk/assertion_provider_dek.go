package sdk

// DEK-Based Assertion Validator
// Provides fallback validation for assertions signed with the Data Encryption Key (DEK)

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/opentdf/platform/lib/ocrypto"
)

// DEKAssertionValidator validates assertions that were signed with the DEK (payload key).
// This is used as a fallback validator for assertions that don't have schema-specific validators.
// It uses a wildcard schema ("*") to match any assertion.
type DEKAssertionValidator struct {
	dekKey            AssertionKey
	manifestSignature string
	aggregateHash     string
	useHex            bool
	verificationMode  AssertionVerificationMode
}

// NewDEKAssertionValidator creates a new DEK-based validator.
func NewDEKAssertionValidator(dekKey AssertionKey, manifestSignature, aggregateHash string, useHex bool) *DEKAssertionValidator {
	return &DEKAssertionValidator{
		dekKey:            dekKey,
		manifestSignature: manifestSignature,
		aggregateHash:     aggregateHash,
		useHex:            useHex,
		verificationMode:  FailFast, // Default to secure mode
	}
}

// SetVerificationMode updates the verification mode for this validator.
func (v *DEKAssertionValidator) SetVerificationMode(mode AssertionVerificationMode) {
	v.verificationMode = mode
}

// Schema returns the wildcard pattern to match any assertion schema.
func (v *DEKAssertionValidator) Schema() string {
	return SchemaWildcard
}

// Verify checks the cryptographic binding of an assertion signed with the DEK.
func (v *DEKAssertionValidator) Verify(ctx context.Context, a Assertion, _ Reader) error {
	// Use shared DEK-based verification logic
	return verifyDEKSignedAssertion(ctx, a, v.dekKey, v.manifestSignature, v.aggregateHash, v.useHex)
}

// Validate does nothing - DEK-based validation doesn't check trust/policy.
func (v *DEKAssertionValidator) Validate(_ context.Context, _ Assertion, _ Reader) error {
	return nil
}

// verifyDEKSignedAssertion performs cryptographic verification of an assertion signed with the DEK.
// This is the common verification logic shared by SystemMetadataAssertionProvider and DEKAssertionValidator.
//
// Parameters:
//   - ctx: Context for the operation
//   - assertion: The assertion to verify
//   - dekKey: The DEK (payload key) used for verification
//   - manifestSignature: The manifest root signature for binding verification
//   - aggregateHash: The aggregate hash for legacy v1 format verification
//   - useHex: Whether to use hex encoding (legacy TDF compatibility)
//
// Returns error if verification fails (tampering detected), nil if verification succeeds.
func verifyDEKSignedAssertion(
	ctx context.Context,
	assertion Assertion,
	dekKey AssertionKey,
	manifestSignature string,
	aggregateHash string,
	useHex bool,
) error {
	_ = ctx // unused context

	// Assertions without cryptographic bindings cannot be verified
	if assertion.Binding.Signature == "" {
		return fmt.Errorf("%w: assertion has no cryptographic binding", ErrAssertionFailure{ID: assertion.ID})
	}

	// Verify the JWT with the DEK
	assertionHash, assertionSig, _, err := assertion.Verify(dekKey)
	if err != nil {
		if errors.Is(err, errAssertionVerifyKeyFailure) {
			return fmt.Errorf("assertion verification failed: %w", err)
		}
		return fmt.Errorf("%w: assertion verification failed: %w", ErrAssertionFailure{ID: assertion.ID}, err)
	}

	// Get the hash of the assertion
	hashOfAssertionAsHex, err := assertion.GetHash()
	if err != nil {
		return fmt.Errorf("%w: failed to get hash of assertion: %w", ErrAssertionFailure{ID: assertion.ID}, err)
	}
	if string(hashOfAssertionAsHex) != assertionHash {
		return fmt.Errorf("%w: assertion hash mismatch", ErrAssertionFailure{ID: assertion.ID})
	}

	// Auto-detect binding format: check if assertionSig matches root signature
	// v2 format: assertionSig = rootSignature
	// v1 (legacy) format: assertionSig = base64(aggregateHash + assertionHash)
	if assertionSig == manifestSignature {
		// Current v2 format validation
		return nil
	}

	// Try legacy format verification
	return verifyDEKSignedAssertionLegacyV1(assertion.ID, assertionSig, hashOfAssertionAsHex, aggregateHash, useHex)
}

// verifyDEKSignedAssertionLegacyV1 validates assertions using the pre-v2 schema format
// where signatures are base64(aggregateHash + assertionHash).
// This maintains compatibility with Java SDK and other legacy implementations.
func verifyDEKSignedAssertionLegacyV1(
	assertionID string,
	assertionSig string,
	hashOfAssertionAsHex []byte,
	aggregateHash string,
	useHex bool,
) error {
	// Legacy validation (pre-v2 TDFs)
	// Expected signature format: base64(aggregateHash + assertionHash)
	hashOfAssertion := make([]byte, hex.DecodedLen(len(hashOfAssertionAsHex)))
	_, err := hex.Decode(hashOfAssertion, hashOfAssertionAsHex)
	if err != nil {
		return fmt.Errorf("%w: error decoding hex string: %w", ErrAssertionFailure{ID: assertionID}, err)
	}

	// Use raw bytes or hex based on useHex flag (legacy TDF compatibility)
	var hashToUse []byte
	if useHex {
		hashToUse = hashOfAssertionAsHex
	} else {
		hashToUse = hashOfAssertion
	}

	// Combine aggregate hash with assertion hash (legacy format)
	var completeHashBuilder bytes.Buffer
	completeHashBuilder.WriteString(aggregateHash)
	completeHashBuilder.Write(hashToUse)

	expectedSig := string(ocrypto.Base64Encode(completeHashBuilder.Bytes()))

	if assertionSig != expectedSig {
		return fmt.Errorf("%w: failed integrity check on legacy assertion signature", ErrAssertionFailure{ID: assertionID})
	}

	return nil
}
