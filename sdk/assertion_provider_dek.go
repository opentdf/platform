package sdk

// DEK-Based Assertion Validator
// Provides fallback validation for assertions signed with the Data Encryption Key (DEK)

import (
	"context"
	"errors"
	"fmt"
)

// DEKAssertionValidator validates assertions that were signed with the DEK (payload key).
// This is used as a fallback validator for assertions that don't have schema-specific validators.
// It uses a wildcard schema ("*") to match any assertion.
type DEKAssertionValidator struct {
	dekKey           AssertionKey
	verificationMode AssertionVerificationMode
}

// NewDEKAssertionValidator creates a new DEK-based validator.
// The aggregateHash and useHex are computed from the manifest during verification.
func NewDEKAssertionValidator(dekKey AssertionKey) *DEKAssertionValidator {
	return &DEKAssertionValidator{
		dekKey:           dekKey,
		verificationMode: FailFast, // Default to secure mode
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
func (v *DEKAssertionValidator) Verify(ctx context.Context, a Assertion, r Reader) error {
	// Compute aggregate hash from manifest
	aggregateHashBytes, err := ComputeAggregateHash(r.Manifest().EncryptionInformation.IntegrityInformation.Segments)
	if err != nil {
		return fmt.Errorf("%w: failed to compute aggregate hash: %w", ErrAssertionFailure{ID: a.ID}, err)
	}

	// Determine encoding format from manifest
	useHex := ShouldUseHexEncoding(r.Manifest())

	// Use shared DEK-based verification logic
	return verifyDEKSignedAssertion(ctx, a, v.dekKey, string(aggregateHashBytes), useHex)
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
//   - aggregateHash: The aggregate hash for verification
//   - useHex: Whether to use hex encoding (for TDF 4.2.2 compatibility)
//
// Returns error if verification fails (tampering detected), nil if verification succeeds.
func verifyDEKSignedAssertion(
	ctx context.Context,
	assertion Assertion,
	dekKey AssertionKey,
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

	// Verify signature format: base64(aggregateHash + assertionHash)
	return verifyDEKSignedAssertionFormat(assertion.ID, assertionSig, hashOfAssertionAsHex, aggregateHash, useHex)
}

// verifyDEKSignedAssertionFormat validates assertions using standard format
// where signatures are base64(aggregateHash + assertionHash).
// This is the standard format used across all SDKs (Java/JS/Go).
func verifyDEKSignedAssertionFormat(
	assertionID string,
	assertionSig string,
	hashOfAssertionAsHex []byte,
	aggregateHash string,
	useHex bool,
) error {
	// Compute expected signature using standard format
	expectedSig, err := ComputeAssertionSignature(aggregateHash, hashOfAssertionAsHex, useHex)
	if err != nil {
		return fmt.Errorf("%w: failed to compute assertion signature: %w", ErrAssertionFailure{ID: assertionID}, err)
	}

	if assertionSig != expectedSig {
		return fmt.Errorf("%w: failed integrity check on assertion signature", ErrAssertionFailure{ID: assertionID})
	}

	return nil
}
