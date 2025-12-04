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

// Verify checks the cryptographic binding of an assertion signed with the DEK.
func (v *DEKAssertionValidator) Verify(ctx context.Context, a Assertion, r TDFReader) error {
	// Use shared DEK-based verification logic
	return verifyDEKSignedAssertion(ctx, a, v.dekKey, r.Manifest())
}

// Validate does nothing - DEK-based validation doesn't check trust/policy.
func (v *DEKAssertionValidator) Validate(_ context.Context, _ Assertion, _ TDFReader) error {
	return nil
}

// verifyDEKSignedAssertion performs cryptographic verification of an assertion signed with the DEK.
// This is the common verification logic shared by SystemMetadataAssertionProvider and DEKAssertionValidator.
//
// Parameters:
//   - ctx: Context for the operation
//   - assertion: The assertion to verify
//   - dekKey: The DEK (payload key) used for verification
//   - manifest: The TDF manifest containing segments and version info
//
// Returns error if verification fails (tampering detected), nil if verification succeeds.
func verifyDEKSignedAssertion(
	ctx context.Context,
	assertion Assertion,
	dekKey AssertionKey,
	manifest Manifest,
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
	return VerifyAssertionSignatureFormat(assertion.ID, assertionSig, hashOfAssertionAsHex, manifest)
}
