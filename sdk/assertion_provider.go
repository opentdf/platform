package sdk

import (
	"context"
	"fmt"
)

// SignInput contains all inputs needed for signing an assertion
type SignInput struct {
	Assertion     Assertion
	AggregateHash []byte // Optional: for TDF multi-assertion integrity
	UseHex        bool   // Optional: hex encoding flag for legacy TDF
}

// AssertionSigner provides custom assertion signing logic.
// Implementations MUST be safe for concurrent use.
// The SDK may call Sign() from multiple goroutines simultaneously.
type AssertionSigner interface {
	// Sign produces a Binding for an Assertion using the provided inputs and key.
	// The context can be used for cancellation, deadlines, and tracing.
	// If SignInput.AggregateHash is provided, it should be included in the signature computation.
	Sign(ctx context.Context, input SignInput, key AssertionKey) (Binding, error)
}

// VerifyInput contains all inputs needed for verifying an assertion
type VerifyInput struct {
	Assertion     Assertion
	AggregateHash []byte // Optional: for TDF multi-assertion integrity validation
	IsLegacyTDF   bool   // Optional: flag for legacy TDF handling
}

// AssertionVerifier provides custom assertion verification logic.
// Implementations MUST be safe for concurrent use.
// The SDK may call Verify() from multiple goroutines simultaneously.
type AssertionVerifier interface {
	// Verify the assertion's binding using the provided inputs and key.
	// Returns nil if valid; typed error on failure.
	// The context can be used for cancellation, deadlines, and tracing.
	// If VerifyInput.AggregateHash is provided, it should be validated against the signature.
	Verify(ctx context.Context, input VerifyInput, key AssertionKey) error
}

// AssertionValidator is a compatibility alias for AssertionVerifier.
// Deprecated: Use AssertionVerifier instead. This alias will be removed in a future version.
type AssertionValidator = AssertionVerifier

// AssertionError represents an error during assertion operations with structured context
type AssertionError struct {
	Kind           string // Error kind for programmatic handling
	AssertionID    string // ID of the assertion that failed
	Algorithm      string // Algorithm involved (if applicable)
	KeyID          string // Key ID involved (if applicable)
	BindingVersion string // Binding version (if applicable)
	Message        string // Human-readable message
	Cause          error  // Underlying error
}

func (e *AssertionError) Error() string {
	if e.AssertionID != "" {
		return fmt.Sprintf("assertion [%s]: %s: %s", e.AssertionID, e.Kind, e.Message)
	}
	return fmt.Sprintf("assertion: %s: %s", e.Kind, e.Message)
}

func (e *AssertionError) Unwrap() error {
	return e.Cause
}

// Is implements errors.Is for AssertionError
func (e *AssertionError) Is(target error) bool {
	t, ok := target.(*AssertionError)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// Sentinel errors for assertion operations - use errors.Is() to check
var (
	// ErrAssertionMissingBinding indicates the assertion lacks a binding
	ErrAssertionMissingBinding = &AssertionError{Kind: "missing_binding", Message: "assertion lacks binding"}

	// ErrAssertionUnsupportedAlg indicates the algorithm is not in the allowlist
	ErrAssertionUnsupportedAlg = &AssertionError{Kind: "unsupported_alg", Message: "algorithm not in allowlist"}

	// ErrAssertionInvalidSignature indicates signature verification failed
	ErrAssertionInvalidSignature = &AssertionError{Kind: "invalid_signature", Message: "signature verification failed"}

	// ErrAssertionKeyMismatch indicates the key doesn't match the expected format
	ErrAssertionKeyMismatch = &AssertionError{Kind: "key_mismatch", Message: "key format mismatch"}

	// ErrAssertionHashMismatch indicates the computed hash doesn't match the expected value
	ErrAssertionHashMismatch = &AssertionError{Kind: "hash_mismatch", Message: "hash validation failed"}
)
