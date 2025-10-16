package sdk

import (
	"context"
)

type AssertionBinder interface {
	// Bind creates and signs an assertion, binding it to the given manifest.
	// The implementation is responsible for both configuring the assertion and binding it.
	Bind(ctx context.Context, m Manifest) (Assertion, error)
}

type AssertionValidator interface {
	Verify(ctx context.Context, a Assertion, r Reader) error
	// TODO add obligationStatus and more
	Validate(ctx context.Context, a Assertion, r Reader) error
}

// ------ Deprecate in favor of AssertionBuilder and AssertionValidator  ------

// AssertionSigningProvider defines the interface for custom assertion signing implementations.
// This allows integration with external signing mechanisms like hardware security modules,
// smart cards (CAC/PIV), or cloud-based key management services.
type AssertionSigningProvider interface {
	// Sign creates a JWS signature for the given assertion.
	// The implementation should return a complete JWS compact serialization.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - assertion: The assertion to be signed
	//   - assertionHash: The hash of the assertion in hex format
	//   - assertionSig: The signature to bind the assertion to the TDF
	//
	// Returns:
	//   - signature: The complete JWS compact serialization (header.payload.signature)
	//   - err: Any error that occurred during signing
	Sign(ctx context.Context, assertion *Assertion, assertionHash string) (signature string, err error)

	// GetSigningKeyReference returns a reference or identifier for the signing key.
	// This is used for audit logging and debugging purposes.
	GetSigningKeyReference() string

	// GetAlgorithm returns the signing algorithm used by this builder (e.g., "RS256", "ES256")
	GetAlgorithm() string

	// CreateAssertionConfig the signing builder creates the specific AssertionConfig
	CreateAssertionConfig() AssertionConfig
}

// AssertionValidationProvider defines the interface for custom assertion validation implementations.
// This allows for flexible validation strategies including certificate-based validation,
// hardware token verification, and custom trust models.
type AssertionValidationProvider interface {
	// Validate verifies the signature and integrity of an assertion.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - assertion: The assertion to validate
	//
	// Returns:
	//   - hash: The assertion hash from the validated signature
	//   - sig: The assertion signature from the validated signature
	//   - err: Any validation error
	Validate(ctx context.Context, assertion Assertion, r Reader) error

	// IsTrusted checks if the signing entity is trusted according to this builder's policy.
	// This can involve certificate chain validation, revocation checking, or custom trust logic.
	IsTrusted(ctx context.Context, assertion Assertion) error

	// GetTrustedAuthorities returns a list of trusted signing authorities.
	// This is used for audit and configuration verification.
	GetTrustedAuthorities() []string
}

// NoopAssertionValidationProvider No operation performed, set this as default in non-strict strategy
type NoopAssertionValidationProvider struct{}

func (NoopAssertionValidationProvider) Validate(_ context.Context, _ Assertion, _ Reader) error {
	return nil
}
func (NoopAssertionValidationProvider) IsTrusted(_ context.Context, _ Assertion) error {
	return nil
}
func (NoopAssertionValidationProvider) GetTrustedAuthorities() []string {
	return []string{}
}
