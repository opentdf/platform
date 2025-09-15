package sdk

import (
	"context"
	"crypto/x509"
	"errors"
)

// ErrProviderNotImplemented is returned when a method is not implemented by a provider
var ErrProviderNotImplemented = errors.New("provider method not implemented")

type AssertionProvider interface {
	Configure(ctx context.Context) (AssertionConfig, error)
	Bind(ctx context.Context, ac AssertionConfig, m Manifest) (Assertion, error)
	Verify(ctx context.Context, a Assertion, r Reader) error
	// TODO add obligationStatus and more
	Validate(ctx context.Context, a Assertion, r Reader) error
}

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

	// GetAlgorithm returns the signing algorithm used by this provider (e.g., "RS256", "ES256")
	GetAlgorithm() string

	// CreateAssertionConfig the signing provider creates the specific AssertionConfig
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

	// IsTrusted checks if the signing entity is trusted according to this provider's policy.
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

type bridgeAssertionValidationProvider struct {
	p AssertionProvider
}

// Validate does Verify and Validate, so we call both here
func (b bridgeAssertionValidationProvider) Validate(ctx context.Context, assertion Assertion, r Reader) error {
	b.p.Verify(ctx, assertion, r)
	return b.p.Validate(ctx, assertion, r)
}
func (b bridgeAssertionValidationProvider) IsTrusted(ctx context.Context, assertion Assertion) error {
	//TODO implement me
	panic("implement me")
}

func (b bridgeAssertionValidationProvider) GetTrustedAuthorities() []string {
	//TODO implement me
	panic("implement me")
}

// X509ValidationOptions provides configuration for X.509 certificate-based validation
type X509ValidationOptions struct {
	// TrustedCAs is a pool of trusted root certificates
	TrustedCAs *x509.CertPool

	// RequiredPolicies are the certificate policy OIDs that must be present
	// For PIV: "2.16.840.1.101.3.2.1.3.13" (PIV Authentication)
	// For CAC: "2.16.840.1.101.3.2.1.3.13" (ID Certificate)
	RequiredPolicies []string

	// CheckRevocation enables certificate revocation checking
	CheckRevocation bool

	// AllowSelfSigned permits self-signed certificates (useful for testing)
	AllowSelfSigned bool

	// RequireChainValidation enforces full certificate chain validation
	RequireChainValidation bool
}

// HardwareSigningOptions provides configuration for hardware-based signing
type HardwareSigningOptions struct {
	// SlotID identifies the hardware slot (for PKCS#11)
	SlotID string

	// KeyLabel is the label of the key on the hardware device
	KeyLabel string

	// PIN for accessing the hardware device (should be handled securely)
	PIN []byte

	// IncludeCertChain determines if the x5c header should include the full chain
	IncludeCertChain bool

	// Algorithm specifies the signing algorithm (e.g., "RS256", "ES256")
	Algorithm string
}

// ProviderCapabilities describes what a provider supports
type ProviderCapabilities struct {
	// SupportsHardware indicates hardware token support
	SupportsHardware bool

	// SupportedAlgorithms lists the supported signing algorithms
	SupportedAlgorithms []string

	// SupportsX5C indicates support for X.509 certificate chains
	SupportsX5C bool

	// SupportsBatching indicates if the provider can handle batch operations
	SupportsBatching bool

	// MaxSignatureRate is the maximum signatures per second (0 = unlimited)
	MaxSignatureRate int
}

// ProviderMetrics tracks provider performance and usage
type ProviderMetrics struct {
	// TotalSignatures is the total number of signatures created
	TotalSignatures int64

	// TotalValidations is the total number of validations performed
	TotalValidations int64

	// FailedSignatures is the count of failed signature attempts
	FailedSignatures int64

	// FailedValidations is the count of failed validation attempts
	FailedValidations int64

	// AverageSigningTimeMs is the average time to sign in milliseconds
	AverageSigningTimeMs float64

	// AverageValidationTimeMs is the average time to validate in milliseconds
	AverageValidationTimeMs float64
}
