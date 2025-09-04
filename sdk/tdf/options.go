package tdf

import "github.com/opentdf/platform/protocol/go/policy"

// IntegrityAlgorithm specifies the cryptographic algorithm used for integrity verification.
//
// Different algorithms provide different security and performance characteristics:
//   - HS256: HMAC-SHA256, widely supported, good balance of security and performance
//   - GMAC: Galois Message Authentication Code, faster but requires AES-GCM support
//
// The algorithm choice affects both segment-level and root-level integrity verification.
type IntegrityAlgorithm int

// String returns the string representation of the integrity algorithm.
// Used for manifest generation and protocol compatibility.
func (i IntegrityAlgorithm) String() string {
	switch i {
	case HS256:
		return "HS256"
	case GMAC:
		return "GMAC"
	default:
		return "unknown"
	}
}

const (
	// HS256 uses HMAC-SHA256 for integrity verification.
	// This is the default and most widely supported algorithm.
	HS256 = iota
	// GMAC uses Galois Message Authentication Code for integrity verification.
	// Provides better performance with AES-GCM but requires hardware support for optimal speed.
	GMAC
)

// BaseConfig provides common configuration foundation for TDF operations.
// Currently empty but reserved for future common configuration options.
type BaseConfig struct{}

// WriterConfig contains configuration options for TDF Writer creation.
//
// The configuration controls cryptographic algorithms and processing behavior:
//   - integrityAlgorithm: Algorithm for root integrity signature calculation
//   - segmentIntegrityAlgorithm: Algorithm for individual segment hash calculation
//
// These can be set independently to optimize for different security/performance requirements.
type WriterConfig struct {
	BaseConfig
	// integrityAlgorithm specifies the algorithm for root integrity verification
	integrityAlgorithm IntegrityAlgorithm
	// segmentIntegrityAlgorithm specifies the algorithm for segment-level integrity
	segmentIntegrityAlgorithm IntegrityAlgorithm
}

// ReaderConfig contains configuration options for TDF Reader creation.
// Reserved for future reader configuration options.
type ReaderConfig struct {
	BaseConfig
}

// Option is a functional option pattern for configuring TDF operations.
//
// This generic type allows type-safe configuration of different TDF components:
//   - Option[*WriterConfig] for Writer configuration
//   - Option[*WriterFinalizeConfig] for Finalize operation configuration
//   - Option[*ReaderConfig] for future Reader configuration
//
// Example usage:
//
//	writer, err := NewWriter(ctx, WithIntegrityAlgorithm(GMAC))
//	finalBytes, manifest, err := writer.Finalize(ctx, WithPayloadMimeType("text/plain"))
type Option[T any] func(T)

// WithIntegrityAlgorithm sets the algorithm for root integrity signature calculation.
//
// The root integrity algorithm is used to generate a signature over all segment hashes,
// providing verification that the complete TDF has not been tampered with.
//
// Algorithm options:
//   - HS256: HMAC-SHA256 (default) - widely supported, secure
//   - GMAC: Galois Message Authentication Code - faster with hardware acceleration
//
// Example:
//
//	writer, err := NewWriter(ctx, WithIntegrityAlgorithm(GMAC))
func WithIntegrityAlgorithm(algo IntegrityAlgorithm) Option[*WriterConfig] {
	return func(c *WriterConfig) {
		c.integrityAlgorithm = algo
	}
}

// WithSegmentIntegrityAlgorithm sets the algorithm for individual segment hash calculation.
//
// The segment integrity algorithm is used to calculate a hash for each individual
// segment, enabling verification of segment-level integrity independent of the
// complete file. This is particularly useful for streaming scenarios where
// segments may be processed independently.
//
// The segment algorithm can differ from the root algorithm to optimize for
// different processing patterns:
//   - Use GMAC for segments if processing many small segments (better performance)
//   - Use HS256 for root signature for broader compatibility
//
// Example:
//
//	// Fast segment processing with compatible root signature
//	writer, err := NewWriter(ctx,
//		WithSegmentIntegrityAlgorithm(GMAC),  // Fast segment hashing
//		WithIntegrityAlgorithm(HS256),        // Compatible root signature
//	)
func WithSegmentIntegrityAlgorithm(algo IntegrityAlgorithm) Option[*WriterConfig] {
	return func(c *WriterConfig) {
		c.segmentIntegrityAlgorithm = algo
	}
}

// WriterFinalizeConfig contains configuration options for TDF finalization.
//
// This configuration controls the final TDF structure and access controls:
//   - Key access server configuration for attribute-based access
//   - Data attributes defining access policies
//   - Cryptographic assertions for additional integrity/handling instructions
//   - Metadata and content type specifications
//
// All fields have sensible defaults and are optional unless specific access
// controls or metadata are required.
type WriterFinalizeConfig struct {
	// defaultKas specifies the default Key Access Server for attribute-based access control.
	// If not provided, the system will attempt to resolve KAS from attributes.
	defaultKas *policy.SimpleKasKey

	// attributes contains the data attributes that define access policies for this TDF.
	// Each attribute represents an access requirement (e.g., clearance level, classification).
	attributes []*policy.Value

	// assertions contains cryptographic assertions providing additional integrity
	// or handling instructions for the TDF.
	assertions []AssertionConfig

	// excludeVersionFromManifest controls whether to exclude version information
	// from the TDF manifest (for compatibility with older readers).
	excludeVersionFromManifest bool

	// encryptedMetadata contains sensitive metadata encrypted within the TDF.
	// This metadata is stored in key access objects and only accessible after
	// successful attribute-based access control validation.
	encryptedMetadata string

	// payloadMimeType specifies the MIME type of the payload content.
	// Used by readers to determine appropriate content handling.
	payloadMimeType string
}

// WithEncryptedMetadata includes encrypted metadata in the TDF.
//
// The metadata is encrypted and stored within key access objects, making it
// accessible only after successful attribute-based access control validation.
// This is useful for storing sensitive information about the data that should
// only be visible to authorized users.
//
// The metadata is encrypted using the same key management as the payload data,
// ensuring consistent access controls.
//
// Example:
//
//	finalBytes, manifest, err := writer.Finalize(ctx,
//		WithEncryptedMetadata("classification: secret"),
//	)
func WithEncryptedMetadata(metadata string) Option[*WriterFinalizeConfig] {
	return func(c *WriterFinalizeConfig) {
		c.encryptedMetadata = metadata
	}
}

// WithPayloadMimeType sets the MIME type for the TDF payload.
//
// The MIME type helps readers understand how to process the decrypted content.
// Common values include:
//   - "application/octet-stream" (default) - binary data
//   - "text/plain" - plain text files
//   - "application/json" - JSON data
//   - "image/jpeg", "video/mp4", etc. - media files
//
// Example:
//
//	finalBytes, manifest, err := writer.Finalize(ctx,
//		WithPayloadMimeType("application/json"),
//	)
func WithPayloadMimeType(mimeType string) Option[*WriterFinalizeConfig] {
	return func(c *WriterFinalizeConfig) {
		c.payloadMimeType = mimeType
	}
}

// WithDefaultKAS sets the default Key Access Server for attribute resolution.
//
// The KAS is used when attributes don't specify their own key access servers.
// This simplifies configuration when all attributes use the same KAS instance.
//
// The provided KAS configuration includes:
//   - URI: The KAS endpoint URL
//   - Public key information for key wrapping
//   - Algorithm specification (typically RSA-2048)
//
// Example:
//
//	kasKey := &policy.SimpleKasKey{
//		KasUri: "https://kas.example.com",
//		PublicKey: &policy.SimpleKasPublicKey{
//			Algorithm: policy.Algorithm_ALGORITHM_RSA_2048,
//			Kid: "kas-key-1",
//			Pem: kasPublicKeyPEM,
//		},
//	}
//	finalBytes, manifest, err := writer.Finalize(ctx, WithDefaultKAS(kasKey))
func WithDefaultKAS(kas *policy.SimpleKasKey) Option[*WriterFinalizeConfig] {
	return func(c *WriterFinalizeConfig) {
		c.defaultKas = kas
	}
}

// WithAttributeValues sets the data attributes for access control.
//
// Data attributes define who can access the TDF based on attribute-based
// access control (ABAC) policies. Each attribute represents a requirement
// that must be satisfied for access.
//
// Attributes typically include:
//   - Classification levels (SECRET, TOP_SECRET, etc.)
//   - Organizational units (HR, Finance, Engineering)
//   - Clearance levels (Level_1, Level_2, etc.)
//   - Custom business attributes
//
// Each attribute must have associated Key Access Server information that
// defines how the attribute is validated and which KAS controls access.
//
// Example:
//
//	attributes := []*policy.Value{
//		{
//			Fqn: "https://company.com/attr/classification/value/secret",
//			Grants: []*policy.KeyAccessServer{kasConfig},
//		},
//	}
//	finalBytes, manifest, err := writer.Finalize(ctx, WithAttributeValues(attributes))
func WithAttributeValues(values []*policy.Value) Option[*WriterFinalizeConfig] {
	return func(c *WriterFinalizeConfig) {
		c.attributes = values
	}
}

// WithExcludeVersionFromManifest controls version information in the manifest.
//
// When set to true, excludes TDF specification version information from
// the manifest. This may be needed for compatibility with older TDF readers
// that don't expect version fields.
//
// Generally should be left as default (false) unless specific compatibility
// requirements exist.
//
// Example:
//
//	// For compatibility with legacy readers
//	finalBytes, manifest, err := writer.Finalize(ctx,
//		WithExcludeVersionFromManifest(true),
//	)
func WithExcludeVersionFromManifest(exclude bool) Option[*WriterFinalizeConfig] {
	return func(c *WriterFinalizeConfig) {
		c.excludeVersionFromManifest = exclude
	}
}

// WithAssertions includes cryptographic assertions in the TDF.
//
// Assertions provide additional integrity verification and can include
// handling instructions, metadata, or custom verification logic. Each
// assertion is cryptographically signed to prevent tampering.
//
// Common assertion types:
//   - BaseAssertion ("other"): General-purpose assertions
//   - HandlingAssertion: Data handling and processing instructions
//
// Each assertion includes:
//   - Statement: The assertion content (JSON format)
//   - Scope: What the assertion applies to (payload, TDF object)
//   - Signing key: For cryptographic verification
//
// Example:
//
//	assertion := AssertionConfig{
//		ID: "handling-instruction",
//		Type: HandlingAssertion,
//		Scope: PayloadScope,
//		AppliesToState: Unencrypted,
//		Statement: Statement{
//			Format: "json",
//			Schema: "handling-v1",
//			Value: `{"retention_days": 90}`,
//		},
//	}
//	finalBytes, manifest, err := writer.Finalize(ctx, WithAssertions(assertion))
func WithAssertions(assertions ...AssertionConfig) Option[*WriterFinalizeConfig] {
	return func(c *WriterFinalizeConfig) {
		c.assertions = assertions
	}
}
