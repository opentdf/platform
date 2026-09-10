// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package tdf

import (
	"fmt"

	"github.com/opentdf/platform/protocol/go/policy"
)

// IntegrityAlgorithm specified an integrity algorithm without saying what it
// was allowed to protect.
//
// Deprecated: the root signature and the segment hashes accept different sets
// of algorithms, which one type cannot express. Use [RootIntegrityAlg] or
// [SegmentIntegrityAlg].
type IntegrityAlgorithm int

// String returns the string representation of the integrity algorithm.
//
// Deprecated: use [RootIntegrityAlg.String] or [SegmentIntegrityAlg.String].
func (i IntegrityAlgorithm) String() string {
	switch i {
	case HS256:
		return algHS256
	case GMAC:
		return algGMAC
	default:
		return "unknown"
	}
}

const (
	// HS256 uses HMAC-SHA256 for integrity verification.
	//
	// Deprecated: use [RootHS256] or [SegmentHS256].
	HS256 = iota
	// GMAC uses Galois Message Authentication Code for integrity verification.
	//
	// Deprecated: use [SegmentGMAC]. GMAC is not a legal root algorithm.
	GMAC
)

// Manifest spellings of the two algorithms.
const (
	algHS256 = "HS256"
	algGMAC  = "GMAC"
)

// RootIntegrityAlg is the algorithm that signs the aggregate hash -- the
// concatenation of every segment hash, in manifest order. The root signature is
// the only thing that authenticates the manifest's description of the payload,
// so a segment list that has been truncated, reordered, or duplicated is caught
// here or not at all.
//
// HS256 is the only value, and this type exists to say so at compile time. The
// aggregate hash is manifest data that never passed through the AEAD, so tag
// extraction has nothing to extract: a "GMAC" root signature is just a copy of
// the last segment hash, producible by an attacker with no key.
type RootIntegrityAlg int

// RootHS256 is an HMAC-SHA256 over the aggregate hash, keyed by the DEK. It is
// the default and the only supported value.
const RootHS256 RootIntegrityAlg = iota

// SegmentIntegrityAlg is the algorithm that authenticates a single segment's
// bytes. Unlike the root, both values are genuine authenticators, because the
// input is data the cipher itself produced.
type SegmentIntegrityAlg int

const (
	// SegmentHS256 is an HMAC-SHA256 over the segment's bytes, keyed by the
	// DEK. It is the only meaningful choice when those bytes are not AEAD
	// output -- a plaintext segment has no tag to read out -- and it is this
	// writer's default.
	SegmentHS256 SegmentIntegrityAlg = iota
	// SegmentGMAC reads out the AES-GCM tag the cipher already computed over
	// exactly this segment's ciphertext.
	SegmentGMAC
)

// String returns the manifest spelling of the algorithm. Out-of-range values
// have no spelling: the type is int-backed, so they are representable, and
// naming one "HS256" in a manifest would claim a signature that was never
// computed.
func (a RootIntegrityAlg) String() string {
	if a == RootHS256 {
		return algHS256
	}
	return fmt.Sprintf("RootIntegrityAlg(%d)", int(a))
}

// String returns the manifest spelling of the algorithm. See
// [RootIntegrityAlg.String] on out-of-range values.
func (a SegmentIntegrityAlg) String() string {
	switch a {
	case SegmentHS256:
		return algHS256
	case SegmentGMAC:
		return algGMAC
	}
	return fmt.Sprintf("SegmentIntegrityAlg(%d)", int(a))
}

// BaseConfig provides common configuration foundation for TDF operations.
// Currently empty but reserved for future common configuration options.
type BaseConfig struct{}

// WriterConfig contains configuration options for TDF Writer creation.
//
// The configuration controls cryptographic algorithms and processing behavior:
//   - rootIntegrityAlg: Algorithm for root integrity signature calculation
//   - segmentIntegrityAlg: Algorithm for individual segment hash calculation
//
// These are set independently, and their legal values differ: see
// [RootIntegrityAlg] and [SegmentIntegrityAlg].
type WriterConfig struct {
	BaseConfig
	// rootIntegrityAlg specifies the algorithm for root integrity verification
	rootIntegrityAlg RootIntegrityAlg
	// segmentIntegrityAlg specifies the algorithm for segment-level integrity
	segmentIntegrityAlg SegmentIntegrityAlg

	// initialAttributes allows callers to provide attribute values at writer creation time.
	// These will be used during Finalize() if no attributes are provided there.
	initialAttributes []*policy.Value

	// initialDefaultKAS allows callers to provide a default KAS at writer creation time.
	// This will be used during Finalize() if no default KAS is provided there.
	initialDefaultKAS *policy.SimpleKasKey
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
//	writer, err := NewWriter(ctx, WithSegmentIntegrityAlgorithm(SegmentGMAC))
//	finalBytes, manifest, err := writer.Finalize(ctx, WithPayloadMimeType("text/plain"))
type Option[T any] func(T)

// WithIntegrityAlgorithm sets the algorithm for root integrity signature calculation.
//
// The root integrity algorithm is used to generate a signature over all segment hashes,
// providing verification that the complete TDF has not been tampered with.
//
// [RootHS256] is the only supported value, and the default. Options cannot
// return an error, so anything else is refused by Finalize.
//
// Example:
//
//	writer, err := NewWriter(ctx, WithIntegrityAlgorithm(RootHS256))
func WithIntegrityAlgorithm(algo RootIntegrityAlg) Option[*WriterConfig] {
	return func(c *WriterConfig) {
		c.rootIntegrityAlg = algo
	}
}

// WithSegmentIntegrityAlgorithm sets the algorithm for individual segment hash calculation.
//
// The segment integrity algorithm is used to calculate a hash for each individual
// segment, enabling verification of segment-level integrity independent of the
// complete file. This is particularly useful for streaming scenarios where
// segments may be processed independently.
//
// Both [SegmentHS256] and [SegmentGMAC] are supported, and the choice is
// independent of the root:
//   - SegmentGMAC reads out the AES-GCM tag the cipher already computed, so it
//     costs nothing extra per segment
//   - SegmentHS256 is the default, and the only option for bytes the AEAD did
//     not produce
//
// Example:
//
//	// Fast segment processing with compatible root signature
//	writer, err := NewWriter(ctx,
//		WithSegmentIntegrityAlgorithm(SegmentGMAC),  // Fast segment hashing
//		WithIntegrityAlgorithm(RootHS256),           // Compatible root signature
//	)
func WithSegmentIntegrityAlgorithm(algo SegmentIntegrityAlg) Option[*WriterConfig] {
	return func(c *WriterConfig) {
		c.segmentIntegrityAlg = algo
	}
}

// WithInitialAttributes sets data attributes on the Writer at creation time.
//
// These attributes are used by Finalize() if no attributes are provided via
// Finalize options. Finalize-specified attributes always take precedence.
func WithInitialAttributes(values []*policy.Value) Option[*WriterConfig] {
	return func(c *WriterConfig) {
		c.initialAttributes = values
	}
}

// WithDefaultKASForWriter sets the default KAS on the Writer at creation time.
//
// This default KAS is used by Finalize() if no default KAS is provided via
// Finalize options. Finalize-specified default KAS always takes precedence.
func WithDefaultKASForWriter(kas *policy.SimpleKasKey) Option[*WriterConfig] {
	return func(c *WriterConfig) {
		c.initialDefaultKAS = kas
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

	// keepSegments indicates caller-provided segment indices to keep when finalizing.
	// Indices must form a contiguous prefix [0..K]. If empty, all written
	// segments (default behavior) are used.
	keepSegments []int
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

// WithSegments restricts finalization to the provided segment indices and order.
// The order provided is used as the logical payload order. Indices may be sparse
// but must refer to segments that were written. When omitted, all present indices
// are used in ascending order.
func WithSegments(indices []int) Option[*WriterFinalizeConfig] {
	return func(c *WriterFinalizeConfig) {
		c.keepSegments = indices
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
