// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package tdf

import (
	"github.com/opentdf/platform/sdk"
)

// These claim names have no caller here beyond the tests that assert
// against sdk's claim names.
const (
	kAssertionSignature = "assertionSig"
	kAssertionHash      = "assertionHash"
)

// Aliases onto [github.com/opentdf/platform/sdk], which owns the
// implementation. See the package doc for why.
type (
	// AssertionConfig defines an assertion to be included in the TDF during
	// creation. It extends [Assertion] with a signing key, which is used
	// during TDF creation but is not stored in the final TDF. An empty
	// SigningKey defaults to the TDF's DEK with HS256.
	//
	// See [sdk.AssertionConfig].
	AssertionConfig = sdk.AssertionConfig

	// Assertion represents a cryptographically signed assertion in the TDF
	// manifest. Assertions provide integrity verification and handling
	// instructions that are cryptographically bound to the TDF, so they
	// cannot be modified or copied to another TDF without detection.
	//
	// See [sdk.Assertion].
	Assertion = sdk.Assertion

	// Statement includes information applying to the scope of the assertion.
	// It could contain rights, handling instructions, or general metadata.
	//
	// See [sdk.Statement].
	Statement = sdk.Statement

	// Binding enforces cryptographic integrity of the assertion, so it
	// cannot be modified or copied to another TDF.
	//
	// See [sdk.Binding].
	Binding = sdk.Binding

	// AssertionType represents the category of assertion being made.
	//
	// See [sdk.AssertionType].
	AssertionType = sdk.AssertionType

	// Scope defines what component of the TDF the assertion applies to.
	//
	// See [sdk.Scope].
	Scope = sdk.Scope

	// AppliesToState declares whether the assertion applies to encrypted or
	// unencrypted data. It is a marker for consumers; nothing in the SDK
	// dispatches on it.
	//
	// See [sdk.AppliesToState].
	AppliesToState = sdk.AppliesToState

	// BindingMethod represents the cryptographic method used to bind
	// assertions to the TDF.
	//
	// See [sdk.BindingMethod].
	BindingMethod = sdk.BindingMethod

	// AssertionKeyAlg represents the cryptographic algorithm for assertion
	// signing keys.
	//
	// See [sdk.AssertionKeyAlg].
	AssertionKeyAlg = sdk.AssertionKeyAlg

	// AssertionKey represents a cryptographic key for signing and verifying
	// assertions. For RS256 the Key is an RSA private key, a jwk.Key, or a
	// [crypto.Signer] for hardware-backed keys; for HS256 it is the shared
	// secret bytes.
	//
	// See [sdk.AssertionKey].
	AssertionKey = sdk.AssertionKey

	// AssertionVerificationKeys represents the verification keys for
	// assertions, with an optional default for unlisted assertion IDs. Get
	// returns an empty key, not an error, when neither is set.
	//
	// See [sdk.AssertionVerificationKeys].
	AssertionVerificationKeys = sdk.AssertionVerificationKeys
)

const (
	// SystemMetadataAssertionID is the standard ID for system metadata assertions.
	SystemMetadataAssertionID = sdk.SystemMetadataAssertionID
	// SystemMetadataSchemaV1 defines the schema version for system metadata.
	SystemMetadataSchemaV1 = sdk.SystemMetadataSchemaV1

	// HandlingAssertion provides instructions for data handling and processing.
	// Examples: retention policies, deletion schedules, processing requirements.
	HandlingAssertion = sdk.HandlingAssertion
	// BaseAssertion is a general-purpose assertion type for metadata and other
	// content. Examples: audit information, system metadata, custom business logic.
	BaseAssertion = sdk.BaseAssertion

	// TrustedDataObjScope indicates the assertion applies to the complete TDF
	// object, including manifest, key access objects, and payload.
	TrustedDataObjScope = sdk.TrustedDataObjScope
	// PayloadScope indicates the assertion applies only to the payload data.
	// This is the most common scope for data handling assertions.
	PayloadScope = sdk.PayloadScope

	// Encrypted marks the assertion as applying to the encrypted payload.
	Encrypted = sdk.Encrypted
	// Unencrypted marks the assertion as applying to the decrypted payload.
	Unencrypted = sdk.Unencrypted

	// JWS (JSON Web Signature) is the standard method for assertion binding.
	JWS = sdk.JWS

	// AssertionKeyAlgRS256 uses RSA-SHA256 for assertion signatures. Suitable
	// when assertions must be verified without access to the signing key.
	AssertionKeyAlgRS256 = sdk.AssertionKeyAlgRS256
	// AssertionKeyAlgHS256 uses HMAC-SHA256 for assertion signatures. More
	// efficient, and lets the TDF's DEK double as the signing key.
	AssertionKeyAlgHS256 = sdk.AssertionKeyAlgHS256
)
