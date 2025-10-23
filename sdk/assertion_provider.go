package sdk

import (
	"context"
)

const (
	// SchemaWildcard is a wildcard pattern that matches any assertion schema.
	SchemaWildcard = "*"
)

type AssertionBinder interface {
	// Bind creates and signs an assertion, binding it to the given manifest.
	// The implementation is responsible for both configuring the assertion and binding it.
	//
	// Custom implementations should use ShouldUseHexEncoding(m) to determine the correct
	// encoding format when calling ComputeAssertionSignature().
	//
	// Example:
	//   useHex := ShouldUseHexEncoding(m)
	//   aggregateHash, _ := ComputeAggregateHash(m.EncryptionInformation.IntegrityInformation.Segments)
	//   sig, _ := ComputeAssertionSignature(string(aggregateHash), assertionHash, useHex)
	Bind(ctx context.Context, m Manifest) (Assertion, error)
}

type AssertionValidator interface {
	// Schema returns the schema URI this validator handles.
	// The schema identifies the assertion format and version.
	// Examples: "urn:opentdf:system:metadata:v1", "urn:opentdf:key:assertion:v1"
	Schema() string

	// Verify checks the assertion's cryptographic binding.
	//
	// Custom implementations should use ShouldUseHexEncoding(r.Manifest()) to determine the
	// correct encoding format when calling ComputeAssertionSignature().
	//
	// Example:
	//   useHex := ShouldUseHexEncoding(r.Manifest())
	//   aggregateHash, _ := ComputeAggregateHash(r.Manifest().EncryptionInformation.IntegrityInformation.Segments)
	//   expectedSig, _ := ComputeAssertionSignature(string(aggregateHash), assertionHash, useHex)
	Verify(ctx context.Context, a Assertion, r Reader) error

	// Validate checks the assertion's policy and trust requirements
	Validate(ctx context.Context, a Assertion, r Reader) error
}
