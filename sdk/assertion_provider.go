package sdk

import (
	"context"
)

const (
	// SchemaWildcard is a wildcard pattern that matches any assertion schema.
	SchemaWildcard = "*"
)

type AssertionBinder interface {
	// Bind creates an assertion without cryptographic binding.
	// The caller is responsible for signing the assertion after binding.
	//
	// Parameters:
	//   - ctx: Context for the operation
	//   - payloadHash: The aggregate hash computed from manifest segments via ComputeAggregateHash()
	//
	// Returns assertion. If unsigned assertion, then signed with DEK.
	Bind(ctx context.Context, payloadHash []byte) (Assertion, error)
}

type AssertionValidator interface {
	// Schema returns the schema URI this validator handles.
	// The schema identifies the assertion format and version.
	// Examples: "urn:opentdf:system:metadata:v1", "urn:opentdf:key:assertion:v1"
	Schema() string

	// Verify checks the assertion's cryptographic binding.
	//
	// Example:
	//   assertionHash, _ := a.GetHash()
	//   manifest := r.Manifest()
	//   expectedSig, _ := manifest.ComputeAssertionSignature(assertionHash)
	Verify(ctx context.Context, a Assertion, r TDFReader) error

	// Validate checks the assertion's policy and trust requirements
	Validate(ctx context.Context, a Assertion, r TDFReader) error
}
