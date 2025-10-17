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
	// Schema returns the schema URI this validator handles.
	// The schema identifies the assertion format and version.
	// Examples: "urn:opentdf:system:metadata:v2", "urn:opentdf:key:assertion:v2"
	Schema() string

	// Verify checks the assertion's cryptographic binding
	Verify(ctx context.Context, a Assertion, r Reader) error

	// Validate checks the assertion's policy and trust requirements
	Validate(ctx context.Context, a Assertion, r Reader) error
}
