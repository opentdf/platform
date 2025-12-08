package sdk

import (
	"context"
)

type AssertionBinder interface {
	// Bind creates an assertion with cryptographic binding to the payloadHash.
	Bind(ctx context.Context, payloadHash []byte) (Assertion, error)
}

type AssertionValidator interface {
	// Verify checks the assertion's cryptographic binding.
	Verify(ctx context.Context, a Assertion, computedSignature []byte) error

	// Validate checks the assertion's policy and trust requirements
	Validate(ctx context.Context, a Assertion, r TDFReader) error
}
