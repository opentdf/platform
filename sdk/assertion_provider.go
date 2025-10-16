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
