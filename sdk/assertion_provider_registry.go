package sdk

// Assertion Provider Registry

import (
	"context"
	"fmt"
)

// AssertionRegistry manages and dispatches calls to registered assertion providers.
// It implements both the AssertionBinder and AssertionValidator interfaces,
// allowing it to be used internally for assertion management.
type AssertionRegistry struct {
	binders    []AssertionBinder
	validators map[string]AssertionValidator
}

// newAssertionRegistry creates and initializes a new AssertionRegistry.
func newAssertionRegistry() *AssertionRegistry {
	return &AssertionRegistry{
		binders:    make([]AssertionBinder, 0),
		validators: make(map[string]AssertionValidator),
	}
}

func (r *AssertionRegistry) RegisterValidator(validator AssertionValidator) error {
	schema := validator.Schema()
	// error if already registered
	if _, exists := r.validators[schema]; exists {
		return fmt.Errorf("validator for schema '%s' is already registered", schema)
	}
	// register
	r.validators[schema] = validator
	return nil
}

// GetValidationProvider finds and returns the registered AssertionValidator
// for the given schema URI. If no validator matches, it returns an error.
func (r *AssertionRegistry) GetValidationProvider(schema string) (AssertionValidator, error) {
	validator, exists := r.validators[schema]
	if !exists {
		return nil, fmt.Errorf("no validation provider registered for schema '%s'", schema)
	}
	return validator, nil
}

// --- AssertionValidator Implementation ---

// Validate finds the correct validator for the assertion and delegates the validation call.
func (r *AssertionRegistry) Validate(ctx context.Context, assertion Assertion, t Reader) error {
	provider, err := r.GetValidationProvider(assertion.Statement.Schema)
	if err != nil {
		return err
	}
	return provider.Validate(ctx, assertion, t)
}

// Verify finds the correct validator for the assertion and delegates the verification call.
func (r *AssertionRegistry) Verify(ctx context.Context, assertion Assertion, t Reader) error {
	provider, err := r.GetValidationProvider(assertion.Statement.Schema)
	if err != nil {
		return err
	}
	return provider.Verify(ctx, assertion, t)
}

func (r *AssertionRegistry) RegisterBinder(binder AssertionBinder) {
	r.binders = append(r.binders, binder)
}
