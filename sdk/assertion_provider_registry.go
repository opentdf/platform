package sdk

// Assertion Provider Registry

import (
	"context"
	"fmt"
	"regexp"
)

// AssertionRegistry manages and dispatches calls to registered assertion providers.
// It implements both the AssertionBinder and AssertionValidator interfaces,
// allowing it to be used internally for assertion management.
type AssertionRegistry struct {
	binders              []AssertionBinder
	registeredValidators []registeredValidators
}

// newAssertionRegistry creates and initializes a new AssertionRegistry.
func newAssertionRegistry() *AssertionRegistry {
	return &AssertionRegistry{
		binders:              make([]AssertionBinder, 0),
		registeredValidators: make([]registeredValidators, 0),
	}
}

func (r *AssertionRegistry) RegisterValidator(pattern *regexp.Regexp, validator AssertionValidator) error {
	// error if already registered
	for _, p := range r.registeredValidators {
		if p.pattern.String() == pattern.String() {
			return fmt.Errorf("pattern '%s' is already registered", pattern.String())
		}
	}
	// register
	r.registeredValidators = append(r.registeredValidators, registeredValidators{
		pattern, validator,
	})
	return nil
}

// GetValidationProvider finds and returns the first registered AssertionValidationProvider
// that matches the given assertionID. If no builder matches, it returns the default
// builder if one is set, otherwise it returns an error.
func (r *AssertionRegistry) GetValidationProvider(assertionID string) (AssertionValidator, error) {
	for _, p := range r.registeredValidators {
		if p.pattern.MatchString(assertionID) {
			return p.validator, nil
		}
	}
	return nil, fmt.Errorf("no default nor validation builder registered for assertion ID '%s'", assertionID)
}

// registeredValidators holds a compiled regex and its associated validation builder.
type registeredValidators struct {
	pattern   *regexp.Regexp
	validator AssertionValidator
}

// --- AssertionValidator Implementation ---

// Validate finds the correct validator for the assertion and delegates the validation call.
func (r *AssertionRegistry) Validate(ctx context.Context, assertion Assertion, t Reader) error {
	provider, err := r.GetValidationProvider(assertion.ID)
	if err != nil {
		return err
	}
	return provider.Validate(ctx, assertion, t)
}

// Verify finds the correct validator for the assertion and delegates the verification call.
func (r *AssertionRegistry) Verify(ctx context.Context, assertion Assertion, t Reader) error {
	provider, err := r.GetValidationProvider(assertion.ID)
	if err != nil {
		return err
	}
	return provider.Verify(ctx, assertion, t)
}

func (r *AssertionRegistry) RegisterBinder(binder AssertionBinder) {
	r.binders = append(r.binders, binder)
}
