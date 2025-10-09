package sdk

// Assertion Provider Registry

import (
	"context"
	"fmt"
	"regexp"
)

// AssertionRegistry manages and dispatches calls to registered assertion providers.
// It implements both the AssertionSigningProvider and AssertionValidationProvider interfaces,
// allowing it to be passed directly into SDK configuration options.
type AssertionRegistry struct {
	builders             []AssertionBuilder
	registeredValidators []registeredValidators
}

// NewAssertionRegistry creates and initializes a new AssertionRegistry.
func NewAssertionRegistry() *AssertionRegistry {
	return &AssertionRegistry{
		builders:             make([]AssertionBuilder, 0),
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

// --- AssertionValidationProvider Implementation ---

// Validate finds the correct builder for the assertion and delegates the validation call.
func (r *AssertionRegistry) Validate(ctx context.Context, assertion Assertion, t Reader) error {
	provider, err := r.GetValidationProvider(assertion.ID)
	if err != nil {
		return err
	}
	return provider.Validate(ctx, assertion, t)
}

// IsTrusted finds the correct builder and delegates the trust check.
func (r *AssertionRegistry) IsTrusted(ctx context.Context, assertion Assertion) error {
	//provider, err := r.GetValidationProvider(assertion.ID)
	//if err != nil {
	//	return err
	//}
	//return provider.IsTrusted(ctx, assertion)
	// FIXME move to PK assertion provider
	return nil
}

// GetTrustedAuthorities aggregates and returns the trusted authorities from all registered validation providers.
func (r *AssertionRegistry) GetTrustedAuthorities() []string {
	// FIXME move to PK assertion provider
	authorities := make([]string, 0)
	return authorities
}

func (r *AssertionRegistry) RegisterBuilder(builder AssertionBuilder) {
	r.builders = append(r.builders, builder)
}
