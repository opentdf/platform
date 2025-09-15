package sdk

// Assertion Provider Factory (and Bridge) - perhaps more of a manager than a factory

import (
	"context"
	"fmt"
	"regexp"
)

type registeredAssertionProvider struct {
	pattern  *regexp.Regexp
	provider AssertionProvider
}

// registeredSigningProvider holds a compiled regex and its associated signing provider.
type registeredSigningProvider struct {
	pattern  *regexp.Regexp
	provider AssertionSigningProvider
}

// registeredValidationProvider holds a compiled regex and its associated validation provider.
type registeredValidationProvider struct {
	pattern  *regexp.Regexp
	provider AssertionValidationProvider
}

// AssertionProviderFactory manages and dispatches calls to registered assertion providers.
// It implements both the AssertionSigningProvider and AssertionValidationProvider interfaces,
// allowing it to be passed directly into SDK configuration options.
type AssertionProviderFactory struct {
	signingProviders          []registeredSigningProvider
	validationProviders       []registeredValidationProvider
	registeredProviders       []registeredAssertionProvider
	defaultValidationProvider AssertionValidationProvider
}

// NewAssertionProviderFactory creates and initializes a new AssertionProviderFactory.
func NewAssertionProviderFactory() *AssertionProviderFactory {
	return &AssertionProviderFactory{
		signingProviders:    make([]registeredSigningProvider, 0),
		validationProviders: make([]registeredValidationProvider, 0),
	}
}

func (f *AssertionProviderFactory) RegisterAssertionProvider(pattern *regexp.Regexp, provider AssertionProvider) error {
	// error if already registered
	for _, p := range f.registeredProviders {
		if p.pattern.String() == pattern.String() {
			return fmt.Errorf("pattern '%s' is already registered", pattern.String())
		}
	}
	// register
	f.registeredProviders = append(f.registeredProviders, registeredAssertionProvider{
		pattern, provider,
	})
	// TODO can we remove this bridge
	bridge := bridgeAssertionValidationProvider{p: provider}
	f.validationProviders = append(f.validationProviders, registeredValidationProvider{
		pattern:  pattern,
		provider: bridge,
	})
	return nil
}

// RegisterSigningProvider registers an AssertionSigningProvider for a given regex pattern.
// The first registered provider that matches an assertion ID will be used.
func (f *AssertionProviderFactory) RegisterSigningProvider(pattern regexp.Regexp, provider AssertionSigningProvider) error {
	f.signingProviders = append(f.signingProviders, registeredSigningProvider{
		pattern:  &pattern,
		provider: provider,
	})
	return nil
}

// RegisterValidationProvider registers an AssertionValidationProvider for a given regex pattern.
// The first registered provider that matches an assertion ID will be used.
func (f *AssertionProviderFactory) RegisterValidationProvider(pattern string, provider AssertionValidationProvider) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid regex pattern '%s': %w", pattern, err)
	}

	f.validationProviders = append(f.validationProviders, registeredValidationProvider{
		pattern:  re,
		provider: provider,
	})
	return nil
}

// SetDefaultValidationProvider sets a default provider to use when no pattern matches.
func (f *AssertionProviderFactory) SetDefaultValidationProvider(provider AssertionValidationProvider) {
	f.defaultValidationProvider = provider
}

// GetSigningProvider finds and returns the first registered AssertionSigningProvider
// that matches the given assertionID.
func (f *AssertionProviderFactory) GetSigningProvider(assertionID string) (AssertionSigningProvider, error) {
	for _, p := range f.signingProviders {
		if p.pattern.MatchString(assertionID) {
			return p.provider, nil
		}
	}
	return nil, fmt.Errorf("no signing provider registered for assertion ID '%s'", assertionID)
}

// GetValidationProvider finds and returns the first registered AssertionValidationProvider
// that matches the given assertionID. If no provider matches, it returns the default
// provider if one is set, otherwise it returns an error.
func (f *AssertionProviderFactory) GetValidationProvider(assertionID string) (AssertionValidationProvider, error) {
	for _, p := range f.validationProviders {
		if p.pattern.MatchString(assertionID) {
			return p.provider, nil
		}
	}

	if f.defaultValidationProvider != nil {
		return f.defaultValidationProvider, nil
	}
	return nil, fmt.Errorf("no default nor validation provider registered for assertion ID '%s'", assertionID)
}

// --- AssertionSigningProvider Implementation ---

// Sign finds the correct provider for the assertion and delegates the signing call.
func (f *AssertionProviderFactory) Sign(ctx context.Context, assertion *Assertion, hash string) (string, error) {
	provider, err := f.GetSigningProvider(assertion.ID)
	if err != nil {
		return "", err
	}
	return provider.Sign(ctx, assertion, hash)
}

// GetSigningKeyReference returns a placeholder as this is a factory for multiple providers.
func (f *AssertionProviderFactory) GetSigningKeyReference() string {
	return "factory-managed-provider"
}

// GetAlgorithm returns a placeholder as this is a factory for multiple providers.
func (f *AssertionProviderFactory) GetAlgorithm() string {
	return "dynamic"
}

// --- AssertionValidationProvider Implementation ---

// Validate finds the correct provider for the assertion and delegates the validation call.
func (f *AssertionProviderFactory) Validate(ctx context.Context, assertion Assertion, r Reader) error {
	provider, err := f.GetValidationProvider(assertion.ID)
	if err != nil {
		return err
	}
	return provider.Validate(ctx, assertion, r)
}

// IsTrusted finds the correct provider and delegates the trust check.
func (f *AssertionProviderFactory) IsTrusted(ctx context.Context, assertion Assertion) error {
	provider, err := f.GetValidationProvider(assertion.ID)
	if err != nil {
		return err
	}
	return provider.IsTrusted(ctx, assertion)
}

// GetTrustedAuthorities aggregates and returns the trusted authorities from all registered validation providers.
func (f *AssertionProviderFactory) GetTrustedAuthorities() []string {
	authorities := make([]string, 0)
	seen := make(map[string]bool)

	for _, p := range f.validationProviders {
		for _, auth := range p.provider.GetTrustedAuthorities() {
			if !seen[auth] {
				authorities = append(authorities, auth)
				seen[auth] = true
			}
		}
	}

	if f.defaultValidationProvider != nil {
		for _, auth := range f.defaultValidationProvider.GetTrustedAuthorities() {
			if !seen[auth] {
				authorities = append(authorities, auth)
				seen[auth] = true
			}
		}
	}

	return authorities
}
