package sdk

import (
	"context"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// DefaultSigningProvider implements the existing key-based signing logic.
// This preserves backward compatibility with the current SDK behavior.
type DefaultSigningProvider struct {
	key AssertionKey
}

// NewDefaultSigningProvider creates a signing provider using the existing AssertionKey structure
func NewDefaultSigningProvider(key AssertionKey) *DefaultSigningProvider {
	return &DefaultSigningProvider{
		key: key,
	}
}

// Sign creates a JWS signature using the configured key
func (p *DefaultSigningProvider) Sign(ctx context.Context, assertion *Assertion, assertionHash, assertionSig string) (string, error) {
	if p.key.IsEmpty() {
		return "", errors.New("signing key not configured")
	}

	// Create JWT with assertion hash and signature claims
	tok := jwt.New()
	if err := tok.Set(kAssertionHash, assertionHash); err != nil {
		return "", fmt.Errorf("failed to set assertion hash: %w", err)
	}
	if err := tok.Set(kAssertionSignature, assertionSig); err != nil {
		return "", fmt.Errorf("failed to set assertion signature: %w", err)
	}

	// Sign the token with the configured key
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.KeyAlgorithmFrom(p.key.Alg.String()), p.key.Key))
	if err != nil {
		return "", fmt.Errorf("signing assertion failed: %w", err)
	}

	return string(signedTok), nil
}

// GetSigningKeyReference returns a reference to the signing key
func (p *DefaultSigningProvider) GetSigningKeyReference() string {
	if p.key.IsEmpty() {
		return "no-key"
	}
	return fmt.Sprintf("key-alg:%s", p.key.Alg.String())
}

// GetAlgorithm returns the signing algorithm
func (p *DefaultSigningProvider) GetAlgorithm() string {
	if p.key.IsEmpty() {
		return ""
	}
	return p.key.Alg.String()
}

// DefaultValidationProvider implements the existing key-based validation logic.
// This preserves backward compatibility with the current SDK behavior.
type DefaultValidationProvider struct {
	keys AssertionVerificationKeys
}

// NewDefaultValidationProvider creates a validation provider using the existing verification keys
func NewDefaultValidationProvider(keys AssertionVerificationKeys) *DefaultValidationProvider {
	return &DefaultValidationProvider{
		keys: keys,
	}
}

// NewDefaultValidationProviderWithKey creates a validation provider with a single key
func NewDefaultValidationProviderWithKey(key AssertionKey) *DefaultValidationProvider {
	return &DefaultValidationProvider{
		keys: AssertionVerificationKeys{
			DefaultKey: key,
		},
	}
}

// Validate verifies the assertion signature using the configured keys
func (p *DefaultValidationProvider) Validate(ctx context.Context, assertion Assertion) (string, string, error) {
	// Get the appropriate key for this assertion
	key, err := p.keys.Get(assertion.ID)
	if err != nil {
		return "", "", fmt.Errorf("failed to get verification key: %w", err)
	}

	// If no key is configured, skip validation (backward compatibility)
	if key.IsEmpty() {
		return "", "", nil
	}

	// Parse and verify the JWS
	tok, err := jwt.Parse([]byte(assertion.Binding.Signature),
		jwt.WithKey(jwa.KeyAlgorithmFrom(key.Alg.String()), key.Key),
	)
	if err != nil {
		return "", "", fmt.Errorf("%w: %w", errAssertionVerifyKeyFailure, err)
	}

	// Extract the hash claim
	hashClaim, found := tok.Get(kAssertionHash)
	if !found {
		return "", "", errors.New("hash claim not found")
	}
	hash, ok := hashClaim.(string)
	if !ok {
		return "", "", errors.New("hash claim is not a string")
	}

	// Extract the signature claim
	sigClaim, found := tok.Get(kAssertionSignature)
	if !found {
		return "", "", errors.New("signature claim not found")
	}
	sig, ok := sigClaim.(string)
	if !ok {
		return "", "", errors.New("signature claim is not a string")
	}

	return hash, sig, nil
}

// IsTrusted always returns nil for the default provider (key-based trust)
func (p *DefaultValidationProvider) IsTrusted(ctx context.Context, assertion Assertion) error {
	// In the default implementation, trust is implicit if we have the key
	key, err := p.keys.Get(assertion.ID)
	if err != nil {
		return err
	}
	if key.IsEmpty() {
		return errors.New("no verification key configured")
	}
	return nil
}

// GetTrustedAuthorities returns the list of configured verification keys
func (p *DefaultValidationProvider) GetTrustedAuthorities() []string {
	var authorities []string

	if !p.keys.DefaultKey.IsEmpty() {
		authorities = append(authorities, fmt.Sprintf("default:%s", p.keys.DefaultKey.Alg.String()))
	}

	for id, key := range p.keys.Keys {
		if !key.IsEmpty() {
			authorities = append(authorities, fmt.Sprintf("%s:%s", id, key.Alg.String()))
		}
	}

	return authorities
}

// PayloadKeyProvider is a special provider for using the payload key as the signing key.
// This is used for HMAC-based assertions where the payload key itself signs the assertion.
type PayloadKeyProvider struct {
	payloadKey []byte
}

// NewPayloadKeyProvider creates a provider that uses the payload key for signing
func NewPayloadKeyProvider(payloadKey []byte) *PayloadKeyProvider {
	return &PayloadKeyProvider{
		payloadKey: payloadKey,
	}
}

// Sign creates a JWS signature using the payload key (HMAC-SHA256)
func (p *PayloadKeyProvider) Sign(ctx context.Context, assertion *Assertion, assertionHash, assertionSig string) (string, error) {
	if len(p.payloadKey) == 0 {
		return "", errors.New("payload key not configured")
	}

	// Create JWT with assertion hash and signature claims
	tok := jwt.New()
	if err := tok.Set(kAssertionHash, assertionHash); err != nil {
		return "", fmt.Errorf("failed to set assertion hash: %w", err)
	}
	if err := tok.Set(kAssertionSignature, assertionSig); err != nil {
		return "", fmt.Errorf("failed to set assertion signature: %w", err)
	}

	// Sign with HMAC using the payload key
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256, p.payloadKey))
	if err != nil {
		return "", fmt.Errorf("signing assertion failed: %w", err)
	}

	return string(signedTok), nil
}

// GetSigningKeyReference returns a reference to the signing method
func (p *PayloadKeyProvider) GetSigningKeyReference() string {
	return "payload-key:HS256"
}

// GetAlgorithm returns the signing algorithm
func (p *PayloadKeyProvider) GetAlgorithm() string {
	return "HS256"
}

// PayloadKeyValidationProvider validates assertions signed with the payload key
type PayloadKeyValidationProvider struct {
	payloadKey []byte
}

// NewPayloadKeyValidationProvider creates a validation provider for payload key signatures
func NewPayloadKeyValidationProvider(payloadKey []byte) *PayloadKeyValidationProvider {
	return &PayloadKeyValidationProvider{
		payloadKey: payloadKey,
	}
}

// Validate verifies the assertion using the payload key
func (p *PayloadKeyValidationProvider) Validate(ctx context.Context, assertion Assertion) (string, string, error) {
	if len(p.payloadKey) == 0 {
		return "", "", errors.New("payload key not configured")
	}

	// Parse and verify the JWS with HMAC
	tok, err := jwt.Parse([]byte(assertion.Binding.Signature),
		jwt.WithKey(jwa.HS256, p.payloadKey),
	)
	if err != nil {
		return "", "", fmt.Errorf("assertion verification failed: %w", err)
	}

	// Extract the hash claim
	hashClaim, found := tok.Get(kAssertionHash)
	if !found {
		return "", "", errors.New("hash claim not found")
	}
	hash, ok := hashClaim.(string)
	if !ok {
		return "", "", errors.New("hash claim is not a string")
	}

	// Extract the signature claim
	sigClaim, found := tok.Get(kAssertionSignature)
	if !found {
		return "", "", errors.New("signature claim not found")
	}
	sig, ok := sigClaim.(string)
	if !ok {
		return "", "", errors.New("signature claim is not a string")
	}

	return hash, sig, nil
}

// IsTrusted always returns nil for payload key validation
func (p *PayloadKeyValidationProvider) IsTrusted(ctx context.Context, assertion Assertion) error {
	return nil
}

// GetTrustedAuthorities returns payload key as the trusted authority
func (p *PayloadKeyValidationProvider) GetTrustedAuthorities() []string {
	return []string{"payload-key:HS256"}
}
