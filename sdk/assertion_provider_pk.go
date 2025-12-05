package sdk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
)

const (
	// KeyAssertionID is the standard identifier for key-based assertions.
	KeyAssertionID = "assertion-key"

	// KeyAssertionSchema is the schema URI for key-based assertions.
	// Includes assertionSchema claim in JWT binding for security against schema substitution attacks.
	KeyAssertionSchema = "urn:opentdf:key:assertion:v1"
)

type KeyAssertionBinder struct {
	privateKey     AssertionKey
	publicKey      AssertionKey
	statementValue string
}

type KeyAssertionValidator struct {
	publicKeys       AssertionVerificationKeys
	verificationMode AssertionVerificationMode
}

// NewKeyAssertionBinder creates a new key-based assertion binder.
// The publicKey will be included in the JWS protected headers as a jwk claim.
// statementValue is optional and can be empty string - the public key is stored in JWS headers, not the statement.
// Key-based assertions use standard format: base64(aggregationHash + assertionHash).
// The encoding format (hex vs raw bytes) is automatically determined from the manifest during binding.
func NewKeyAssertionBinder(privateKey AssertionKey, publicKey AssertionKey, statementValue string) *KeyAssertionBinder {
	return &KeyAssertionBinder{
		privateKey:     privateKey,
		publicKey:      publicKey,
		statementValue: statementValue,
	}
}

func NewKeyAssertionValidator(publicKeys AssertionVerificationKeys) *KeyAssertionValidator {
	return &KeyAssertionValidator{
		publicKeys:       publicKeys,
		verificationMode: FailFast, // Default to secure mode
	}
}

// SetVerificationMode updates the verification mode for this validator.
// This is typically called by the SDK when registering validators to propagate
// the global verification mode setting.
func (p *KeyAssertionValidator) SetVerificationMode(mode AssertionVerificationMode) {
	p.verificationMode = mode
}

func (p KeyAssertionBinder) Bind(_ context.Context, _ []byte) (Assertion, error) {
	// Build the assertion without signing.
	// The caller is responsible for signing the assertion after binding.
	assertion := Assertion{
		ID:             KeyAssertionID,
		Type:           BaseAssertion,
		Scope:          PayloadScope,
		AppliesToState: Unencrypted,
		Statement: Statement{
			Format: StatementFormatJSON,
			Schema: KeyAssertionSchema,
			Value:  p.statementValue,
		},
	}

	return assertion, nil
}

func (p KeyAssertionValidator) Verify(_ context.Context, a Assertion, computedSignature []byte) error {
	// SECURITY: The JWS may contain a 'jwk' header with the public key, but we
	// ALWAYS use the configured verification keys instead of the key from the header.
	// This prevents attackers from bypassing verification by providing their own keys.
	// The jwk header is informational only.

	// Assertions without cryptographic bindings cannot be verified - this is a security issue
	if a.Binding.Signature == "" {
		return fmt.Errorf("%w: assertion has no cryptographic binding", ErrAssertionFailure{ID: a.ID})
	}

	// Check if validator has keys configured
	// Behavior depends on verification mode for security
	if p.publicKeys.IsEmpty() {
		switch p.verificationMode {
		case PermissiveMode:
			// Allow for forward compatibility - skip validation
			return nil
		case StrictMode, FailFast:
			// Fail secure - cannot verify without keys
			// This prevents attackers from bypassing verification by using unconfigured key IDs
			return fmt.Errorf("%w: no verification keys configured for assertion validation", ErrAssertionFailure{ID: a.ID})
		default:
			// Unknown mode - fail secure by default
			return fmt.Errorf("%w: no verification keys configured for assertion validation", ErrAssertionFailure{ID: a.ID})
		}
	}
	// Look up the key for the assertion
	key, err := p.publicKeys.Get(a.ID)
	if err != nil || key.IsEmpty() {
		// Key not found for this assertion ID - let another validator try
		return errAssertionVerifyKeyFailure
	}
	// Verify the JWT with key (now returns schema claim)
	verifiedHash, verifiedSignature, err := a.Verify(key)
	if err != nil {
		// JWT signature verification failed - this key doesn't match
		if errors.Is(err, errAssertionVerifyKeyFailure) {
			return errAssertionVerifyKeyFailure
		}
		return fmt.Errorf("%w: assertion verification failed: %w", ErrAssertionFailure{ID: a.ID}, err)
	}

	// Get the hash of the assertion
	computedHash, err := a.GetHash()
	if err != nil {
		return fmt.Errorf("%w: failed to get hash of assertion: %w", ErrAssertionFailure{ID: a.ID}, err)
	}

	if !bytes.Equal(verifiedHash, computedHash) {
		return fmt.Errorf("%w: assertion hash missmatch", ErrAssertionFailure{ID: a.ID})
	}

	if !bytes.Equal(verifiedSignature, computedSignature) {
		return fmt.Errorf("%w: failed integrity check on assertion signature", ErrAssertionFailure{ID: a.ID})
	}
	return nil
}

func (p KeyAssertionValidator) Validate(_ context.Context, a Assertion, _ TDFReader) error {
	if p.publicKeys.IsEmpty() {
		return errors.New("no verification keys are trusted")
	}
	// If found and verified, then it is trusted
	_, err := p.publicKeys.Get(a.ID)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAssertionFailure{ID: a.ID}, err)
	}
	return nil
}
