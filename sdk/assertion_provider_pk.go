package sdk

import (
	"context"
	"errors"
	"fmt"
)

const (
	// KeyAssertionID is the standard identifier for key-based assertions.
	KeyAssertionID = "assertion-key"

	// KeyAssertionSchema is the schema URI for key-based assertions.
	// v2 includes assertionSchema claim in JWT binding for security against schema substitution attacks.
	KeyAssertionSchema = "urn:opentdf:key:assertion:v1"
)

type PublicKeyStatement struct {
	Algorithm string `json:"algorithm"`
	Key       any    `json:"key"`
}

type KeyAssertionBinder struct {
	privateKey     AssertionKey
	publicKey      AssertionKey
	statementValue string
}

type KeyAssertionValidator struct {
	publicKeys       AssertionVerificationKeys
	verificationMode AssertionVerificationMode
}

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

// Schema returns the schema URI this validator handles.
// Returns wildcard to match any assertion schema when verification keys are provided.
func (p *KeyAssertionValidator) Schema() string {
	return SchemaWildcard
}

func (p KeyAssertionBinder) Bind(_ context.Context, m Manifest) (Assertion, error) {
	// Build the assertion
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

	// Get the hash and sign the assertion
	assertionHash, err := assertion.GetHash()
	if err != nil {
		return assertion, fmt.Errorf("failed to get hash of assertion: %w", err)
	}

	// aggregation hash replaced with manifest root signature
	if err := assertion.Sign(string(assertionHash), m.RootSignature.Signature, p.privateKey); err != nil {
		return assertion, fmt.Errorf("failed to sign assertion: %w", err)
	}

	return assertion, nil
}

func (p KeyAssertionValidator) Verify(_ context.Context, a Assertion, r Reader) error {
	// NOTE: This validator uses a wildcard schema pattern to match any assertion
	// when verification keys are provided. Schema validation is still performed
	// via the JWT's assertionSchema claim verification below.

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
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAssertionFailure{ID: a.ID}, err)
	}
	// Verify the JWT with key (now returns schema claim)
	verifiedAssertionHash, verifiedManifestSignature, verifiedSchema, err := a.Verify(key)
	if err != nil {
		return fmt.Errorf("%w: assertion verification failed: %w", ErrAssertionFailure{ID: a.ID}, err)
	}

	// SECURITY: Verify schema claim matches Statement.Schema (if claim exists)
	// This prevents schema substitution after JWT signing
	// For legacy assertions (v1), verifiedSchema will be empty string - skip check
	if verifiedSchema != "" && verifiedSchema != a.Statement.Schema {
		return fmt.Errorf("%w: schema claim mismatch - JWT contains %q but Statement has %q (tampering detected)",
			ErrAssertionFailure{ID: a.ID}, verifiedSchema, a.Statement.Schema)
	}

	// Get the hash of the assertion
	assertionHash, err := a.GetHash()
	if err != nil {
		return fmt.Errorf("%w: failed to get hash of assertion: %w", ErrAssertionFailure{ID: a.ID}, err)
	}
	manifestSignature := r.Manifest().RootSignature.Signature

	if string(assertionHash) != verifiedAssertionHash {
		return fmt.Errorf("%w: assertion hash missmatch", ErrAssertionFailure{ID: a.ID})
	}

	// Auto-detect binding format: check if verifiedManifestSignature matches root signature
	// v2 format: assertionSig = rootSignature
	// v1 (legacy) format: assertionSig = base64(aggregateHash + assertionHash)
	//
	// This allows assertions with explicit keys to use either format
	// for cross-SDK compatibility (Java/JS may use v1, Go uses v2)
	if manifestSignature == verifiedManifestSignature {
		// Current v2 format validation
		return nil
	}

	// v1 (legacy) format: The verifiedManifestSignature is base64(aggregateHash + assertionHash)
	// For custom assertions with explicit keys, Java/JS SDKs may use this format
	// We accept it for backward compatibility

	// In v1 format, we cannot verify the binding to the manifest root signature
	// because the signature is based on aggregateHash which we don't have access to here
	// This is less secure but maintains compatibility with Java/JS SDKs
	// The JWT signature itself is still verified, so the assertion content is authenticated
	return nil
}

func (p KeyAssertionValidator) Validate(_ context.Context, a Assertion, _ Reader) error {
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
