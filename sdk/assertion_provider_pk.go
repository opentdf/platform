package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
)

// KeyAssertionID is the standard identifier for key-based assertions.
//
// Assertion ID Naming Convention:
//   - System assertions (built-in): Use simple kebab-case names (e.g., "assertion-key", "system-metadata")
//   - Custom assertions: Should use reverse-domain notation or descriptive prefixes to avoid conflicts
//     (e.g., "com.example.custom-assertion", "app-specific-assertion")
//
// The simple "assertion-key" ID is used for SDK-provided key-based assertions and is part of the
// standard TDF specification. Custom implementations should choose unique IDs that won't conflict
// with current or future standard assertion types.
const KeyAssertionID = "assertion-key"

type PublicKeyStatement struct {
	Algorithm string `json:"algorithm"`
	Key       any    `json:"key"`
}

type KeyAssertionBinder struct {
	privateKey AssertionKey
	publicKey  AssertionKey
}

type KeyAssertionValidator struct {
	publicKeys AssertionVerificationKeys
}

func NewKeyAssertionBinder(privateKey AssertionKey) *KeyAssertionBinder {
	return &KeyAssertionBinder{
		privateKey: privateKey,
	}
}

func NewKeyAssertionValidator(publicKeys AssertionVerificationKeys) *KeyAssertionValidator {
	return &KeyAssertionValidator{
		publicKeys: publicKeys,
	}
}

func (p KeyAssertionBinder) Bind(_ context.Context, m Manifest) (Assertion, error) {
	// Create the public key statement
	statement := PublicKeyStatement{
		Algorithm: p.publicKey.Alg.String(),
		Key:       p.publicKey.Key,
	}

	jsonBytes, err := json.Marshal(statement)
	if err != nil {
		return Assertion{}, fmt.Errorf("failed to marshal public key statement: %w", err)
	}
	statementValue := string(jsonBytes)

	// Build the assertion
	assertion := Assertion{
		ID:             KeyAssertionID,
		Type:           BaseAssertion,
		Scope:          PayloadScope,
		AppliesToState: Unencrypted,
		Statement: Statement{
			Format: StatementFormatJSON,
			Schema: SystemMetadataSchemaV1,
			Value:  statementValue,
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

func (p KeyAssertionValidator) Verify(ctx context.Context, a Assertion, r Reader) error {
	// Skip verification for assertions without bindings
	if a.Binding.Signature == "" {
		slog.WarnContext(ctx, "assertion has no binding, skipping verification",
			slog.String("assertion_id", a.ID),
			slog.String("assertion_type", string(a.Type)))
		return nil
	}

	if p.publicKeys.IsEmpty() {
		slog.WarnContext(ctx, "no verification keys configured for assertion validation",
			slog.String("assertion_id", a.ID),
			slog.String("assertion_type", string(a.Type)))
		return nil
		// if an error is thrown here, a tamper event will be triggered
		// return errors.New("no verification key configured")
	}
	// Look up the key for the assertion
	key, err := p.publicKeys.Get(a.ID)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAssertionFailure{ID: a.ID}, err)
	}
	// Verify the JWT with key
	verifiedAssertionHash, verifiedManifestSignature, err := a.Verify(key)
	if err != nil {
		return fmt.Errorf("%w: assertion verification failed: %w", ErrAssertionFailure{ID: a.ID}, err)
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

	if manifestSignature != verifiedManifestSignature {
		return fmt.Errorf("%w: failed integrity check on assertion signature", ErrAssertionFailure{ID: a.ID})
	}

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
