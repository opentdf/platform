package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// TODO ??? prefix in name
const KeyAssertionID = "assertion-key"

type PublicKeyStatement struct {
	Algorithm string `json:"algorithm"`
	Key       any    `json:"key"`
}

type KeyAssertionBuilder struct {
	privateKey AssertionKey
	publicKey  AssertionKey
}

type KeyAssertionValidator struct {
	publicKeys AssertionVerificationKeys
}

func NewKeyAssertionBuilder(privateKey AssertionKey) *KeyAssertionBuilder {
	return &KeyAssertionBuilder{
		privateKey: privateKey,
	}
}

func NewKeyAssertionValidator(publicKeys AssertionVerificationKeys) *KeyAssertionValidator {
	return &KeyAssertionValidator{
		publicKeys: publicKeys,
	}
}

func (p KeyAssertionBuilder) Configure(ctx context.Context) (AssertionConfig, error) {
	statement := PublicKeyStatement{
		Algorithm: p.publicKey.Alg.String(),
		Key:       p.publicKey.Key,
	}

	jsonBytes, err := json.Marshal(statement)
	if err != nil {
		return AssertionConfig{}, fmt.Errorf("failed to marshal public key statement: %w", err)
	}
	statementValue := string(jsonBytes)

	return AssertionConfig{
		ID:             KeyAssertionID,
		Type:           BaseAssertion,
		Scope:          PayloadScope,
		AppliesToState: Unencrypted,
		Statement: Statement{
			Format: StatementFormatJSON,
			Schema: SystemMetadataSchemaV1,
			Value:  statementValue,
		},
	}, nil
}

func (p KeyAssertionBuilder) Bind(ctx context.Context, ac AssertionConfig, m Manifest) (Assertion, error) {
	assertion := Assertion{
		ID:             ac.ID,
		Type:           ac.Type,
		Scope:          ac.Scope,
		Statement:      ac.Statement,
		AppliesToState: ac.AppliesToState,
	}
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
	if p.publicKeys.IsEmpty() {
		// TODO ??? warn maybe
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

func (p KeyAssertionValidator) Validate(ctx context.Context, a Assertion, r Reader) error {
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
