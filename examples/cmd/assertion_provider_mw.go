package cmd

// Simple Magic Word Assertion Provider Example
//
// This is a basic demonstration provider that uses a shared secret (magic word) for assertion
// verification. It is NOT suitable for production use as it provides minimal security.
//
// For production scenarios, consider using:
// - Key-based assertions (sdk.KeyAssertionBinder) with asymmetric cryptography
// - X.509 certificate-based signing with hardware security modules (HSMs)
// - Cloud KMS integration for key management
//
// This example is useful for:
// - Understanding the assertion provider interface
// - Testing and development environments
// - Educational purposes demonstrating the provider pattern

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/opentdf/platform/sdk"
)

const (
	MagicWordAssertionID     = "magic-word"
	MagicWordAssertionSchema = "urn:magic-word:assertion:v1"
)

// MagicWordAssertionProvider "signs" an assertion by appending a secret word.
// Implements sdk.AssertionBinder and sdk.AssertionValidator
type MagicWordAssertionProvider struct {
	MagicWord string
}

// NewMagicWordAssertionProvider a provider that holds the magic word
func NewMagicWordAssertionProvider(magicWord string) *MagicWordAssertionProvider {
	return &MagicWordAssertionProvider{
		MagicWord: strings.TrimSpace(magicWord),
	}
}

func (p *MagicWordAssertionProvider) Bind(_ context.Context, m sdk.Manifest) (sdk.Assertion, error) {
	// Create the statement by hashing the magic word
	h := hmac.New(sha256.New, []byte(p.MagicWord))
	h.Write([]byte(p.MagicWord))
	statementValue := hex.EncodeToString(h.Sum(nil))

	return sdk.Assertion{
		ID:             MagicWordAssertionID,
		Type:           sdk.BaseAssertion,
		Scope:          sdk.PayloadScope,
		AppliesToState: sdk.Unencrypted,
		Statement: sdk.Statement{
			Format: sdk.StatementFormatString,
			Schema: MagicWordAssertionSchema,
			Value:  statementValue,
		},
		Binding: sdk.Binding{
			Method:    "",
			Signature: fmt.Sprintf("%s:%s", m.Signature, p.MagicWord),
		},
	}, nil
}

// Verify assertion is well-formed and bound
func (p *MagicWordAssertionProvider) Verify(_ context.Context, a sdk.Assertion, _ sdk.Reader) error {
	h := hmac.New(sha256.New, []byte(p.MagicWord))
	h.Write([]byte(p.MagicWord))
	computedHMAC := hex.EncodeToString(h.Sum(nil))

	if computedHMAC != a.Statement.Value {
		return errors.New("invalid assertion value: HMAC verification failed")
	}

	return nil
}

// Validate does nothing.
func (p *MagicWordAssertionProvider) Validate(_ context.Context, _ sdk.Assertion, _ sdk.Reader) error {
	return nil
}

// Schema returns the schema URI this validator handles.
func (p *MagicWordAssertionProvider) Schema() string {
	return MagicWordAssertionSchema
}
