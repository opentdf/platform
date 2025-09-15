package cmd

// Simple Magic Word Assertion Provider Example

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/opentdf/platform/sdk"
)

const MagicWordAssertionID = "magic-word"

// MagicWordAssertionProvider "signs" an assertion by appending a secret word.
// Implements sdk.AssertionProvider
type MagicWordAssertionProvider struct {
	MagicWord string
}

// NewMagicWordAssertionProvider a provider that holds the magic word
func NewMagicWordAssertionProvider(magicWord string) *MagicWordAssertionProvider {
	return &MagicWordAssertionProvider{
		MagicWord: strings.TrimSpace(magicWord),
	}
}

func (p *MagicWordAssertionProvider) Configure(_ context.Context) (sdk.AssertionConfig, error) {
	h := hmac.New(sha256.New, []byte(p.MagicWord))
	h.Write([]byte(p.MagicWord))
	statementValue := hex.EncodeToString(h.Sum(nil))

	return sdk.AssertionConfig{
		ID:             MagicWordAssertionID,
		Type:           sdk.BaseAssertion,
		Scope:          sdk.PayloadScope,
		AppliesToState: sdk.Unencrypted,
		Statement: sdk.Statement{
			Format: sdk.StatementFormatString,
			Schema: "urn:magic-word:assertion:v1",
			Value:  statementValue,
		},
		// no SigningKey used in this example
	}, nil
}

func (p *MagicWordAssertionProvider) Bind(_ context.Context, ac sdk.AssertionConfig, m sdk.Manifest) (sdk.Assertion, error) {
	return sdk.Assertion{
		ID:             ac.ID,
		Type:           ac.Type,
		Scope:          ac.Scope,
		AppliesToState: ac.AppliesToState,
		Statement:      ac.Statement,
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
		return fmt.Errorf("invalid assertion value: HMAC verification failed")
	}

	return nil
}

// Validate does nothing.
func (p *MagicWordAssertionProvider) Validate(_ context.Context, _ sdk.Assertion, _ sdk.Reader) error {
	return nil
}
