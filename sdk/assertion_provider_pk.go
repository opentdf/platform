package sdk

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/lib/ocrypto"
)

// TODO ??? prefix in name
const KeyAssertionID = "assertion-key"

type PublicKeyStatement struct {
	Algorithm string `json:"algorithm"`
	Key       any    `json:"key"`
}

type KeyAssertionProvider struct {
	privateKey AssertionKey
	publicKey  AssertionKey
}

func NewKeyAssertionBuilder(privateKey AssertionKey) *KeyAssertionProvider {
	return &KeyAssertionProvider{
		privateKey: privateKey,
	}
}

func NewKeyAssertionValidator(publicKey AssertionKey) *KeyAssertionProvider {
	return &KeyAssertionProvider{
		publicKey: publicKey,
	}
}

func (p KeyAssertionProvider) Configure(ctx context.Context) (AssertionConfig, error) {
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

func (p KeyAssertionProvider) Bind(ctx context.Context, ac AssertionConfig, m Manifest) (Assertion, error) {
	assertion := Assertion{
		ID:             ac.ID,
		Type:           ac.Type,
		Scope:          ac.Scope,
		Statement:      ac.Statement,
		AppliesToState: ac.AppliesToState,
	}

	signingProvider := NewPublicKeySigningProvider(p.privateKey)
	// FIXME aggregation hash replaced with manifest root signature
	if err := assertion.SignWithProvider(ctx, m.RootSignature.Signature, signingProvider); err != nil {
		return assertion, fmt.Errorf("failed to sign assertion: %w", err)
	}
	return assertion, nil
}

func (p KeyAssertionProvider) Verify(ctx context.Context, a Assertion, r Reader) error {
	//TODO implement me
	panic("implement me")
}

func (p KeyAssertionProvider) Validate(ctx context.Context, a Assertion, r Reader) error {
	verifier, err := r.config.verifiers.Get(a.ID)
	if err != nil {
		return err
	}
	if verifier.IsEmpty() {
		return errors.New("no verification key configured")
	}
	//TODO implement me, read trusted keys
	panic("implement me")
}

// PublicKeySigningProvider implements key-based signing logic.
// This preserves backward compatibility with the current SDK behavior.
// Implements AssertionProvider, AssertionSigningProvider, AssertionValidationProvider
type PublicKeySigningProvider struct {
	key AssertionKey
}

// NewPublicKeySigningProvider creates a signing builder using the existing AssertionKey structure
func NewPublicKeySigningProvider(key AssertionKey) *PublicKeySigningProvider {
	return &PublicKeySigningProvider{
		key: key,
	}
}

func (p *PublicKeySigningProvider) CreateAssertionConfig() AssertionConfig {
	// TODO implement
	panic("implement me")
}

// Sign creates a JWS signature using the configured key
func (p *PublicKeySigningProvider) Sign(_ context.Context, _ *Assertion, assertionHash string) (string, error) {
	if p.key.IsEmpty() {
		return "", errors.New("signing key not configured")
	}

	// Configure JWT with assertion hash and signature claims
	tok := jwt.New()
	if err := tok.Set(kAssertionHash, assertionHash); err != nil {
		return "", fmt.Errorf("failed to set assertion hash: %w", err)
	}
	assertionSig := ocrypto.Base64Encode([]byte(assertionHash))
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
func (p *PublicKeySigningProvider) GetSigningKeyReference() string {
	if p.key.IsEmpty() {
		return "no-key"
	}
	return "key-alg:" + p.key.Alg.String()
}

// GetAlgorithm returns the signing algorithm
func (p *PublicKeySigningProvider) GetAlgorithm() string {
	if p.key.IsEmpty() {
		return ""
	}
	return p.key.Alg.String()
}

// PublicKeyValidationProvider implements the existing key-based validation logic.
// This preserves backward compatibility with the current SDK behavior.
type PublicKeyValidationProvider struct {
	keys          AssertionVerificationKeys
	aggregateHash []byte
}

// NewPublicKeyValidationProvider creates a validation builder using the existing verification keys
func NewPublicKeyValidationProvider() *PublicKeyValidationProvider {
	return &PublicKeyValidationProvider{}
}

// Verify verifies the assertion signature using the configured keys
func (p *PublicKeyValidationProvider) Verify(_ context.Context, assertion Assertion, t TDFObject) error {
	//if !r.config.verifiers.IsEmpty() {
	//	foundKey, err := r.config.verifiers.Get(assertion.ID)
	//	if err != nil {
	//		return nil, fmt.Errorf("%w: %w", ErrAssertionFailure{ID: assertion.ID}, err)
	//	}
	//	if !foundKey.IsEmpty() {
	//		assertionKey.Alg = foundKey.Alg
	//		assertionKey.Key = foundKey.Key
	//	}
	//}
	// Get the appropriate key for this assertion
	key, err := p.keys.Get(assertion.ID)
	if err != nil {
		return fmt.Errorf("failed to get verification key: %w", err)
	}

	// If no key is configured, skip validation (backward compatibility)
	if key.IsEmpty() {
		return nil
	}

	// Parse and verify the JWS
	tok, err := jwt.Parse([]byte(assertion.Binding.Signature),
		jwt.WithKey(jwa.KeyAlgorithmFrom(key.Alg.String()), key.Key),
	)
	if err != nil {
		return fmt.Errorf("%w: %w", errAssertionVerifyKeyFailure, err)
	}

	// Extract the hash claim
	hashClaim, found := tok.Get(kAssertionHash)
	if !found {
		return errors.New("hash claim not found")
	}
	hash, ok := hashClaim.(string)
	if !ok {
		return errors.New("hash claim is not a string")
	}

	// Extract the signature claim
	sigClaim, found := tok.Get(kAssertionSignature)
	if !found {
		return errors.New("signature claim not found")
	}
	sig, ok := sigClaim.(string)
	if !ok {
		return errors.New("signature claim is not a string")
	}

	if err := performStandardAssertionChecks(assertion, hash, sig, p.aggregateHash, t.Manifest()); err != nil {
		return err
	}

	return nil
}

// IsTrusted always returns nil for the default builder (key-based trust)
func (p *PublicKeyValidationProvider) IsTrusted(_ context.Context, assertion Assertion) error {
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
func (p *PublicKeyValidationProvider) GetTrustedAuthorities() []string {
	var authorities []string

	if !p.keys.DefaultKey.IsEmpty() {
		authorities = append(authorities, "default:"+p.keys.DefaultKey.Alg.String())
	}

	for id, key := range p.keys.Keys {
		if !key.IsEmpty() {
			authorities = append(authorities, fmt.Sprintf("%s:%s", id, key.Alg.String()))
		}
	}

	return authorities
}

// performStandardAssertionChecks performs the standard DEK-based assertion validation checks
func performStandardAssertionChecks(assertion Assertion, assertionHash, assertionSig string, aggregateHashBytes []byte, m Manifest) error {
	// Get the hash of the assertion
	hashOfAssertionAsHex, err := assertion.GetHash()
	if err != nil {
		return fmt.Errorf("%w: failed to get hash of assertion: %w", ErrAssertionFailure{ID: assertion.ID}, err)
	}

	hashOfAssertion := make([]byte, hex.DecodedLen(len(hashOfAssertionAsHex)))
	_, err = hex.Decode(hashOfAssertion, hashOfAssertionAsHex)
	if err != nil {
		return fmt.Errorf("error decoding hex string: %w", err)
	}

	isLegacyTDF := m.TDFVersion == ""
	if isLegacyTDF {
		hashOfAssertion = hashOfAssertionAsHex
	}

	var completeHashBuilder bytes.Buffer
	completeHashBuilder.Write(aggregateHashBytes)
	completeHashBuilder.Write(hashOfAssertion)

	base64Hash := ocrypto.Base64Encode(completeHashBuilder.Bytes())

	if string(hashOfAssertionAsHex) != assertionHash {
		return fmt.Errorf("%w: assertion hash missmatch", ErrAssertionFailure{ID: assertion.ID})
	}

	if assertionSig != string(base64Hash) {
		return fmt.Errorf("%w: failed integrity check on assertion signature", ErrAssertionFailure{ID: assertion.ID})
	}

	return nil
}
