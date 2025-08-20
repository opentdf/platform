package sdk

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/gowebpki/jcs"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/lib/ocrypto"
)

// Use the constants from tdf.go to avoid redeclaration

// Canonicalization Specification:
// The SDK uses JCS (JSON Canonicalization Scheme - RFC 8785) for deterministic JSON serialization.
// This ensures consistent hash computation across different implementations and languages.
// Version 1.0: JCS canonicalization → SHA-256 → JWT signature
//
// Assertion Ordering:
// For aggregate hash computation, assertions MUST be processed in lexicographic order by ID.
// This prevents tampering through reordering attacks.
const bindingVersion = "1.0"

// internalSign performs the canonical signing operation for an assertion.
// This function:
// 1. Canonicalizes the assertion payload (excluding Binding)
// 2. Computes a hash (SHA-256 of canonical JSON)
// 3. Signs with the provided key algorithm
// 4. Returns a Binding containing the algorithm, signature, and optional KeyID
func internalSign(_ context.Context, a Assertion, key AssertionKey) (Binding, error) {
	// Validate the algorithm
	if err := validateAlgorithm(key.Alg.String()); err != nil {
		return Binding{}, err
	}

	// Get the hash of the assertion
	hashBytes, err := computeAssertionHash(a)
	if err != nil {
		return Binding{}, fmt.Errorf("failed to compute assertion hash: %w", err)
	}
	hashHex := hex.EncodeToString(hashBytes)

	// Create the aggregate signature (simplified for now - you may need to adjust based on your needs)
	// This matches the existing implementation pattern
	sig := ocrypto.Base64Encode(hashBytes)

	// Create JWT with hash and signature claims
	tok := jwt.New()
	if err := tok.Set(kAssertionHash, hashHex); err != nil {
		return Binding{}, fmt.Errorf("failed to set assertion hash: %w", err)
	}
	if err := tok.Set(kAssertionSignature, string(sig)); err != nil {
		return Binding{}, fmt.Errorf("failed to set assertion signature: %w", err)
	}

	// Sign the JWT
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.KeyAlgorithmFrom(key.Alg.String()), key.Key))
	if err != nil {
		return Binding{}, fmt.Errorf("signing assertion failed: %w", err)
	}

	// Create and return the binding with version
	binding := Binding{
		Method:    "jws",
		Signature: string(signedTok),
		Version:   bindingVersion,
	}

	return binding, nil
}

// InternalSignWithAggregateHash performs signing with an aggregate hash.
// This is used during TDF creation where multiple assertions are combined.
func internalSignWithAggregateHash(_ context.Context, a Assertion, key AssertionKey, aggregateHash string, useHex bool) (Binding, error) {
	// Validate the algorithm
	if err := validateAlgorithm(key.Alg.String()); err != nil {
		return Binding{}, err
	}

	// Get the hash of the assertion
	hashBytes, err := computeAssertionHash(a)
	if err != nil {
		return Binding{}, fmt.Errorf("failed to compute assertion hash: %w", err)
	}
	hashHex := hex.EncodeToString(hashBytes)

	// Build complete hash with aggregate
	var completeHash strings.Builder
	completeHash.WriteString(aggregateHash)
	if useHex {
		completeHash.WriteString(hashHex)
	} else {
		completeHash.Write(hashBytes)
	}

	// Encode the complete hash
	encoded := ocrypto.Base64Encode([]byte(completeHash.String()))

	// Create JWT with hash and signature claims
	tok := jwt.New()
	if err := tok.Set(kAssertionHash, hashHex); err != nil {
		return Binding{}, fmt.Errorf("failed to set assertion hash: %w", err)
	}
	if err := tok.Set(kAssertionSignature, string(encoded)); err != nil {
		return Binding{}, fmt.Errorf("failed to set assertion signature: %w", err)
	}

	// Sign the JWT
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.KeyAlgorithmFrom(key.Alg.String()), key.Key))
	if err != nil {
		return Binding{}, fmt.Errorf("signing assertion failed: %w", err)
	}

	// Create and return the binding with version
	binding := Binding{
		Method:    "jws",
		Signature: string(signedTok),
		Version:   bindingVersion,
	}

	return binding, nil
}

// InternalVerify performs the canonical verification operation for an assertion.
// This function:
// 1. Extracts the Binding from the assertion
// 2. Recomputes the hash (same as InternalSign)
// 3. Verifies the signature against the key
// 4. Returns nil on success; typed error on failure
func internalVerify(_ context.Context, a Assertion, key AssertionKey) error {
	// Check for binding
	if a.Binding.Signature == "" {
		return ErrAssertionMissingBinding
	}

	// Validate the algorithm
	if err := validateAlgorithm(key.Alg.String()); err != nil {
		return err
	}

	// Parse and verify the JWT signature
	tok, err := jwt.Parse([]byte(a.Binding.Signature),
		jwt.WithKey(jwa.KeyAlgorithmFrom(key.Alg.String()), key.Key),
	)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAssertionInvalidSignature, err)
	}

	// Extract the hash claim
	hashClaim, found := tok.Get(kAssertionHash)
	if !found {
		return errors.New("hash claim not found in assertion binding")
	}
	storedHashHex, ok := hashClaim.(string)
	if !ok {
		return errors.New("hash claim is not a string")
	}

	// Recompute the hash of the assertion
	computedHashBytes, err := computeAssertionHash(a)
	if err != nil {
		return fmt.Errorf("failed to compute assertion hash for verification: %w", err)
	}
	computedHashHex := hex.EncodeToString(computedHashBytes)

	// Compare hashes
	if storedHashHex != computedHashHex {
		return ErrAssertionHashMismatch
	}

	// Note: Aggregate hash validation would need to be done at a higher level
	// since we don't have access to the aggregate hash here

	return nil
}

// InternalVerifyWithContext performs verification with aggregate hash validation.
// This is used during TDF reading where multiple assertions need aggregate validation.
func internalVerifyWithContext(_ context.Context, a Assertion, key AssertionKey, aggregateHash []byte, isLegacyTDF bool) error {
	// Check for binding
	if a.Binding.Signature == "" {
		return ErrAssertionMissingBinding
	}

	// Validate the algorithm
	if err := validateAlgorithm(key.Alg.String()); err != nil {
		return err
	}

	// Parse and verify the JWT signature
	tok, err := jwt.Parse([]byte(a.Binding.Signature),
		jwt.WithKey(jwa.KeyAlgorithmFrom(key.Alg.String()), key.Key),
	)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAssertionInvalidSignature, err)
	}

	// Extract the hash claim
	hashClaim, found := tok.Get(kAssertionHash)
	if !found {
		return errors.New("hash claim not found in assertion binding")
	}
	storedHashHex, ok := hashClaim.(string)
	if !ok {
		return errors.New("hash claim is not a string")
	}

	// Extract the signature claim
	sigClaim, found := tok.Get(kAssertionSignature)
	if !found {
		return errors.New("signature claim not found in assertion binding")
	}
	storedSig, ok := sigClaim.(string)
	if !ok {
		return errors.New("signature claim is not a string")
	}

	// Recompute the hash of the assertion
	computedHashBytes, err := computeAssertionHash(a)
	if err != nil {
		return fmt.Errorf("failed to compute assertion hash for verification: %w", err)
	}
	computedHashHex := hex.EncodeToString(computedHashBytes)

	// Verify the hash matches
	if storedHashHex != computedHashHex {
		return ErrAssertionHashMismatch
	}

	// Verify the aggregate hash signature
	hashOfAssertion := computedHashBytes
	if isLegacyTDF {
		hashOfAssertion = []byte(computedHashHex)
	}

	var completeHash bytes.Buffer
	completeHash.Write(aggregateHash)
	completeHash.Write(hashOfAssertion)

	expectedSig := ocrypto.Base64Encode(completeHash.Bytes())
	if storedSig != string(expectedSig) {
		// Try alternate approach for cross-SDK compatibility
		// Some Java SDKs may use hex encoding even for modern TDFs
		var altCompleteHash bytes.Buffer
		altCompleteHash.Write(aggregateHash)
		altCompleteHash.Write([]byte(computedHashHex))

		altExpectedSig := ocrypto.Base64Encode(altCompleteHash.Bytes())
		if storedSig != string(altExpectedSig) {
			return fmt.Errorf("%w: aggregate signature mismatch (tried both binary and hex formats)", ErrAssertionInvalidSignature)
		}
	}

	return nil
}

// computeAssertionHash computes the canonical hash of an assertion.
// It excludes the Binding field and uses JCS for canonical JSON.
func computeAssertionHash(a Assertion) ([]byte, error) {
	// Create a copy without the binding
	cleanAssertion := Assertion{
		ID:             a.ID,
		Type:           a.Type,
		Scope:          a.Scope,
		AppliesToState: a.AppliesToState,
		Statement:      a.Statement,
		// Binding is intentionally omitted
	}

	// Marshal to JSON
	assertionJSON, err := json.Marshal(cleanAssertion)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal failed: %w", err)
	}

	// Transform using JCS for canonical form
	canonicalJSON, err := jcs.Transform(assertionJSON)
	if err != nil {
		return nil, fmt.Errorf("jcs.Transform failed: %w", err)
	}

	// Compute SHA-256 hash and return as hex-encoded bytes
	// (matching the existing implementation which returns hex as bytes)
	hash := ocrypto.SHA256AsHex(canonicalJSON)
	return hash, nil
}

// validateAlgorithm checks if the algorithm is allowed
func validateAlgorithm(alg string) error {
	allowedAlgs := map[string]bool{
		"HS256": true,
		"RS256": true,
	}
	if !allowedAlgs[alg] {
		return fmt.Errorf("%w: %s", ErrAssertionUnsupportedAlg, alg)
	}
	return nil
}

// defaultAssertionSigner is the default implementation of AssertionSigner
type defaultAssertionSigner struct{}

// Sign implements AssertionSigner using the internal signing logic
func (d defaultAssertionSigner) Sign(ctx context.Context, input SignInput, key AssertionKey) (Binding, error) {
	// If aggregate hash is provided, use TDF-specific signing
	if len(input.AggregateHash) > 0 {
		aggregateHashStr := string(input.AggregateHash)
		return internalSignWithAggregateHash(ctx, input.Assertion, key, aggregateHashStr, input.UseHex)
	}
	// Otherwise use standard signing
	return internalSign(ctx, input.Assertion, key)
}

// defaultAssertionVerifier is the default implementation of AssertionVerifier
type defaultAssertionVerifier struct{}

// Verify implements AssertionVerifier using the internal verification logic
func (d defaultAssertionVerifier) Verify(ctx context.Context, input VerifyInput, key AssertionKey) error {
	// If aggregate hash is provided, use TDF-specific verification
	if len(input.AggregateHash) > 0 {
		return internalVerifyWithContext(ctx, input.Assertion, key, input.AggregateHash, input.IsLegacyTDF)
	}
	// Otherwise use standard verification
	return internalVerify(ctx, input.Assertion, key)
}
