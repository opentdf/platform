package sdk

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock signer for testing
type mockAssertionSigner struct {
	signCalls []signCall
	mu        sync.Mutex
	shouldErr bool
	errMsg    string
}

type signCall struct {
	input SignInput
	key   AssertionKey
}

func (m *mockAssertionSigner) Sign(_ context.Context, input SignInput, key AssertionKey) (Binding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.signCalls = append(m.signCalls, signCall{input: input, key: key})

	if m.shouldErr {
		return Binding{}, errors.New(m.errMsg)
	}

	return Binding{
		Method:    "mock",
		Signature: "mock-signature-" + input.Assertion.ID,
		Version:   bindingVersion,
	}, nil
}

func (m *mockAssertionSigner) getCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.signCalls)
}

// Mock verifier for testing
type mockAssertionVerifier struct {
	verifyCalls []verifyCall
	mu          sync.Mutex
	shouldErr   bool
	errMsg      string
}

type verifyCall struct {
	input VerifyInput
	key   AssertionKey
}

func (m *mockAssertionVerifier) Verify(_ context.Context, input VerifyInput, key AssertionKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.verifyCalls = append(m.verifyCalls, verifyCall{input: input, key: key})

	if m.shouldErr {
		if m.errMsg == "invalid-signature" {
			return ErrAssertionInvalidSignature
		}
		return errors.New(m.errMsg)
	}

	return nil
}

func (m *mockAssertionVerifier) getCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.verifyCalls)
}

// Test provider invocation
func TestAssertionProviderInvocation(t *testing.T) {
	mockSigner := &mockAssertionSigner{}
	mockVerifier := &mockAssertionVerifier{}

	// Create SDK with custom providers
	sdk, err := New("http://localhost:8080",
		WithInsecurePlaintextConn(),
		WithPlatformConfiguration(PlatformConfiguration{
			"platform_issuer": "http://localhost:8080",
		}),
		WithAssertionSigner(mockSigner),
		WithAssertionVerifier(mockVerifier),
	)
	require.NoError(t, err)

	// Verify providers are set
	assert.NotNil(t, sdk.assertionSigner)
	assert.NotNil(t, sdk.assertionVerifier)

	// Verify it's our mock providers
	_, ok := sdk.assertionSigner.(*mockAssertionSigner)
	assert.True(t, ok, "Expected mock signer to be set")

	_, ok = sdk.assertionVerifier.(*mockAssertionVerifier)
	assert.True(t, ok, "Expected mock verifier to be set")
}

// Test default providers
func TestDefaultProviders(t *testing.T) {
	// Create SDK without custom providers
	sdk, err := New("http://localhost:8080",
		WithInsecurePlaintextConn(),
		WithPlatformConfiguration(PlatformConfiguration{
			"platform_issuer": "http://localhost:8080",
		}),
	)
	require.NoError(t, err)

	// Verify default providers are set
	assert.NotNil(t, sdk.assertionSigner)
	assert.NotNil(t, sdk.assertionVerifier)

	// Verify they are the default implementations
	_, ok := sdk.assertionSigner.(defaultAssertionSigner)
	assert.True(t, ok, "Expected default signer")

	_, ok = sdk.assertionVerifier.(defaultAssertionVerifier)
	assert.True(t, ok, "Expected default verifier")
}

// Test concurrent signing
func TestConcurrentSigning(t *testing.T) {
	mockSigner := &mockAssertionSigner{}

	ctx := t.Context()
	numGoroutines := 10
	numSignsPerGoroutine := 5

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(_ int) {
			defer wg.Done()

			for j := 0; j < numSignsPerGoroutine; j++ {
				input := SignInput{
					Assertion: Assertion{
						ID:   "test-assertion",
						Type: HandlingAssertion,
					},
				}
				key := AssertionKey{
					Alg: AssertionKeyAlgHS256,
					Key: []byte("test-key"),
				}

				_, err := mockSigner.Sign(ctx, input, key)
				assert.NoError(t, err)
			}
		}(i)
	}

	wg.Wait()

	// Verify all calls were recorded
	expectedCalls := numGoroutines * numSignsPerGoroutine
	assert.Equal(t, expectedCalls, mockSigner.getCallCount())
}

// Test concurrent verification
func TestConcurrentVerification(t *testing.T) {
	mockVerifier := &mockAssertionVerifier{}

	ctx := t.Context()
	numGoroutines := 10
	numVerifiesPerGoroutine := 5

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(_ int) {
			defer wg.Done()

			for j := 0; j < numVerifiesPerGoroutine; j++ {
				input := VerifyInput{
					Assertion: Assertion{
						ID:   "test-assertion",
						Type: HandlingAssertion,
						Binding: Binding{
							Method:    "jws",
							Signature: "test-sig",
						},
					},
				}
				key := AssertionKey{
					Alg: AssertionKeyAlgHS256,
					Key: []byte("test-key"),
				}

				err := mockVerifier.Verify(ctx, input, key)
				assert.NoError(t, err)
			}
		}(i)
	}

	wg.Wait()

	// Verify all calls were recorded
	expectedCalls := numGoroutines * numVerifiesPerGoroutine
	assert.Equal(t, expectedCalls, mockVerifier.getCallCount())
}

// Test error conditions
func TestAssertionErrorConditions(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name          string
		setupVerifier func() AssertionVerifier
		assertion     Assertion
		expectedErr   error
	}{
		{
			name: "missing binding",
			setupVerifier: func() AssertionVerifier {
				return defaultAssertionVerifier{}
			},
			assertion: Assertion{
				ID: "test",
				// No binding
			},
			expectedErr: ErrAssertionMissingBinding,
		},
		{
			name: "invalid signature",
			setupVerifier: func() AssertionVerifier {
				return &mockAssertionVerifier{
					shouldErr: true,
					errMsg:    "invalid-signature",
				}
			},
			assertion: Assertion{
				ID: "test",
				Binding: Binding{
					Method:    "jws",
					Signature: "bad-sig",
				},
			},
			expectedErr: ErrAssertionInvalidSignature,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := tt.setupVerifier()
			key := AssertionKey{
				Alg: AssertionKeyAlgHS256,
				Key: []byte("test-key"),
			}

			input := VerifyInput{Assertion: tt.assertion}
			err := verifier.Verify(ctx, input, key)
			assert.ErrorIs(t, err, tt.expectedErr, "Expected error %v, got %v", tt.expectedErr, err)
		})
	}
}

// Test algorithm validation
func TestAlgorithmValidation(t *testing.T) {
	ctx := t.Context()
	signer := defaultAssertionSigner{}

	// Test with unsupported algorithm
	assertion := Assertion{
		ID:   "test",
		Type: HandlingAssertion,
	}

	key := AssertionKey{
		Alg: "UNSUPPORTED",
		Key: []byte("test-key"),
	}

	input := SignInput{Assertion: assertion}
	_, err := signer.Sign(ctx, input, key)
	assert.ErrorIs(t, err, ErrAssertionUnsupportedAlg)
}

// Test TDF-specific signing
func TestTDFSpecificSigning(t *testing.T) {
	ctx := t.Context()
	signer := defaultAssertionSigner{}

	assertion := Assertion{
		ID:    "test-assertion",
		Type:  HandlingAssertion,
		Scope: TrustedDataObjScope,
		Statement: Statement{
			Format: "json",
			Schema: "test",
			Value:  `{"test": "value"}`,
		},
	}

	hs256Key := make([]byte, 32)
	_, err := rand.Read(hs256Key)
	require.NoError(t, err)

	key := AssertionKey{
		Alg: AssertionKeyAlgHS256,
		Key: hs256Key,
	}

	// Test regular signing
	input1 := SignInput{Assertion: assertion}
	binding1, err := signer.Sign(ctx, input1, key)
	require.NoError(t, err)
	assert.NotEmpty(t, binding1.Signature)
	assert.Equal(t, "jws", binding1.Method)
	assert.Equal(t, bindingVersion, binding1.Version)

	// Test TDF-specific signing with aggregate hash
	input2 := SignInput{
		Assertion:     assertion,
		AggregateHash: []byte("test-aggregate-hash"),
		UseHex:        false,
	}

	binding2, err := signer.Sign(ctx, input2, key)
	require.NoError(t, err)
	assert.NotEmpty(t, binding2.Signature)
	assert.Equal(t, "jws", binding2.Method)
	assert.Equal(t, bindingVersion, binding2.Version)

	// Signatures should be different due to aggregate hash
	assert.NotEqual(t, binding1.Signature, binding2.Signature)
}

// Test TDF-specific verification
func TestTDFSpecificVerification(t *testing.T) {
	ctx := t.Context()
	signer := defaultAssertionSigner{}
	verifier := defaultAssertionVerifier{}

	assertion := Assertion{
		ID:    "test-assertion",
		Type:  HandlingAssertion,
		Scope: TrustedDataObjScope,
		Statement: Statement{
			Format: "json",
			Schema: "test",
			Value:  `{"test": "value"}`,
		},
	}

	hs256Key := make([]byte, 32)
	_, err := rand.Read(hs256Key)
	require.NoError(t, err)

	key := AssertionKey{
		Alg: AssertionKeyAlgHS256,
		Key: hs256Key,
	}

	// Sign with aggregate hash
	aggregateHash := []byte("test-aggregate")
	input := SignInput{
		Assertion:     assertion,
		AggregateHash: aggregateHash,
		UseHex:        false,
	}

	binding, err := signer.Sign(ctx, input, key)
	require.NoError(t, err)

	assertion.Binding = binding

	// Verify with correct aggregate hash
	verifyInput := VerifyInput{
		Assertion:     assertion,
		AggregateHash: aggregateHash,
		IsLegacyTDF:   false,
	}

	err = verifier.Verify(ctx, verifyInput, key)
	require.NoError(t, err)

	// Verify with wrong aggregate hash should fail
	verifyInput.AggregateHash = []byte("wrong-aggregate")
	err = verifier.Verify(ctx, verifyInput, key)
	assert.Error(t, err)
}

// Test interoperability between default signer and custom verifier
func TestSignerVerifierInterop(t *testing.T) {
	ctx := t.Context()

	// Use default signer
	signer := defaultAssertionSigner{}

	assertion := Assertion{
		ID:    "test",
		Type:  HandlingAssertion,
		Scope: TrustedDataObjScope,
		Statement: Statement{
			Format: "json",
			Value:  `{"test": "data"}`,
		},
	}

	// Generate a key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	key := AssertionKey{
		Alg: AssertionKeyAlgRS256,
		Key: privateKey,
	}

	// Sign with default signer
	input := SignInput{Assertion: assertion}
	binding, err := signer.Sign(ctx, input, key)
	require.NoError(t, err)

	assertion.Binding = binding

	// Verify with custom verifier that always succeeds
	customVerifier := &mockAssertionVerifier{shouldErr: false}
	verifyInput := VerifyInput{Assertion: assertion}
	err = customVerifier.Verify(ctx, verifyInput, key)
	require.NoError(t, err)
	assert.Equal(t, 1, customVerifier.getCallCount())
}

// Test reader-level verifier override
func TestReaderVerifierOverride(t *testing.T) {
	// Create a TDF reader config with custom verifier
	customVerifier := &mockAssertionVerifier{}

	config, err := newTDFReaderConfig(
		WithReaderAssertionVerifier(customVerifier),
	)
	require.NoError(t, err)

	// Verify the custom verifier is set
	assert.NotNil(t, config.assertionVerifier)
	_, ok := config.assertionVerifier.(*mockAssertionVerifier)
	assert.True(t, ok, "Expected custom verifier to be set in reader config")
}

// SECURITY TESTS

// Test canonicalization invariants - different map orders should produce the same digest
func TestCanonicalizationInvariants(t *testing.T) {
	ctx := t.Context()
	signer := defaultAssertionSigner{}

	// Test that identical assertions produce identical hashes
	assertion1 := Assertion{
		ID:             "test-canonical",
		Type:           HandlingAssertion,
		Scope:          TrustedDataObjScope,
		AppliesToState: Encrypted,
		Statement: Statement{
			Format: "json",
			Schema: "test",
			Value:  `{"test":"value"}`,
		},
	}

	assertion2 := Assertion{
		ID:             "test-canonical",
		Type:           HandlingAssertion,
		Scope:          TrustedDataObjScope,
		AppliesToState: Encrypted,
		Statement: Statement{
			Format: "json",
			Schema: "test",
			Value:  `{"test":"value"}`,
		},
	}

	// Compute hashes for both assertions
	hash1, err := computeAssertionHash(assertion1)
	require.NoError(t, err)

	hash2, err := computeAssertionHash(assertion2)
	require.NoError(t, err)

	// Hashes should be identical for identical assertions
	assert.Equal(t, hash1, hash2, "Identical assertions should produce identical hashes")

	// Test that different assertion content produces different hashes
	assertion3 := Assertion{
		ID:             "test-canonical",
		Type:           HandlingAssertion,
		Scope:          TrustedDataObjScope,
		AppliesToState: Encrypted,
		Statement: Statement{
			Format: "json",
			Schema: "test",
			Value:  `{"test":"different"}`,
		},
	}

	hash3, err := computeAssertionHash(assertion3)
	require.NoError(t, err)

	assert.NotEqual(t, hash1, hash3, "Different assertion content should produce different hashes")

	// Test that the JSON canonicalization of the assertion struct itself is deterministic
	// This tests that field order in the JSON representation doesn't matter
	// We'll create the same assertion through JSON marshaling/unmarshaling
	jsonStr := `{
		"statement": {"format": "json", "schema": "test", "value": "{\"data\":\"test\"}"},
		"scope": "tdo",
		"type": "handling",
		"id": "json-test",
		"appliesToState": "encrypted"
	}`

	var assertion4 Assertion
	err = json.Unmarshal([]byte(jsonStr), &assertion4)
	require.NoError(t, err)

	// Create the same assertion programmatically (fields in different order in JSON)
	assertion5 := Assertion{
		ID:             "json-test",
		Type:           HandlingAssertion,
		Scope:          TrustedDataObjScope,
		AppliesToState: Encrypted,
		Statement: Statement{
			Format: "json",
			Schema: "test",
			Value:  `{"data":"test"}`,
		},
	}

	hash4, err := computeAssertionHash(assertion4)
	require.NoError(t, err)

	hash5, err := computeAssertionHash(assertion5)
	require.NoError(t, err)

	assert.Equal(t, hash4, hash5, "JSON field order should not affect canonical hash")

	// Sign both assertions and verify signatures are valid
	key := AssertionKey{
		Alg: AssertionKeyAlgHS256,
		Key: []byte("test-secret-key-32-bytes-long!!!"),
	}

	input1 := SignInput{Assertion: assertion1}
	binding1, err := signer.Sign(ctx, input1, key)
	require.NoError(t, err)
	assert.Equal(t, bindingVersion, binding1.Version)

	input2 := SignInput{Assertion: assertion2}
	binding2, err := signer.Sign(ctx, input2, key)
	require.NoError(t, err)
	assert.Equal(t, bindingVersion, binding2.Version)

	// The bindings should be different (different JWT signatures due to timestamps)
	// but both should verify correctly
	verifier := defaultAssertionVerifier{}

	assertion1.Binding = binding1
	verifyInput1 := VerifyInput{Assertion: assertion1}
	err = verifier.Verify(ctx, verifyInput1, key)
	require.NoError(t, err)

	assertion2.Binding = binding2
	verifyInput2 := VerifyInput{Assertion: assertion2}
	err = verifier.Verify(ctx, verifyInput2, key)
	assert.NoError(t, err)
}

// Test assertion order tampering - swapping assertion order should fail verification
func TestAssertionOrderTampering(t *testing.T) {
	ctx := t.Context()
	signer := defaultAssertionSigner{}
	verifier := defaultAssertionVerifier{}

	// Create multiple assertions that would be aggregated
	assertion1 := Assertion{
		ID:    "assertion-001", // Lexicographically first
		Type:  HandlingAssertion,
		Scope: TrustedDataObjScope,
		Statement: Statement{
			Format: "json",
			Schema: "test",
			Value:  `{"order":1}`,
		},
	}

	assertion2 := Assertion{
		ID:    "assertion-002", // Lexicographically second
		Type:  HandlingAssertion,
		Scope: TrustedDataObjScope,
		Statement: Statement{
			Format: "json",
			Schema: "test",
			Value:  `{"order":2}`,
		},
	}

	key := AssertionKey{
		Alg: AssertionKeyAlgHS256,
		Key: []byte("test-secret-key-32-bytes-long!!!"),
	}

	// Simulate aggregate hash computation in correct order
	// In real TDF, assertions must be processed in lexicographic order by ID
	hash1, err := computeAssertionHash(assertion1)
	require.NoError(t, err)
	hash2, err := computeAssertionHash(assertion2)
	require.NoError(t, err)

	// Correct order: assertion-001, then assertion-002
	correctAggregateHash := make([]byte, 0, len(hash1)+len(hash2))
	correctAggregateHash = append(correctAggregateHash, hash1...)
	correctAggregateHash = append(correctAggregateHash, hash2...)

	// Sign assertions with the correct aggregate hash
	input1 := SignInput{
		Assertion:     assertion1,
		AggregateHash: correctAggregateHash,
		UseHex:        false,
	}
	binding1, err := signer.Sign(ctx, input1, key)
	require.NoError(t, err)
	assertion1.Binding = binding1

	input2 := SignInput{
		Assertion:     assertion2,
		AggregateHash: correctAggregateHash,
		UseHex:        false,
	}
	binding2, err := signer.Sign(ctx, input2, key)
	require.NoError(t, err)
	assertion2.Binding = binding2

	// Verify with correct aggregate hash - should succeed
	verifyInput1 := VerifyInput{
		Assertion:     assertion1,
		AggregateHash: correctAggregateHash,
		IsLegacyTDF:   false,
	}
	err = verifier.Verify(ctx, verifyInput1, key)
	require.NoError(t, err, "Verification with correct aggregate hash should succeed")

	// Simulate tampered aggregate hash (wrong order: assertion-002, then assertion-001)
	tamperedAggregateHash := make([]byte, 0, len(hash2)+len(hash1))
	tamperedAggregateHash = append(tamperedAggregateHash, hash2...)
	tamperedAggregateHash = append(tamperedAggregateHash, hash1...)

	// Verify with tampered aggregate hash - should fail
	verifyInputTampered := VerifyInput{
		Assertion:     assertion1,
		AggregateHash: tamperedAggregateHash,
		IsLegacyTDF:   false,
	}
	err = verifier.Verify(ctx, verifyInputTampered, key)
	require.Error(t, err, "Verification with tampered aggregate hash (wrong order) should fail")
	assert.Contains(t, err.Error(), "aggregate signature mismatch")
}

// Test algorithm policy - unknown/weak algorithms should return ErrUnsupportedAlg
func TestAlgorithmPolicy(t *testing.T) {
	ctx := t.Context()
	signer := defaultAssertionSigner{}
	verifier := defaultAssertionVerifier{}

	assertion := Assertion{
		ID:    "test-alg-policy",
		Type:  HandlingAssertion,
		Scope: TrustedDataObjScope,
		Statement: Statement{
			Format: "json",
			Schema: "test",
			Value:  `{"test":"data"}`,
		},
	}

	tests := []struct {
		name        string
		alg         AssertionKeyAlg
		key         interface{}
		shouldError bool
		expectedErr error
	}{
		{
			name:        "HS256 allowed",
			alg:         AssertionKeyAlgHS256,
			key:         []byte("test-secret-key-32-bytes-long!!!"),
			shouldError: false,
		},
		{
			name: "RS256 allowed",
			alg:  AssertionKeyAlgRS256,
			key: func() interface{} {
				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				return key
			}(),
			shouldError: false,
		},
		{
			name:        "ES256 not allowed",
			alg:         "ES256",
			key:         []byte("doesnt-matter"),
			shouldError: true,
			expectedErr: ErrAssertionUnsupportedAlg,
		},
		{
			name:        "HS512 not allowed",
			alg:         "HS512",
			key:         []byte("doesnt-matter"),
			shouldError: true,
			expectedErr: ErrAssertionUnsupportedAlg,
		},
		{
			name:        "none algorithm blocked",
			alg:         "none",
			key:         nil,
			shouldError: true,
			expectedErr: ErrAssertionUnsupportedAlg,
		},
		{
			name:        "empty algorithm blocked",
			alg:         "",
			key:         []byte("test"),
			shouldError: true,
			expectedErr: ErrAssertionUnsupportedAlg,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := AssertionKey{
				Alg: tt.alg,
				Key: tt.key,
			}

			// Test signing with algorithm
			input := SignInput{Assertion: assertion}
			binding, err := signer.Sign(ctx, input, key)

			if tt.shouldError {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.expectedErr, "Expected error %v, got %v", tt.expectedErr, err)
				assert.Empty(t, binding.Signature)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, binding.Signature)

				// If signing succeeded, verification should also succeed
				assertion.Binding = binding
				verifyInput := VerifyInput{Assertion: assertion}
				err = verifier.Verify(ctx, verifyInput, key)
				require.NoError(t, err)
			}

			// Test verification with algorithm (for blocked algorithms)
			if tt.shouldError {
				// Create a fake binding to test verification
				assertion.Binding = Binding{
					Method:    "jws",
					Signature: "fake-signature",
					Version:   bindingVersion,
				}
				verifyInput := VerifyInput{Assertion: assertion}
				err = verifier.Verify(ctx, verifyInput, key)
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.expectedErr, "Verify should also reject unsupported algorithm")
			}
		})
	}
}

// Test that binding version is properly set and validated
func TestBindingVersion(t *testing.T) {
	ctx := t.Context()
	signer := defaultAssertionSigner{}

	assertion := Assertion{
		ID:    "test-version",
		Type:  HandlingAssertion,
		Scope: PayloadScope,
		Statement: Statement{
			Format: "json",
			Schema: "test",
			Value:  `{"test":"version"}`,
		},
	}

	key := AssertionKey{
		Alg: AssertionKeyAlgHS256,
		Key: []byte("test-secret-key-32-bytes-long!!!"),
	}

	// Sign and verify version is set
	input := SignInput{Assertion: assertion}
	binding, err := signer.Sign(ctx, input, key)
	require.NoError(t, err)

	assert.Equal(t, bindingVersion, binding.Version, "Binding version should be set to current version")
	assert.Equal(t, "1.0", binding.Version, "Version should be 1.0")

	// Test with aggregate hash - version should still be set
	inputWithHash := SignInput{
		Assertion:     assertion,
		AggregateHash: []byte("test-aggregate"),
		UseHex:        false,
	}
	bindingWithHash, err := signer.Sign(ctx, inputWithHash, key)
	require.NoError(t, err)

	assert.Equal(t, bindingVersion, bindingWithHash.Version, "Binding version should be set even with aggregate hash")
}

// Test legacy TDF hex encoding compatibility
func TestLegacyTDFHexEncoding(t *testing.T) {
	ctx := t.Context()
	signer := defaultAssertionSigner{}
	verifier := defaultAssertionVerifier{}

	assertion := Assertion{
		ID:    "legacy-test",
		Type:  HandlingAssertion,
		Scope: TrustedDataObjScope,
		Statement: Statement{
			Format: "json",
			Schema: "test",
			Value:  `{"legacy":true}`,
		},
	}

	key := AssertionKey{
		Alg: AssertionKeyAlgHS256,
		Key: []byte("test-secret-key-32-bytes-long!!!"),
	}

	aggregateHash := []byte("test-aggregate-hash")

	// Sign with hex encoding (legacy TDF)
	inputHex := SignInput{
		Assertion:     assertion,
		AggregateHash: aggregateHash,
		UseHex:        true, // Legacy TDF uses hex
	}
	bindingHex, err := signer.Sign(ctx, inputHex, key)
	require.NoError(t, err)

	// Sign without hex encoding (modern TDF)
	inputBinary := SignInput{
		Assertion:     assertion,
		AggregateHash: aggregateHash,
		UseHex:        false, // Modern TDF uses binary
	}
	bindingBinary, err := signer.Sign(ctx, inputBinary, key)
	require.NoError(t, err)

	// Signatures should be different
	assert.NotEqual(t, bindingHex.Signature, bindingBinary.Signature, "Hex and binary encodings should produce different signatures")

	// Verify legacy TDF (with hex)
	assertion.Binding = bindingHex
	verifyInputLegacy := VerifyInput{
		Assertion:     assertion,
		AggregateHash: aggregateHash,
		IsLegacyTDF:   true, // Must match signing mode
	}
	err = verifier.Verify(ctx, verifyInputLegacy, key)
	require.NoError(t, err, "Legacy TDF verification should succeed")

	// Verify modern TDF (without hex)
	assertion.Binding = bindingBinary
	verifyInputModern := VerifyInput{
		Assertion:     assertion,
		AggregateHash: aggregateHash,
		IsLegacyTDF:   false, // Must match signing mode
	}
	err = verifier.Verify(ctx, verifyInputModern, key)
	require.NoError(t, err, "Modern TDF verification should succeed")

	// Cross-verification now succeeds due to fallback compatibility logic
	// This allows Java-Go SDK interoperability
	assertion.Binding = bindingHex
	verifyInputCross := VerifyInput{
		Assertion:     assertion,
		AggregateHash: aggregateHash,
		IsLegacyTDF:   false, // Mismatch, but fallback should handle it
	}
	err = verifier.Verify(ctx, verifyInputCross, key)
	assert.NoError(t, err, "Cross-verification should succeed with fallback compatibility logic")
}
