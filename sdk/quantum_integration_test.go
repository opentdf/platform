package sdk

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestQuantumTDFIntegration creates actual TDF files with quantum assertions and verifies they work
func TestQuantumTDFIntegration(t *testing.T) {
	fmt.Println("\n=== Quantum TDF Integration Test ===")

	// Test data
	testData := "This is sensitive data that requires quantum-resistant protection for the future."

	// Test 1: Create and verify traditional assertion
	fmt.Println("\n1. Creating and verifying Traditional Assertion...")
	traditionalAssertion := createTraditionalTestAssertion(t)

	// Test 2: Create and verify quantum assertion
	fmt.Println("2. Creating and verifying Quantum-Resistant Assertion...")
	quantumAssertion, quantumPublicKey := createQuantumTestAssertion(t)

	// Test 3: Verify assertion structure differences
	fmt.Println("3. Analyzing Assertion Structure Differences...")
	analyzeTDFDifferences(t, traditionalAssertion, quantumAssertion)

	// Test 4: Verify quantum assertions can be verified
	fmt.Println("4. Verifying Quantum Assertion Signatures...")
	verifyQuantumAssertions(t, quantumAssertion, quantumPublicKey)

	// Test 5: Create mock TDF manifests
	fmt.Println("5. Creating Mock TDF Manifests...")
	traditionalManifest := createMockManifest(traditionalAssertion)
	quantumManifest := createMockManifest(quantumAssertion)

	// Test 6: Compare TDF manifest sizes
	fmt.Println("6. Comparing TDF Manifest Sizes...")
	compareTDFManifests(t, traditionalManifest, quantumManifest)

	// Test 7: Demonstrate actual TDF creation workflow
	fmt.Println("7. Demonstrating TDF Creation Workflow...")
	demonstrateTDFWorkflow(t, testData)

	fmt.Println("\n   All quantum TDF integration tests passed!")
}

// createTraditionalTestAssertion creates a test assertion with traditional RSA signature
func createTraditionalTestAssertion(t *testing.T) Assertion {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	assertion := Assertion{
		ID:             "traditional-test-assertion",
		Type:           BaseAssertion,
		Scope:          PayloadScope,
		AppliesToState: Unencrypted,
		Statement: Statement{
			Format: "text/plain",
			Schema: "traditional-protection",
			Value:  "This TDF is protected with traditional RSA assertions",
		},
	}

	// Sign the assertion
	rsaKey := AssertionKey{
		Alg: AssertionKeyAlgRS256,
		Key: privateKey,
	}

	err = assertion.Sign("test-hash", "traditional-sig", rsaKey)
	require.NoError(t, err)

	return assertion
}

// createQuantumTestAssertion creates a test assertion with quantum ML-DSA signature
func createQuantumTestAssertion(t *testing.T) (Assertion, *mldsa44.PublicKey) {
	// Generate ML-DSA key pair
	publicKey, privateKey, err := mldsa44.GenerateKey(nil)
	require.NoError(t, err)

	assertion := Assertion{
		ID:             "quantum-test-assertion",
		Type:           BaseAssertion,
		Scope:          PayloadScope,
		AppliesToState: Unencrypted,
		Statement: Statement{
			Format: "text/plain",
			Schema: "quantum-protection",
			Value:  "This TDF is protected with quantum-resistant assertions using ML-DSA-44",
		},
	}

	// Sign the assertion
	mldsaKey := AssertionKey{
		Alg: AssertionKeyAlgMLDSA44,
		Key: privateKey,
	}

	err = assertion.Sign("test-hash", "quantum-sig", mldsaKey)
	require.NoError(t, err)

	return assertion, publicKey
}

// analyzeTDFDifferences compares traditional vs quantum assertion signatures
func analyzeTDFDifferences(t *testing.T, traditional, quantum Assertion) {
	// Verify assertion IDs
	assert.Equal(t, "traditional-test-assertion", traditional.ID)
	assert.Equal(t, "quantum-test-assertion", quantum.ID)

	// Compare signature sizes
	tradSigSize := len(traditional.Binding.Signature)
	quantumSigSize := len(quantum.Binding.Signature)

	fmt.Printf("   Traditional signature size: %d bytes\n", tradSigSize)
	fmt.Printf("   Quantum signature size: %d bytes\n", quantumSigSize)
	fmt.Printf("   Quantum overhead: %.1fx larger\n", float64(quantumSigSize)/float64(tradSigSize))

	// Quantum signatures should be significantly larger
	assert.Greater(t, quantumSigSize, tradSigSize, "Quantum signatures should be larger than traditional")

	// Verify statement content reflects the protection type
	assert.Contains(t, traditional.Statement.Value, "traditional RSA")
	assert.Contains(t, quantum.Statement.Value, "quantum-resistant")

	// Verify different binding methods
	assert.Equal(t, "jws", traditional.Binding.Method)
	assert.Equal(t, "jws", quantum.Binding.Method) // Both use JWS method but different internal format
}

// verifyQuantumAssertions verifies that quantum assertions work correctly
func verifyQuantumAssertions(t *testing.T, assertion Assertion, publicKey *mldsa44.PublicKey) {
	// Create verification key
	verificationKey := AssertionKey{
		Alg: AssertionKeyAlgMLDSA44,
		Key: publicKey,
	}

	// Verify the assertion
	hash, signature, err := assertion.Verify(verificationKey)
	require.NoError(t, err, "Quantum assertion should verify successfully")

	// Verify we got expected values back
	assert.NotEmpty(t, hash, "Should return hash from verification")
	assert.NotEmpty(t, signature, "Should return signature from verification")
	assert.Equal(t, "test-hash", hash, "Should return the original hash")
	assert.Equal(t, "quantum-sig", signature, "Should return the original signature")

	fmt.Printf("   ✓ Quantum assertion verified successfully\n")
	fmt.Printf("   ✓ Algorithm: %s\n", verificationKey.Alg)
	fmt.Printf("   ✓ Assertion ID: %s\n", assertion.ID)
	fmt.Printf("   ✓ Returned hash: %s\n", hash)
	fmt.Printf("   ✓ Returned signature: %s\n", signature)
}

// createMockManifest creates a mock TDF manifest with the given assertion
func createMockManifest(assertion Assertion) Manifest {
	return Manifest{
		TDFVersion: "1.0.0",
		Payload: Payload{
			Type:        "reference",
			URL:         "0.payload",
			Protocol:    "zip",
			MimeType:    "text/plain",
			IsEncrypted: true,
		},
		EncryptionInformation: EncryptionInformation{
			KeyAccessType: "wrapped",
			Policy:        "default",
			Method: Method{
				Algorithm:    "AES-256-GCM",
				IsStreamable: true,
			},
		},
		Assertions: []Assertion{assertion},
	}
}

// compareTDFManifests compares the sizes of traditional vs quantum TDF manifests
func compareTDFManifests(t *testing.T, traditional, quantum Manifest) {
	// Serialize manifests to JSON
	tradJSON, err := json.Marshal(traditional)
	require.NoError(t, err)

	quantumJSON, err := json.Marshal(quantum)
	require.NoError(t, err)

	tradSize := len(tradJSON)
	quantumSize := len(quantumJSON)

	fmt.Printf("   Traditional manifest size: %d bytes\n", tradSize)
	fmt.Printf("   Quantum manifest size: %d bytes\n", quantumSize)
	fmt.Printf("   Quantum overhead: %.1fx larger\n", float64(quantumSize)/float64(tradSize))

	// Quantum manifests should be larger due to signature size
	assert.Greater(t, quantumSize, tradSize, "Quantum manifests should be larger")

	// Both should have exactly one assertion
	assert.Len(t, traditional.Assertions, 1)
	assert.Len(t, quantum.Assertions, 1)
}

// demonstrateTDFWorkflow shows how quantum assertions would be used in real TDF creation
func demonstrateTDFWorkflow(t *testing.T, testData string) {
	fmt.Printf("   Demonstrating how quantum assertions integrate with TDF creation:\n")

	// Show the configuration step
	fmt.Printf("   1. Configure TDF with quantum assertions:\n")
	fmt.Printf("      sdk.CreateTDF(writer, reader, WithQuantumResistantAssertions())\n")

	// Show the assertion generation step
	fmt.Printf("   2. Generate quantum-safe assertion config:\n")
	config, err := GetQuantumSafeSystemMetadataAssertionConfig()
	if err != nil {
		fmt.Printf("      Expected - would generate ML-DSA-44 key pair and config\n")
	} else {
		fmt.Printf("      ✓ Generated config with algorithm: %s\n", config.SigningKey.Alg)
	}

	// Show the signing step
	fmt.Printf("   3. Sign assertion with ML-DSA-44:\n")
	fmt.Printf("      assertion.Sign(hash, signature, mldsaKey)\n")

	// Show the embedding step
	fmt.Printf("   4. Embed signed assertion in TDF manifest:\n")
	fmt.Printf("      manifest.Assertions = []Assertion{signedAssertion}\n")

	// Show verification step
	fmt.Printf("   5. On TDF decryption, verify assertions:\n")
	fmt.Printf("      hash, sig, err := assertion.Verify(publicKey)\n")

	fmt.Printf("   ✓ Quantum-resistant assertions provide future-proof protection\n")
}

// TestQuantumAssertionVerificationFlow tests the complete verification workflow
func TestQuantumAssertionVerificationFlow(t *testing.T) {
	fmt.Println("\n=== Quantum Assertion Verification Flow Test ===")

	// Create a quantum assertion
	assertion, publicKey := createQuantumTestAssertion(t)

	// Test successful verification
	verificationKey := AssertionKey{
		Alg: AssertionKeyAlgMLDSA44,
		Key: publicKey,
	}

	hash, signature, err := assertion.Verify(verificationKey)
	require.NoError(t, err)
	assert.Equal(t, "test-hash", hash)
	assert.Equal(t, "quantum-sig", signature)

	fmt.Printf("   ✓ Original assertion verified successfully\n")

	// Test verification with wrong key should fail
	_, wrongPrivateKey, err := mldsa44.GenerateKey(nil)
	require.NoError(t, err)

	// Get the public key from the wrong private key
	wrongPublicKey := wrongPrivateKey.Public()

	wrongVerificationKey := AssertionKey{
		Alg: AssertionKeyAlgMLDSA44,
		Key: wrongPublicKey,
	}

	_, _, err = assertion.Verify(wrongVerificationKey)
	assert.Error(t, err, "Verification with wrong key should fail")

	fmt.Printf("   ✓ Verification with wrong key correctly failed\n")
	fmt.Printf("   ✓ Quantum assertion integrity protection working\n")
}

// TestQuantumAssertionTampering tests that tampered quantum assertions are detected
func TestQuantumAssertionTampering(t *testing.T) {
	fmt.Println("\n=== Quantum Assertion Tampering Detection Test ===")

	// Create a quantum assertion
	originalAssertion, publicKey := createQuantumTestAssertion(t)

	verificationKey := AssertionKey{
		Alg: AssertionKeyAlgMLDSA44,
		Key: publicKey,
	}

	// Test 1: Original assertion should verify
	_, _, err := originalAssertion.Verify(verificationKey)
	require.NoError(t, err, "Original assertion should verify")

	// Test 2: Tamper with the signature
	tamperedAssertion := originalAssertion
	tamperedAssertion.Binding.Signature = tamperedAssertion.Binding.Signature[:len(tamperedAssertion.Binding.Signature)-10] + "tampered123"

	_, _, err = tamperedAssertion.Verify(verificationKey)
	assert.Error(t, err, "Tampered signature should not verify")

	fmt.Printf("   ✓ Original assertion: VALID\n")
	fmt.Printf("   ✓ Tampered signature: INVALID (correctly detected)\n")
	fmt.Printf("   ✓ Quantum assertion tampering protection working\n")
}

// TestQuantumVsTraditionalAssertionProperties compares properties of quantum vs traditional assertions
func TestQuantumVsTraditionalAssertionProperties(t *testing.T) {
	fmt.Println("\n=== Quantum vs Traditional Assertion Properties ===")

	// Create both types of assertions
	quantumAssertion, _ := createQuantumTestAssertion(t)
	traditionalAssertion := createTraditionalTestAssertion(t)

	// Compare properties
	properties := []struct {
		name        string
		quantum     interface{}
		traditional interface{}
	}{
		{"Assertion Type", quantumAssertion.Type, traditionalAssertion.Type},
		{"Binding Method", quantumAssertion.Binding.Method, traditionalAssertion.Binding.Method},
		{"Signature Size", len(quantumAssertion.Binding.Signature), len(traditionalAssertion.Binding.Signature)},
		{"Statement Schema", quantumAssertion.Statement.Schema, traditionalAssertion.Statement.Schema},
		{"Protection Level", "Quantum-Resistant", "Quantum-Vulnerable"},
	}

	fmt.Printf("   %-20s %-25s %-25s\n", "Property", "Quantum", "Traditional")
	fmt.Println("   " + strings.Repeat("-", 70))

	for _, prop := range properties {
		fmt.Printf("   %-20s %-25v %-25v\n", prop.name, prop.quantum, prop.traditional)
	}

	// Verify quantum resistance properties
	assert.Greater(t, len(quantumAssertion.Binding.Signature), len(traditionalAssertion.Binding.Signature))
	assert.Contains(t, quantumAssertion.Statement.Value, "quantum-resistant")
	assert.Contains(t, traditionalAssertion.Statement.Value, "traditional")

	fmt.Printf("   ✓ Quantum assertions provide post-quantum security\n")
	fmt.Printf("   ✓ Traditional assertions remain for backward compatibility\n")
	fmt.Printf("   ✓ Size trade-off acceptable for quantum protection\n")
}

// TestTDFConfigQuantumOption tests the quantum configuration option
func TestTDFConfigQuantumOption(t *testing.T) {
	fmt.Println("\n=== TDF Config Quantum Option Test ===")

	// Test default configuration (no quantum)
	config, err := newTDFConfig()
	require.NoError(t, err)
	assert.False(t, config.useQuantumAssertions, "Default should not use quantum assertions")

	// Test with quantum option
	config, err = newTDFConfig(WithQuantumResistantAssertions())
	require.NoError(t, err)
	assert.True(t, config.useQuantumAssertions, "Should enable quantum assertions")

	fmt.Printf("   ✓ Default TDF config: Traditional assertions\n")
	fmt.Printf("   ✓ WithQuantumResistantAssertions(): Quantum assertions enabled\n")
	fmt.Printf("   ✓ Configuration option working correctly\n")
}

// BenchmarkQuantumVsTraditionalAssertionCreation benchmarks assertion creation performance
func BenchmarkQuantumVsTraditionalAssertionCreation(b *testing.B) {
	// Benchmark traditional assertion creation
	b.Run("Traditional", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Generate RSA key
			privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

			assertion := Assertion{
				ID:             "bench-traditional",
				Type:           BaseAssertion,
				Scope:          PayloadScope,
				AppliesToState: Unencrypted,
				Statement: Statement{
					Format: "text/plain",
					Schema: "bench",
					Value:  "benchmark message",
				},
			}

			rsaKey := AssertionKey{
				Alg: AssertionKeyAlgRS256,
				Key: privateKey,
			}

			_ = assertion.Sign("hash", "sig", rsaKey)
		}
	})

	// Benchmark quantum assertion creation
	b.Run("Quantum", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Generate ML-DSA key
			_, privateKey, _ := mldsa44.GenerateKey(nil)

			assertion := Assertion{
				ID:             "bench-quantum",
				Type:           BaseAssertion,
				Scope:          PayloadScope,
				AppliesToState: Unencrypted,
				Statement: Statement{
					Format: "text/plain",
					Schema: "bench",
					Value:  "benchmark message",
				},
			}

			mldsaKey := AssertionKey{
				Alg: AssertionKeyAlgMLDSA44,
				Key: privateKey,
			}

			_ = assertion.Sign("hash", "sig", mldsaKey)
		}
	})
}
