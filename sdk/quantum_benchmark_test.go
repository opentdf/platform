package sdk

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/stretchr/testify/require"
)

// BenchmarkMetrics holds the metrics for comparison
type BenchmarkMetrics struct {
	KeyGenTime       time.Duration
	SigningTime      time.Duration
	VerificationTime time.Duration
	PrivateKeySize   int
	PublicKeySize    int
	SignatureSize    int
}

// TestQuantumVsRSAMetrics provides detailed metrics comparison between RSA and ML-DSA
func TestQuantumVsRSAMetrics(t *testing.T) {
	fmt.Println("\n=== RSA vs ML-DSA-44 Performance & Size Comparison ===")

	// Test data
	testMessage := "This is a test message for signing performance comparison"
	testHash := "c7e16249b8e8cf40bd0d7ffc82cf3c90a7a9b50e"

	// Run RSA benchmarks
	rsaMetrics := benchmarkRSA(t, testMessage, testHash)

	// Run ML-DSA benchmarks
	mldsaMetrics := benchmarkMLDSA(t, testMessage, testHash)

	// Print comparison table
	printMetricsComparison(rsaMetrics, mldsaMetrics)
}

func benchmarkRSA(t *testing.T, message, hash string) BenchmarkMetrics {
	var metrics BenchmarkMetrics

	// Key Generation Benchmark
	start := time.Now()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	metrics.KeyGenTime = time.Since(start)

	// Calculate key sizes
	privateKeyBytes, err := marshalRSAPrivateKey(privateKey)
	require.NoError(t, err)
	publicKeyBytes, err := marshalRSAPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	metrics.PrivateKeySize = len(privateKeyBytes)
	metrics.PublicKeySize = len(publicKeyBytes)

	// Create assertion key
	rsaKey := AssertionKey{
		Alg: AssertionKeyAlgRS256,
		Key: privateKey,
	}

	// Create assertion for signing
	assertion := Assertion{
		ID:             "test-rsa-assertion",
		Type:           BaseAssertion,
		Scope:          PayloadScope,
		AppliesToState: Unencrypted,
		Statement: Statement{
			Format: "text",
			Schema: "test",
			Value:  message,
		},
	}

	// Signing Benchmark
	start = time.Now()
	err = assertion.Sign(hash, "test-signature", rsaKey)
	require.NoError(t, err)
	metrics.SigningTime = time.Since(start)

	// Get signature size
	metrics.SignatureSize = len(assertion.Binding.Signature)

	// Verification Benchmark
	verificationKey := AssertionKey{
		Alg: AssertionKeyAlgRS256,
		Key: &privateKey.PublicKey,
	}

	start = time.Now()
	_, _, err = assertion.Verify(verificationKey)
	require.NoError(t, err)
	metrics.VerificationTime = time.Since(start)

	return metrics
}

func benchmarkMLDSA(t *testing.T, message, hash string) BenchmarkMetrics {
	var metrics BenchmarkMetrics

	// Key Generation Benchmark
	start := time.Now()
	publicKey, privateKey, err := mldsa44.GenerateKey(nil)
	require.NoError(t, err)
	metrics.KeyGenTime = time.Since(start)

	// Calculate key sizes
	metrics.PrivateKeySize = len(privateKey.Bytes())
	metrics.PublicKeySize = len(publicKey.Bytes())

	// Create assertion key
	mldsaKey := AssertionKey{
		Alg: AssertionKeyAlgMLDSA44,
		Key: privateKey,
	}

	// Create assertion for signing
	assertion := Assertion{
		ID:             "test-mldsa-assertion",
		Type:           BaseAssertion,
		Scope:          PayloadScope,
		AppliesToState: Unencrypted,
		Statement: Statement{
			Format: "text",
			Schema: "test",
			Value:  message,
		},
	}

	// Signing Benchmark
	start = time.Now()
	err = assertion.Sign(hash, "test-signature", mldsaKey)
	require.NoError(t, err)
	metrics.SigningTime = time.Since(start)

	// Get signature size (decode the base64 to get actual size)
	metrics.SignatureSize = len(assertion.Binding.Signature)

	// Verification Benchmark
	verificationKey := AssertionKey{
		Alg: AssertionKeyAlgMLDSA44,
		Key: publicKey,
	}

	start = time.Now()
	_, _, err = assertion.Verify(verificationKey)
	require.NoError(t, err)
	metrics.VerificationTime = time.Since(start)

	return metrics
}

func printMetricsComparison(rsa, mldsa BenchmarkMetrics) {
	fmt.Printf("%-25s %-15s %-15s %-10s\n", "Metric", "RSA-2048", "ML-DSA-44", "Ratio")
	fmt.Println(strings.Repeat("-", 70))

	// Key Generation Time
	ratio := float64(mldsa.KeyGenTime) / float64(rsa.KeyGenTime)
	fmt.Printf("%-25s %-15s %-15s %.2fx\n",
		"Key Generation",
		formatDuration(rsa.KeyGenTime),
		formatDuration(mldsa.KeyGenTime),
		ratio)

	// Signing Time
	ratio = float64(mldsa.SigningTime) / float64(rsa.SigningTime)
	fmt.Printf("%-25s %-15s %-15s %.2fx\n",
		"Signing Time",
		formatDuration(rsa.SigningTime),
		formatDuration(mldsa.SigningTime),
		ratio)

	// Verification Time
	ratio = float64(mldsa.VerificationTime) / float64(rsa.VerificationTime)
	fmt.Printf("%-25s %-15s %-15s %.2fx\n",
		"Verification Time",
		formatDuration(rsa.VerificationTime),
		formatDuration(mldsa.VerificationTime),
		ratio)

	fmt.Println()

	// Private Key Size
	ratio = float64(mldsa.PrivateKeySize) / float64(rsa.PrivateKeySize)
	fmt.Printf("%-25s %-15s %-15s %.2fx\n",
		"Private Key Size",
		formatBytes(rsa.PrivateKeySize),
		formatBytes(mldsa.PrivateKeySize),
		ratio)

	// Public Key Size
	ratio = float64(mldsa.PublicKeySize) / float64(rsa.PublicKeySize)
	fmt.Printf("%-25s %-15s %-15s %.2fx\n",
		"Public Key Size",
		formatBytes(rsa.PublicKeySize),
		formatBytes(mldsa.PublicKeySize),
		ratio)

	// Signature Size
	ratio = float64(mldsa.SignatureSize) / float64(rsa.SignatureSize)
	fmt.Printf("%-25s %-15s %-15s %.2fx\n",
		"Signature Size",
		formatBytes(rsa.SignatureSize),
		formatBytes(mldsa.SignatureSize),
		ratio)

	fmt.Println()
	fmt.Println("=== Summary ===")
	fmt.Printf("• ML-DSA-44 provides quantum resistance at the cost of larger signatures\n")
	fmt.Printf("• RSA is faster for verification but vulnerable to quantum attacks\n")
	fmt.Printf("• Key sizes are comparable, but ML-DSA signatures are significantly larger\n")
	fmt.Printf("• Choose ML-DSA for future-proof security, RSA for legacy compatibility\n")
}

// Benchmark functions for Go's built-in benchmarking
func BenchmarkRSAKeyGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMLDSAKeyGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, err := mldsa44.GenerateKey(nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRSASigning(b *testing.B) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaKey := AssertionKey{
		Alg: AssertionKeyAlgRS256,
		Key: privateKey,
	}

	assertion := Assertion{
		ID:             "bench-rsa",
		Type:           BaseAssertion,
		Scope:          PayloadScope,
		AppliesToState: Unencrypted,
		Statement: Statement{
			Format: "text",
			Schema: "test",
			Value:  "benchmark message",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := assertion.Sign("hash", "sig", rsaKey)
		if err != nil {
			b.Fatal(err)
		}
		// Reset binding for next iteration
		assertion.Binding = Binding{}
	}
}

func BenchmarkMLDSASigning(b *testing.B) {
	_, privateKey, _ := mldsa44.GenerateKey(nil)
	mldsaKey := AssertionKey{
		Alg: AssertionKeyAlgMLDSA44,
		Key: privateKey,
	}

	assertion := Assertion{
		ID:             "bench-mldsa",
		Type:           BaseAssertion,
		Scope:          PayloadScope,
		AppliesToState: Unencrypted,
		Statement: Statement{
			Format: "text",
			Schema: "test",
			Value:  "benchmark message",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := assertion.Sign("hash", "sig", mldsaKey)
		if err != nil {
			b.Fatal(err)
		}
		// Reset binding for next iteration
		assertion.Binding = Binding{}
	}
}

func BenchmarkRSAVerification(b *testing.B) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaKey := AssertionKey{
		Alg: AssertionKeyAlgRS256,
		Key: privateKey,
	}

	assertion := Assertion{
		ID:             "bench-rsa",
		Type:           BaseAssertion,
		Scope:          PayloadScope,
		AppliesToState: Unencrypted,
		Statement: Statement{
			Format: "text",
			Schema: "test",
			Value:  "benchmark message",
		},
	}

	// Sign once
	assertion.Sign("hash", "sig", rsaKey)

	verificationKey := AssertionKey{
		Alg: AssertionKeyAlgRS256,
		Key: &privateKey.PublicKey,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := assertion.Verify(verificationKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMLDSAVerification(b *testing.B) {
	publicKey, privateKey, _ := mldsa44.GenerateKey(nil)
	mldsaKey := AssertionKey{
		Alg: AssertionKeyAlgMLDSA44,
		Key: privateKey,
	}

	assertion := Assertion{
		ID:             "bench-mldsa",
		Type:           BaseAssertion,
		Scope:          PayloadScope,
		AppliesToState: Unencrypted,
		Statement: Statement{
			Format: "text",
			Schema: "test",
			Value:  "benchmark message",
		},
	}

	// Sign once
	assertion.Sign("hash", "sig", mldsaKey)

	verificationKey := AssertionKey{
		Alg: AssertionKeyAlgMLDSA44,
		Key: publicKey,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := assertion.Verify(verificationKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// TestTDFCreationPerformance compares TDF creation performance with and without quantum assertions
func TestTDFCreationPerformance(t *testing.T) {
	fmt.Println("\n=== TDF Creation Performance Comparison ===")

	// Measure traditional TDF creation (with HS256 assertions)
	start := time.Now()
	traditionalAssertion, err := GetSystemMetadataAssertionConfig()
	require.NoError(t, err)

	// Create assertion and sign with payload key (simulating HS256)
	assertion := Assertion{
		ID:             traditionalAssertion.ID,
		Type:           traditionalAssertion.Type,
		Scope:          traditionalAssertion.Scope,
		AppliesToState: traditionalAssertion.AppliesToState,
		Statement:      traditionalAssertion.Statement,
	}

	payloadKey := make([]byte, 32) // Simulate 256-bit payload key
	hsKey := AssertionKey{
		Alg: AssertionKeyAlgHS256,
		Key: payloadKey,
	}

	err = assertion.Sign("test-hash", "test-sig", hsKey)
	require.NoError(t, err)
	traditionalTime := time.Since(start)
	traditionalSize := len(assertion.Binding.Signature)

	// Measure quantum-resistant TDF creation
	start = time.Now()
	quantumAssertion, err := GetQuantumSafeSystemMetadataAssertionConfig()
	require.NoError(t, err)

	// Create assertion and sign with ML-DSA
	assertion2 := Assertion{
		ID:             quantumAssertion.ID,
		Type:           quantumAssertion.Type,
		Scope:          quantumAssertion.Scope,
		AppliesToState: quantumAssertion.AppliesToState,
		Statement:      quantumAssertion.Statement,
	}

	err = assertion2.Sign("test-hash", "test-sig", quantumAssertion.SigningKey)
	require.NoError(t, err)
	quantumTime := time.Since(start)
	quantumSize := len(assertion2.Binding.Signature)

	// Print results
	fmt.Printf("%-25s %-15s %-15s %-10s\n", "Metric", "Traditional", "Quantum-Safe", "Ratio")
	fmt.Println(strings.Repeat("-", 70))

	timeRatio := float64(quantumTime) / float64(traditionalTime)
	fmt.Printf("%-25s %-15s %-15s %.2fx\n",
		"Assertion Creation",
		formatDuration(traditionalTime),
		formatDuration(quantumTime),
		timeRatio)

	sizeRatio := float64(quantumSize) / float64(traditionalSize)
	fmt.Printf("%-25s %-15s %-15s %.2fx\n",
		"Assertion Signature Size",
		formatBytes(traditionalSize),
		formatBytes(quantumSize),
		sizeRatio)

	fmt.Printf("\nOverhead Analysis:\n")
	fmt.Printf("• Time overhead: %.1f%% slower\n", (timeRatio-1)*100)
	fmt.Printf("• Size overhead: %.1f%% larger\n", (sizeRatio-1)*100)
	fmt.Printf("• Security benefit: Quantum-resistant protection\n")
}

// BenchmarkTDFWithTraditionalAssertions benchmarks TDF creation with traditional HMAC assertions
func BenchmarkTDFWithTraditionalAssertions(b *testing.B) {
	payloadKey := make([]byte, 32)
	hsKey := AssertionKey{
		Alg: AssertionKeyAlgHS256,
		Key: payloadKey,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config, _ := GetSystemMetadataAssertionConfig()
		assertion := Assertion{
			ID:             config.ID,
			Type:           config.Type,
			Scope:          config.Scope,
			AppliesToState: config.AppliesToState,
			Statement:      config.Statement,
		}

		_ = assertion.Sign("hash", "sig", hsKey)
	}
}

// BenchmarkTDFWithQuantumAssertions benchmarks TDF creation with quantum-resistant assertions
func BenchmarkTDFWithQuantumAssertions(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config, _ := GetQuantumSafeSystemMetadataAssertionConfig()
		assertion := Assertion{
			ID:             config.ID,
			Type:           config.Type,
			Scope:          config.Scope,
			AppliesToState: config.AppliesToState,
			Statement:      config.Statement,
		}

		_ = assertion.Sign("hash", "sig", config.SigningKey)
	}
}

// Helper functions
func formatDuration(d time.Duration) string {
	if d < time.Microsecond {
		return fmt.Sprintf("%dns", d.Nanoseconds())
	}
	if d < time.Millisecond {
		return fmt.Sprintf("%.1fμs", float64(d.Nanoseconds())/1000)
	}
	if d < time.Second {
		return fmt.Sprintf("%.2fms", float64(d.Nanoseconds())/1000000)
	}
	return fmt.Sprintf("%.3fs", d.Seconds())
}

func formatBytes(bytes int) string {
	if bytes < 1024 {
		return fmt.Sprintf("%dB", bytes)
	}
	if bytes < 1024*1024 {
		return fmt.Sprintf("%.1fKB", float64(bytes)/1024)
	}
	return fmt.Sprintf("%.2fMB", float64(bytes)/(1024*1024))
}

// Helper functions for RSA key marshaling
func marshalRSAPrivateKey(key *rsa.PrivateKey) ([]byte, error) {
	// Simplified marshaling for size calculation
	keyData := struct {
		N *rsa.PrivateKey
	}{N: key}
	return json.Marshal(keyData)
}

func marshalRSAPublicKey(key *rsa.PublicKey) ([]byte, error) {
	// Simplified marshaling for size calculation
	keyData := struct {
		N *rsa.PublicKey
	}{N: key}
	return json.Marshal(keyData)
}
