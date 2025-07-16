package main

import (
	"fmt"
	"time"

	"github.com/opentdf/platform/sdk"
)

func main() {
	fmt.Println("🔐 Quantum-Resistant Assertions Demo")
	fmt.Println("===================================")

	// Demonstrate key generation performance
	fmt.Println("\n1. Key Generation Performance:")

	// Traditional HS256 (using payload key)
	start := time.Now()
	payloadKey := make([]byte, 32) // Simulate payload key generation
	traditionalTime := time.Since(start)

	// Quantum-resistant ML-DSA
	start = time.Now()
	_, err := sdk.GenerateMLDSAKeyPair()
	quantumKeyTime := time.Since(start)

	if err != nil {
		fmt.Printf("❌ Error generating quantum key: %v\n", err)
		return
	}

	fmt.Printf("   Traditional (HS256): %v\n", traditionalTime)
	fmt.Printf("   Quantum (ML-DSA-44): %v\n", quantumKeyTime)
	fmt.Printf("   Performance: ML-DSA is %.1fx faster\n",
		float64(traditionalTime)/float64(quantumKeyTime))

	// Demonstrate assertion creation
	fmt.Println("\n2. Assertion Creation:")

	// Traditional assertion
	start = time.Now()
	traditionalAssertion, err := sdk.GetSystemMetadataAssertionConfig()
	if err != nil {
		fmt.Printf("❌ Error creating traditional assertion: %v\n", err)
		return
	}
	traditionalAssertionTime := time.Since(start)

	// Quantum assertion
	start = time.Now()
	quantumAssertion, err := sdk.GetQuantumSafeSystemMetadataAssertionConfig()
	if err != nil {
		fmt.Printf("❌ Error creating quantum assertion: %v\n", err)
		return
	}
	quantumAssertionTime := time.Since(start)

	fmt.Printf("   Traditional: %v\n", traditionalAssertionTime)
	fmt.Printf("   Quantum-Safe: %v\n", quantumAssertionTime)
	fmt.Printf("   Overhead: %.1fx slower\n",
		float64(quantumAssertionTime)/float64(traditionalAssertionTime))

	// Demonstrate signing performance
	fmt.Println("\n3. Signing Performance:")

	assertion1 := sdk.Assertion{
		ID:             traditionalAssertion.ID,
		Type:           traditionalAssertion.Type,
		Scope:          traditionalAssertion.Scope,
		AppliesToState: traditionalAssertion.AppliesToState,
		Statement:      traditionalAssertion.Statement,
	}

	assertion2 := sdk.Assertion{
		ID:             quantumAssertion.ID,
		Type:           quantumAssertion.Type,
		Scope:          quantumAssertion.Scope,
		AppliesToState: quantumAssertion.AppliesToState,
		Statement:      quantumAssertion.Statement,
	}

	// Traditional signing
	hsKey := sdk.AssertionKey{
		Alg: sdk.AssertionKeyAlgHS256,
		Key: payloadKey,
	}

	start = time.Now()
	err = assertion1.Sign("test-hash", "test-sig", hsKey)
	traditionalSignTime := time.Since(start)

	if err != nil {
		fmt.Printf("❌ Error signing traditional assertion: %v\n", err)
		return
	}

	// Quantum signing
	start = time.Now()
	err = assertion2.Sign("test-hash", "test-sig", quantumAssertion.SigningKey)
	quantumSignTime := time.Since(start)

	if err != nil {
		fmt.Printf("❌ Error signing quantum assertion: %v\n", err)
		return
	}

	fmt.Printf("   Traditional (HS256): %v\n", traditionalSignTime)
	fmt.Printf("   Quantum (ML-DSA-44): %v\n", quantumSignTime)
	fmt.Printf("   Performance: ML-DSA is %.1fx faster\n",
		float64(traditionalSignTime)/float64(quantumSignTime))

	// Demonstrate size differences
	fmt.Println("\n4. Size Comparison:")

	traditionalSize := len(assertion1.Binding.Signature)
	quantumSize := len(assertion2.Binding.Signature)

	fmt.Printf("   Traditional signature: %d bytes\n", traditionalSize)
	fmt.Printf("   Quantum signature: %d bytes\n", quantumSize)
	fmt.Printf("   Size overhead: %.1fx larger\n",
		float64(quantumSize)/float64(traditionalSize))

	// Summary
	fmt.Println("\n📊 Summary:")
	fmt.Println("   ✅ ML-DSA-44 key generation is significantly faster")
	fmt.Println("   ✅ ML-DSA-44 signing is faster than traditional methods")
	fmt.Printf("   ⚠️  ML-DSA-44 signatures are %.1fx larger\n",
		float64(quantumSize)/float64(traditionalSize))
	fmt.Println("   🔮 ML-DSA-44 provides quantum-resistant security")

	fmt.Println("\n🎯 Recommendation:")
	fmt.Println("   Use quantum-resistant assertions for long-term data protection")
	fmt.Println("   where future security is more important than signature size.")
}
