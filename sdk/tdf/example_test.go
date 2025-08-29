package tdf_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/sdk/tdf"
)

// ExampleWriter demonstrates basic TDF creation with the experimental streaming writer.
func ExampleWriter() {
	ctx := context.Background()

	// Create a new TDF writer with default settings
	writer, err := tdf.NewWriter(ctx)
	if err != nil {
		log.Println(err)
		return
	}

	// Write segments (can be out-of-order)
	_, err = writer.WriteSegment(ctx, 0, []byte("First part of the data"))
	if err != nil {
		log.Println(err)
		return
	}

	_, err = writer.WriteSegment(ctx, 1, []byte("Second part of the data"))
	if err != nil {
		log.Println(err)
		return
	}

	// Finalize the TDF
	// This example finalizes without attributes, relying on a default KAS.
	mockKasKey := newMockKasKey("https://kas.example.com")

	fmt.Println("TDF writer created and 2 segments written.")
	_, manifest, err := writer.Finalize(ctx, tdf.WithDefaultKAS(mockKasKey))
	if err != nil {
		log.Println(err)
		return
	}

	fmt.Printf("TDF finalized with %d key access object(s).\n", len(manifest.EncryptionInformation.KeyAccessObjs))
	// Output:
	// TDF writer created and 2 segments written.
	// TDF finalized with 1 key access object(s).
}

// ExampleWriter_withAttributes demonstrates TDF creation with attribute-based access control.
func ExampleWriter_withAttributes() {
	ctx := context.Background()

	// Create writer with custom integrity algorithm
	writer, err := tdf.NewWriter(ctx, tdf.WithIntegrityAlgorithm(tdf.GMAC))
	if err != nil {
		log.Println(err)
		return
	}

	// Write sensitive data
	sensitiveData := []byte("Confidential business information")
	_, err = writer.WriteSegment(ctx, 0, sensitiveData)
	if err != nil {
		log.Println(err)
		return
	}

	// Create a mock KAS key to embed in the attributes.
	mockKasKey := newMockKasKey("https://kas.example.com")

	// Define access control attributes
	attributes := []*policy.Value{
		{
			Attribute: &policy.Attribute{
				Namespace: &policy.Namespace{
					Name: "company.com",
				},
				Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
			},
			Fqn: "https://company.com/attr/classification/value/confidential",
			// In real usage, this would be populated by the policy service.
			// For this example, we embed the key directly.
			KasKeys: []*policy.SimpleKasKey{mockKasKey},
		},
		{
			Attribute: &policy.Attribute{
				Namespace: &policy.Namespace{
					Name: "company.com",
				},
				Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			},
			Fqn: "https://company.com/attr/department/value/finance",
			// Multiple attributes can share the same KAS.
			KasKeys: []*policy.SimpleKasKey{mockKasKey},
		},
	}

	fmt.Printf("TDF with %d attributes configured.\n", len(attributes))
	_, manifest, err := writer.Finalize(ctx,
		tdf.WithAttributeValues(attributes),
		tdf.WithPayloadMimeType("text/plain"),
		tdf.WithEncryptedMetadata("Document ID: FIN-2024-001"),
	)
	if err != nil {
		log.Println(err)
	}

	fmt.Printf("TDF finalized with %d key access object(s) for %d attribute(s).\n", len(manifest.EncryptionInformation.KeyAccessObjs), len(attributes))
	// Output:
	// TDF with 2 attributes configured.
	// TDF finalized with 1 key access object(s) for 2 attribute(s).
}

// ExampleWriter_withAssertions demonstrates TDF creation with cryptographic assertions.
func ExampleWriter_withAssertions() {
	ctx := context.Background()

	writer, err := tdf.NewWriter(ctx)
	if err != nil {
		log.Println(err)
		return
	}

	// Write data segment
	data := []byte("Data with retention requirements")
	_, err = writer.WriteSegment(ctx, 0, data)
	if err != nil {
		log.Println(err)
		return
	}

	// Create a handling assertion for data retention
	retentionAssertion := tdf.AssertionConfig{
		ID:             "retention-policy",
		Type:           tdf.HandlingAssertion,
		Scope:          tdf.PayloadScope,
		AppliesToState: tdf.Unencrypted,
		Statement: tdf.Statement{
			Format: "json",
			Schema: "retention-policy-v1",
			Value:  `{"retain_days": 90, "auto_delete": true, "archive_required": false}`,
		},
	}

	// Create a metadata assertion
	metadataAssertion := tdf.AssertionConfig{
		ID:             "audit-info",
		Type:           tdf.BaseAssertion,
		Scope:          tdf.TrustedDataObjScope,
		AppliesToState: tdf.Encrypted,
		Statement: tdf.Statement{
			Format: "json",
			Schema: "audit-v1",
			Value:  `{"created_by": "system", "purpose": "compliance_report"}`,
		},
	}

	// Finalize with assertions
	mockKasKey := newMockKasKey("https://kas.example.com")

	fmt.Printf("TDF configured with %d assertions.\n", 2)
	_, manifest, err := writer.Finalize(ctx,
		tdf.WithAssertions(retentionAssertion, metadataAssertion),
		tdf.WithPayloadMimeType("application/json"),
		tdf.WithDefaultKAS(mockKasKey),
	)
	if err != nil {
		log.Println(err)
	}

	fmt.Printf("TDF finalized with %d assertion(s).\n", len(manifest.Assertions))
	// Output:
	// TDF configured with 2 assertions.
	// TDF finalized with 2 assertion(s).
}

// ExampleWriter_outOfOrder demonstrates out-of-order segment writing for streaming scenarios.
func ExampleWriter_outOfOrder() {
	ctx := context.Background()

	writer, err := tdf.NewWriter(ctx)
	if err != nil {
		log.Println(err)
		return
	}

	// Simulate segments arriving out-of-order (e.g., from parallel processing)
	segments := map[int][]byte{
		0: []byte("Beginning of file"),
		1: []byte("Middle section with important data"),
		2: []byte("End of file"),
	}

	// Write segments as they arrive (out-of-order)
	writeOrder := []int{2, 0, 1} // End, beginning, middle

	for _, index := range writeOrder {
		data := segments[index]
		_, err := writer.WriteSegment(ctx, index, data)
		if err != nil {
			log.Println(err)
			return
		}
		fmt.Printf("Wrote segment %d\n", index)
	}

	// Finalize - segments will be properly ordered in the final TDF
	mockKasKey := newMockKasKey("https://kas.example.com")

	fmt.Println("All out-of-order segments written.")
	_, manifest, err := writer.Finalize(ctx,
		tdf.WithPayloadMimeType("text/plain"),
		tdf.WithDefaultKAS(mockKasKey),
	)
	if err != nil {
		log.Println(err)
	}

	fmt.Printf("Finalized TDF with %d segment(s).\n", len(manifest.EncryptionInformation.IntegrityInformation.Segments))
	// Output:
	// Wrote segment 2
	// Wrote segment 0
	// Wrote segment 1
	// All out-of-order segments written.
	// Finalized TDF with 3 segment(s).
}

// ExampleWriter_largeFile demonstrates efficient handling of large files through segmentation.
func ExampleWriter_largeFile() {
	ctx := context.Background()

	// Configure for large file processing
	writer, err := tdf.NewWriter(ctx,
		tdf.WithSegmentIntegrityAlgorithm(tdf.GMAC), // Faster for many segments
	)
	if err != nil {
		log.Println(err)
		return
	}

	// Simulate processing a large file in 1MB segments
	totalSegments := 2         // Keep it small for an example
	segmentSize := 1024 * 1024 // 1MB segments

	for i := 0; i < totalSegments; i++ {
		// In practice, this data would come from file reading, network, etc.
		segmentData := make([]byte, segmentSize)

		_, err := writer.WriteSegment(ctx, i, segmentData)
		if err != nil {
			log.Println(err)
			return
		}

		fmt.Printf("Processed segment %d: %d bytes\n", i, len(segmentData))
	}

	// Finalize large file
	mockKasKey := newMockKasKey("https://kas.example.com")

	fmt.Printf("All %d segments processed.\n", totalSegments)
	_, manifest, err := writer.Finalize(ctx,
		tdf.WithPayloadMimeType("application/octet-stream"),
		tdf.WithDefaultKAS(mockKasKey),
	)
	if err != nil {
		log.Println(err)
	}

	fmt.Printf("Finalized large file with %d segment(s).\n", len(manifest.EncryptionInformation.IntegrityInformation.Segments))
	// Output:
	// Processed segment 0: 1048576 bytes
	// Processed segment 1: 1048576 bytes
	// All 2 segments processed.
	// Finalized large file with 2 segment(s).
}

// newMockKasKey generates a new RSA key pair and returns a SimpleKasKey
// containing the public key, for use in tests without a real KAS.
func newMockKasKey(kasURL string) *policy.SimpleKasKey { //nolint: unparam // kasURL could change in the future
	// Generate a new key pair for each test run.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key: %v", err)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Fatalf("Failed to marshal public key: %v", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return &policy.SimpleKasKey{
		KasUri: kasURL,
		PublicKey: &policy.SimpleKasPublicKey{
			Algorithm: policy.Algorithm_ALGORITHM_RSA_2048,
			Kid:       "test-kid",
			Pem:       string(publicKeyPEM),
		},
	}
}
