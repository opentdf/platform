package tdf_test

import (
	"context"
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
		log.Fatal(err)
	}

	// Write segments (can be out-of-order)
	segment0, err := writer.WriteSegment(ctx, 0, []byte("First part of the data"))
	if err != nil {
		log.Fatal(err)
	}

	segment1, err := writer.WriteSegment(ctx, 1, []byte("Second part of the data"))
	if err != nil {
		log.Fatal(err)
	}

	// Finalize the TDF
	finalBytes, manifest, err := writer.Finalize(ctx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Segment 0: %d bytes\n", len(segment0))
	fmt.Printf("Segment 1: %d bytes\n", len(segment1))
	fmt.Printf("Complete TDF: %d bytes\n", len(finalBytes))
	fmt.Printf("TDF Version: %s\n", manifest.TDFVersion)
}

// ExampleWriter_withAttributes demonstrates TDF creation with attribute-based access control.
func ExampleWriter_withAttributes() {
	ctx := context.Background()

	// Create writer with custom integrity algorithm
	writer, err := tdf.NewWriter(ctx, tdf.WithIntegrityAlgorithm(tdf.GMAC))
	if err != nil {
		log.Fatal(err)
	}

	// Write sensitive data
	sensitiveData := []byte("Confidential business information")
	_, err = writer.WriteSegment(ctx, 0, sensitiveData)
	if err != nil {
		log.Fatal(err)
	}

	// Define access control attributes
	attributes := []*policy.Value{
		{
			Fqn: "https://company.com/attr/classification/value/confidential",
			// In real usage, include proper KAS configuration
		},
		{
			Fqn: "https://company.com/attr/department/value/finance",
		},
	}

	// Finalize with attributes and metadata
	finalBytes, manifest, err := writer.Finalize(ctx,
		tdf.WithAttributeValues(attributes),
		tdf.WithPayloadMimeType("text/plain"),
		tdf.WithEncryptedMetadata("Document ID: FIN-2024-001"),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Protected TDF: %d bytes\n", len(finalBytes))
	fmt.Printf("Attributes: %d\n", len(manifest.EncryptionInformation.KeyAccessObjs))
}

// ExampleWriter_withAssertions demonstrates TDF creation with cryptographic assertions.
func ExampleWriter_withAssertions() {
	ctx := context.Background()

	writer, err := tdf.NewWriter(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// Write data segment
	data := []byte("Data with retention requirements")
	_, err = writer.WriteSegment(ctx, 0, data)
	if err != nil {
		log.Fatal(err)
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
	finalBytes, manifest, err := writer.Finalize(ctx,
		tdf.WithAssertions(retentionAssertion, metadataAssertion),
		tdf.WithPayloadMimeType("application/json"),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("TDF with assertions: %d bytes\n", len(finalBytes))
	fmt.Printf("Assertions included: %d\n", len(manifest.Assertions))
}

// ExampleWriter_outOfOrder demonstrates out-of-order segment writing for streaming scenarios.
func ExampleWriter_outOfOrder() {
	ctx := context.Background()

	writer, err := tdf.NewWriter(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// Simulate segments arriving out-of-order (e.g., from parallel processing)
	segments := map[int][]byte{
		0: []byte("Beginning of file"),
		1: []byte("Middle section with important data"),  
		2: []byte("End of file"),
	}

	// Write segments as they arrive (out-of-order)
	writeOrder := []int{2, 0, 1} // End, beginning, middle

	var segmentBytes [][]byte
	for _, index := range writeOrder {
		data := segments[index]
		bytes, err := writer.WriteSegment(ctx, index, data)
		if err != nil {
			log.Fatal(err)
		}
		segmentBytes = append(segmentBytes, bytes)
		fmt.Printf("Wrote segment %d: %d bytes\n", index, len(bytes))
	}

	// Finalize - segments will be properly ordered in the final TDF
	finalBytes, _, err := writer.Finalize(ctx,
		tdf.WithPayloadMimeType("text/plain"),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Complete ordered TDF: %d bytes\n", len(finalBytes))
}

// ExampleWriter_largeFile demonstrates efficient handling of large files through segmentation.
func ExampleWriter_largeFile() {
	ctx := context.Background()

	// Configure for large file processing
	writer, err := tdf.NewWriter(ctx,
		tdf.WithSegmentIntegrityAlgorithm(tdf.GMAC), // Faster for many segments
	)
	if err != nil {
		log.Fatal(err)
	}

	// Simulate processing a large file in 1MB segments
	totalSegments := 10
	segmentSize := 1024 * 1024 // 1MB segments

	for i := 0; i < totalSegments; i++ {
		// In practice, this data would come from file reading, network, etc.
		segmentData := make([]byte, segmentSize)
		for j := range segmentData {
			segmentData[j] = byte((i + j) % 256)
		}

		bytes, err := writer.WriteSegment(ctx, i, segmentData)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("Processed segment %d: %d → %d bytes\n", i, len(segmentData), len(bytes))
	}

	// Finalize large file
	finalBytes, manifest, err := writer.Finalize(ctx,
		tdf.WithPayloadMimeType("application/octet-stream"),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Large file TDF: %d bytes total\n", len(finalBytes))
	fmt.Printf("Segments processed: %d\n", len(manifest.EncryptionInformation.IntegrityInformation.Segments))
}