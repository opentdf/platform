// Package tdf provides experimental streaming TDF (Trusted Data Format) creation capabilities.
//
// # Experimental Status
//
// This package is EXPERIMENTAL and its API is subject to change in future releases.
// It is designed for advanced use cases requiring fine-grained control over TDF creation
// with streaming support for large datasets.
//
// For most use cases, prefer the stable SDK-level TDF creation APIs.
//
// # Overview
//
// The tdf package enables streaming creation of TDF files with support for:
//
//   - Variable-length segments that can arrive out-of-order
//   - Cryptographic assertions and integrity verification
//   - Custom attribute-based access controls
//   - Memory-efficient processing of large datasets
//   - ZIP archive generation with proper central directory structures
//
// # Basic Usage
//
//	ctx := context.Background()
//
//	// Create a new TDF writer
//	writer, err := tdf.NewWriter(ctx)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer writer.Close()
//
//	// Write data segments (can be out-of-order)
//	data1 := []byte("First segment")
//	_, err = writer.WriteSegment(ctx, 0, data1)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	data2 := []byte("Second segment")
//	_, err = writer.WriteSegment(ctx, 1, data2)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Finalize with attributes and options
//	finalBytes, manifest, err := writer.Finalize(ctx,
//		WithAttributeValues(attributes),
//		WithPayloadMimeType("text/plain"),
//		WithEncryptedMetadata("sensitive metadata"),
//	)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// # Advanced Features
//
// The package supports advanced TDF features including:
//
//   - Custom cryptographic assertions with JWT-based integrity
//   - Encrypted metadata storage within key access objects
//   - Multiple integrity algorithm support (HS256, GMAC)
//   - ZIP64 format support for large files
//   - Memory-optimized segment processing
//
// # Architecture
//
// The TDF writer uses a two-layer architecture:
//
//  1. TDF Layer (tdf.Writer): Handles encryption, assertions, and TDF protocol logic
//  2. Archive Layer (internal/archive): Manages ZIP file structure and segment assembly
//
// This separation enables independent optimization of cryptographic operations
// and file format handling.
//
// # Thread Safety
//
// Writers are safe for concurrent use with proper external synchronization.
// Individual WriteSegment calls must be serialized, but multiple writers
// can operate independently.
//
// # Performance Characteristics
//
// The implementation is optimized for:
//
//   - Linear time complexity O(n) for n segments
//   - Memory usage proportional to buffered out-of-order segments
//   - Efficient contiguous segment processing
//   - Minimal allocation patterns for high-throughput scenarios
//
// Current benchmarks (100 segments, 1KB each):
//   - Sequential: ~240μs/op, ~530KB memory/op
//   - Out-of-order: Similar performance due to contiguous processing optimization
//
// # Compatibility
//
// TDF files created by this package are compatible with:
//
//   - OpenTDF SDK readers (LoadTDF)
//   - OpenTDF platform services
//   - Standard ZIP tools (for archive structure inspection)
//   - TDF specification version 4.3.0
//
// # Error Handling
//
// The package uses structured error reporting with operation context:
//
//   - ErrAlreadyFinalized: Writer has been finalized
//   - ErrInvalidSegmentIndex: Invalid segment index provided
//   - ErrSegmentAlreadyWritten: Duplicate segment index
//
// All errors include sufficient context for debugging and recovery.
package tdf
