// Experimental: This package is EXPERIMENTAL and may change or be removed at any time
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
//	result, err := writer.Finalize(ctx,
//		tdf.WithAttributeValues(attributes),
//		tdf.WithPayloadMimeType("text/plain"),
//		tdf.WithEncryptedMetadata("sensitive metadata"),
//	)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// result.Data holds the archive's closing bytes; append it after each
//	// segment's SegmentResult.TDFData, in ascending segment index order.
//
// # Initial Attributes and Default KAS at Writer Creation
//
// Callers can provide initial attributes and a default KAS when constructing
// the writer. If Finalize options omit these, the writer-level values are used.
// Finalize-specified values always take precedence.
//
//	attrs := []*policy.Value{ /* ... */ }
//	kasKey := &policy.SimpleKasKey{ /* ... */ }
//	writer, err := tdf.NewWriter(ctx,
//		tdf.WithInitialAttributes(attrs),
//		tdf.WithDefaultKASForWriter(kasKey),
//	)
//	if err != nil {
//		log.Fatal(err)
//	}
//	// Later, Finalize without attributes/KAS uses the initial values.
//
// # Segment Overrides at Finalize
//
// By default Finalize describes every written segment, ordered by index.
// WithSegments narrows that to a chosen subset.
//
// Indices need not be contiguous — a caller mapping S3 multipart uploads
// onto segments might write 0, 1, 5000, 5001 — but the list must name
// written segments in ascending index order and may drop only from the end.
// That is the order a reader concatenates the payload in, so dropping a
// segment from the middle would shift every later segment's offset and
// produce an unreadable TDF.
//
//	// Write segments 0 and 1
//	_, _ = writer.WriteSegment(ctx, 0, []byte("part-0"))
//	_, _ = writer.WriteSegment(ctx, 1, []byte("part-1"))
//
//	// Finalize keeping only segment 0
//	result, err := writer.Finalize(ctx,
//		tdf.WithSegments([]int{0}),
//	)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// Keeping every written segment is the default, so passing the full list is
// optional.
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
// The TDF writer uses a three-layer architecture:
//
//  1. Adapter Layer (tdf.Writer): Maps this package's options onto the stable
//     writer and supplies multi-KAS ABAC key splitting
//  2. TDF Layer (sdk.ChunkedWriter): Handles encryption, assertions, and TDF
//     protocol logic
//  3. Archive Layer (internal/zipstream): Manages ZIP file structure and
//     segment assembly
//
// This separation enables independent optimization of cryptographic operations
// and file format handling. Callers who need only a single KAS can skip layer
// one and use [github.com/opentdf/platform/sdk.NewChunkedWriter] directly.
//
// # Thread Safety
//
// A Writer is safe for concurrent use. [Writer.WriteSegment] may be called
// from several goroutines at once so long as each targets a distinct segment
// index; two concurrent calls for the same index are not allowed, and one of
// them will fail rather than corrupt the archive.
//
// Finalize is terminal and takes an exclusive lock, so it must not overlap
// with any in-flight WriteSegment call.
//
// # Performance Characteristics
//
// The implementation is optimized for:
//
//   - Linear time complexity O(n) for n segments
//   - Memory usage independent of write order (no payload buffering)
//   - CRC aggregation via combine over per-segment CRCs
//   - Minimal allocation patterns for high-throughput scenarios
//
// Current benchmarks (100 segments, 1KB each):
//   - Sequential: ~240μs/op, ~530KB memory/op
//   - Out-of-order: Similar performance due to combine-based CRC approach
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
