// Package tdf provides streaming TDF (Trusted Data Format) creation capabilities.
//
// Deprecated: this package has graduated into the sdk package itself. Use
// [github.com/opentdf/platform/sdk.SDK.NewChunkedWriter], or the package-level
// [github.com/opentdf/platform/sdk.NewChunkedWriter] when there is no platform
// connection to resolve key access against. This package now forwards to that
// implementation and will be removed in a future release.
//
// # Migration
//
// Writer options:
//
//	tdf.NewWriter(ctx, opts...)          -> sdk.NewChunkedWriter(ctx, opts...)
//	                                        client.NewChunkedWriter(ctx, opts...)
//	tdf.WithInitialAttributes(vs)        -> sdk.WithChunkedInitialAttributes(vs)
//	tdf.WithDefaultKASForWriter(k)       -> sdk.WithChunkedDefaultKAS(k)
//	tdf.WithTargetMode(m)                -> sdk.WithChunkedTargetMode(m)
//
// WithIntegrityAlgorithm and WithSegmentIntegrityAlgorithm have no
// counterpart: the stable writer always signs the root with HS256 and hashes
// segments with GMAC, which is the only combination either option accepted.
//
// Finalize options:
//
//	tdf.WithAssertions(as)               -> sdk.WithChunkedAssertions(as)
//	tdf.WithAttributeValues(vs)          -> sdk.WithChunkedAttributes(vs)
//	tdf.WithDefaultKAS(k)                -> sdk.WithChunkedDefaultKASForFinalize(k)
//	tdf.WithEncryptedMetadata(m)         -> sdk.WithChunkedEncryptedMetadata(m)
//	tdf.WithExcludeVersionFromManifest() -> sdk.WithChunkedExcludeVersion()
//	tdf.WithPayloadMimeType(m)           -> sdk.WithChunkedMimeType(m)
//	tdf.WithSegments(ix)                 -> sdk.WithChunkedSegments(ix)
//
// The manifest and assertion types this package exports are aliases of the sdk
// types, so values move across the boundary without conversion.
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
//	// Write data segments (can be out-of-order). Keep every SegmentResult:
//	// its TDFData carries the bytes that make up the payload.
//	data1 := []byte("First segment")
//	seg0, err := writer.WriteSegment(ctx, 0, data1)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	data2 := []byte("Second segment")
//	seg1, err := writer.WriteSegment(ctx, 1, data2)
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
//	// Assemble the TDF: each segment's TDFData in ascending index order,
//	// then result.Data, which holds only the archive's closing bytes.
//	var tdfFile bytes.Buffer
//	for _, seg := range []*tdf.SegmentResult{seg0, seg1} {
//		if _, err := io.Copy(&tdfFile, seg.TDFData); err != nil {
//			log.Fatal(err)
//		}
//	}
//	tdfFile.Write(result.Data)
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
// Dropping a segment from the manifest does not shrink the archive: every
// segment that was actually written — including ones WithSegments excludes
// from the manifest — must still be appended when assembling the final
// file, in ascending index order. Skipping a dropped segment's bytes
// produces an archive whose central directory offsets overshoot, because
// the payload's recorded size and CRC already account for it.
//
//	// Write segments 0 and 1
//	seg0, _ := writer.WriteSegment(ctx, 0, []byte("part-0"))
//	seg1, _ := writer.WriteSegment(ctx, 1, []byte("part-1"))
//
//	// Finalize describing only segment 0 in the manifest -- both segments'
//	// TDFData must still be assembled, in ascending index order.
//	result, err := writer.Finalize(ctx,
//		tdf.WithSegments([]int{0}),
//	)
//	if err != nil {
//		log.Fatal(err)
//	}
//	var tdfFile bytes.Buffer
//	io.Copy(&tdfFile, seg0.TDFData)
//	io.Copy(&tdfFile, seg1.TDFData)
//	tdfFile.Write(result.Data)
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
//   - Integrity: GMAC segment hashes under an HS256 root signature
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
// A successful Finalize is terminal and takes an exclusive lock, so it must
// not overlap with any in-flight WriteSegment call. A refusal before the
// archive is touched, such as ErrChunkedWriteInFlight, leaves the writer
// usable; resolve the cause and retry. An archive failure after mutation or
// a close failure leaves the writer unusable.
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
// # Relationship to the Stable SDK
//
// The manifest and assertion types this package exports are aliases onto
// [github.com/opentdf/platform/sdk], which owns the definitions. A manifest
// produced here is therefore the same Go type the stable SDK produces and
// needs no conversion at the boundary. The aliases exist so existing importers
// compile unchanged; prefer the sdk-scoped names in new code.
//
// Policy, PolicyBody, and PolicyAttribute are the exception: they remain
// local. See their declarations in manifest.go for why.
//
// # Error Handling
//
// The package uses structured error reporting with operation context:
//
//   - ErrAlreadyFinalized: Writer has been finalized
//   - ErrInvalidSegmentIndex: Invalid segment index provided
//   - ErrSegmentAlreadyWritten: Duplicate segment index
//   - ErrMissingSegmentZero: Finalize called without segment 0
//   - ErrUnsupportedRootIntegrityAlgorithm, ErrUnsupportedSegmentIntegrityAlgorithm:
//     NewWriter was asked for an algorithm other than the default
//
// All of the above are aliases of the stable SDK's error values, so
// errors.Is matches whether a caller compares against the experimental or
// the sdk-scoped name. All errors include sufficient context for debugging
// and recovery.
package tdf
