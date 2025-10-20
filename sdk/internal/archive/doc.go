// Package archive provides a minimal ZIP archive builder used by the SDK.
//
// It focuses on streaming-safe payload assembly with a single stored entry
// (0.payload) written as out-of-order segments, followed by a manifest file
// (0.manifest.json). The writer does not retain payload bytes; callers receive
// per-segment bytes to upload and the package reconstructs the final ZIP
// structure during Finalize.
//
// Key features
//   - Segment-based writing: WriteSegment(index, data) supports out-of-order
//     arrival while maintaining deterministic output (segment 0 includes the
//     local file header; others are raw data). The payload entry uses a data
//     descriptor, so sizes/CRC are resolved at Finalize.
//   - CRC32 combine: The payload CRC is computed via CRC32-Combine over
//     per-segment CRCs, avoiding buffering of the entire payload.
//   - ZIP64 modes: Auto/Always/Never to control when ZIP64 structures are
//     emitted. Small archives use ZIP32 unless forced by configuration.
//
// Reader utilities are provided to parse archives created by this package.
package archive
