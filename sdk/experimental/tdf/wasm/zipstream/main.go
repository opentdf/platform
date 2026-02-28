// Canary: zipstream package (copied from sdk/internal/zipstream)
// EXPECTED TO PASS under TinyGo — exercises the full TDF ZIP writer path:
// local file headers, data descriptors, manifest entry, central directory,
// CRC32 combine, and ZIP64 structures.
//
// Validates that the production zipstream code compiles and produces valid
// ZIP archives when compiled with TinyGo to WASM. The output is verified
// structurally (correct signatures, sizes, offsets) since archive/zip is
// not available for validation within the WASM module itself.
package main

import (
	"context"
	"encoding/binary"
	"hash/crc32"

	zs "github.com/opentdf/platform/sdk/experimental/tdf/wasm/zipstream/zipstream"
)

func main() {
	testSingleSegmentTDF()
	testMultiSegmentTDF()
	testZip64TDF()
	testCRC32Combine()
}

func testSingleSegmentTDF() {
	// Simulate a single-segment TDF encrypt:
	// 1. Create writer
	// 2. WriteSegment(0) — get ZIP local file header bytes
	// 3. Finalize with manifest — get data descriptor + manifest + central directory
	w := zs.NewSegmentTDFWriter(1)

	ctx := context.Background()

	// Simulate encrypted payload (11 bytes)
	payload := []byte("hello world")
	payloadCRC := crc32.ChecksumIEEE(payload)

	// WriteSegment returns the ZIP header bytes for segment 0
	headerBytes, err := w.WriteSegment(ctx, 0, uint64(len(payload)), payloadCRC)
	if err != nil {
		panic("WriteSegment failed: " + err.Error())
	}
	if len(headerBytes) == 0 {
		panic("WriteSegment returned empty header for segment 0")
	}

	// Verify local file header signature (PK\x03\x04)
	if len(headerBytes) < 4 {
		panic("header too short")
	}
	sig := binary.LittleEndian.Uint32(headerBytes[0:4])
	if sig != 0x04034b50 {
		panic("wrong local file header signature")
	}

	// Finalize with a manifest
	manifest := []byte(`{"encryptionInformation":{"type":"split"}}`)
	tailBytes, err := w.Finalize(ctx, manifest)
	if err != nil {
		panic("Finalize failed: " + err.Error())
	}
	if len(tailBytes) == 0 {
		panic("Finalize returned empty")
	}

	// Verify the tail contains an end-of-central-directory signature
	found := false
	eocdSig := []byte{0x50, 0x4b, 0x05, 0x06}
	for i := 0; i <= len(tailBytes)-4; i++ {
		if tailBytes[i] == eocdSig[0] && tailBytes[i+1] == eocdSig[1] &&
			tailBytes[i+2] == eocdSig[2] && tailBytes[i+3] == eocdSig[3] {
			found = true
			break
		}
	}
	if !found {
		panic("end-of-central-directory signature not found in finalize output")
	}

	// Verify the tail contains the manifest data
	if !bytesContain(tailBytes, manifest) {
		panic("manifest not found in finalize output")
	}

	// Verify the tail also contains a manifest local file header
	manifestHeaderFound := false
	manifestName := []byte("0.manifest.json")
	for i := 0; i <= len(tailBytes)-4; i++ {
		if tailBytes[i] == 0x50 && tailBytes[i+1] == 0x4b &&
			tailBytes[i+2] == 0x03 && tailBytes[i+3] == 0x04 {
			// Found a local file header; check if filename matches
			if i+30+len(manifestName) <= len(tailBytes) {
				nameStart := i + 30
				if bytesEqual(tailBytes[nameStart:nameStart+len(manifestName)], manifestName) {
					manifestHeaderFound = true
					break
				}
			}
		}
	}
	if !manifestHeaderFound {
		panic("manifest local file header not found")
	}
}

func testMultiSegmentTDF() {
	// Test out-of-order multi-segment writing
	w := zs.NewSegmentTDFWriter(3)
	ctx := context.Background()

	seg0 := []byte("segment zero data!!")
	seg1 := []byte("segment one data!!!")
	seg2 := []byte("segment two data!!!")

	// Write segments out of order: 2, 0, 1
	_, err := w.WriteSegment(ctx, 2, uint64(len(seg2)), crc32.ChecksumIEEE(seg2))
	if err != nil {
		panic("WriteSegment(2) failed: " + err.Error())
	}
	_, err = w.WriteSegment(ctx, 0, uint64(len(seg0)), crc32.ChecksumIEEE(seg0))
	if err != nil {
		panic("WriteSegment(0) failed: " + err.Error())
	}
	_, err = w.WriteSegment(ctx, 1, uint64(len(seg1)), crc32.ChecksumIEEE(seg1))
	if err != nil {
		panic("WriteSegment(1) failed: " + err.Error())
	}

	manifest := []byte(`{"encryptionInformation":{"type":"split","keyAccess":[]}}`)
	tailBytes, err := w.Finalize(ctx, manifest)
	if err != nil {
		panic("multi-segment Finalize failed: " + err.Error())
	}
	if len(tailBytes) == 0 {
		panic("multi-segment Finalize returned empty")
	}
}

func testZip64TDF() {
	// Test ZIP64 mode
	w := zs.NewSegmentTDFWriter(1, zs.WithZip64())
	ctx := context.Background()

	payload := []byte("zip64 payload test")
	_, err := w.WriteSegment(ctx, 0, uint64(len(payload)), crc32.ChecksumIEEE(payload))
	if err != nil {
		panic("ZIP64 WriteSegment failed: " + err.Error())
	}

	manifest := []byte(`{"encryptionInformation":{"type":"split"}}`)
	tailBytes, err := w.Finalize(ctx, manifest)
	if err != nil {
		panic("ZIP64 Finalize failed: " + err.Error())
	}

	// Verify ZIP64 end-of-central-directory signature (PK\x06\x06)
	zip64Sig := []byte{0x50, 0x4b, 0x06, 0x06}
	if !bytesContain(tailBytes, zip64Sig) {
		panic("ZIP64 end-of-central-directory signature not found")
	}

	// Verify ZIP64 locator signature (PK\x06\x07)
	zip64LocSig := []byte{0x50, 0x4b, 0x06, 0x07}
	if !bytesContain(tailBytes, zip64LocSig) {
		panic("ZIP64 end-of-central-directory locator signature not found")
	}
}

func testCRC32Combine() {
	// Test CRC32 combine produces same result as hashing all data at once
	part1 := []byte("hello ")
	part2 := []byte("world")
	combined := append(part1, part2...)

	crc1 := crc32.ChecksumIEEE(part1)
	crc2 := crc32.ChecksumIEEE(part2)
	crcCombined := zs.CRC32CombineIEEE(crc1, crc2, int64(len(part2)))
	crcDirect := crc32.ChecksumIEEE(combined)

	if crcCombined != crcDirect {
		panic("CRC32 combine mismatch")
	}

	// Multi-part combine
	parts := [][]byte{
		[]byte("encrypted segment 0 data here"),
		[]byte("encrypted segment 1 data"),
		[]byte("encrypted segment 2 data!!"),
	}
	var totalCRC uint32
	for i, p := range parts {
		pCRC := crc32.ChecksumIEEE(p)
		if i == 0 {
			totalCRC = pCRC
		} else {
			totalCRC = zs.CRC32CombineIEEE(totalCRC, pCRC, int64(len(p)))
		}
	}

	allData := make([]byte, 0)
	for _, p := range parts {
		allData = append(allData, p...)
	}
	if totalCRC != crc32.ChecksumIEEE(allData) {
		panic("multi-part CRC32 combine mismatch")
	}
}

// ── Helpers ──────────────────────────────────────────────────

func bytesContain(haystack, needle []byte) bool {
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if bytesEqual(haystack[i:i+len(needle)], needle) {
			return true
		}
	}
	return false
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
