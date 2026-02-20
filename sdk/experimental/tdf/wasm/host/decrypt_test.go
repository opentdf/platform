package host

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/sdk/experimental/tdf"
)

// ── Decrypt fixture helpers ─────────────────────────────────────────

// callDecryptRaw invokes tdf_decrypt and returns the raw result length.
// Does NOT fail on error — caller decides how to handle resultLen == 0.
func (f *encryptFixture) callDecryptRaw(
	t *testing.T,
	tdfBytes, dek []byte,
	outCapacity uint32,
) (resultLen uint32, outPtr uint32) {
	t.Helper()

	tdfPtr := f.writeToWASM(t, tdfBytes)
	dekPtr := f.writeToWASM(t, dek)
	outPtr = f.wasmMalloc(t, outCapacity)

	results, err := f.mod.ExportedFunction("tdf_decrypt").Call(f.ctx,
		uint64(tdfPtr), uint64(len(tdfBytes)),
		uint64(dekPtr), uint64(len(dek)),
		uint64(outPtr), uint64(outCapacity),
	)
	if err != nil {
		t.Fatalf("tdf_decrypt call failed: %v", err)
	}
	return uint32(results[0]), outPtr
}

// mustDecrypt calls tdf_decrypt and fails the test on error.
// A 0-length result is valid (empty plaintext); errors are distinguished
// by checking get_error.
func (f *encryptFixture) mustDecrypt(t *testing.T, tdfBytes, dek []byte) []byte {
	t.Helper()
	resultLen, outPtr := f.callDecryptRaw(t, tdfBytes, dek, 1024*1024)
	if resultLen == 0 {
		if errMsg := f.callGetError(t); errMsg != "" {
			t.Fatalf("tdf_decrypt returned 0 with error: %s", errMsg)
		}
		return nil
	}
	ptBytes, ok := f.mod.Memory().Read(outPtr, resultLen)
	if !ok {
		t.Fatal("read plaintext output from WASM memory")
	}
	out := make([]byte, len(ptBytes))
	copy(out, ptBytes)
	return out
}

// ── Integration tests ───────────────────────────────────────────────

func TestTDFDecryptRoundTrip(t *testing.T) {
	f := newEncryptFixture(t)
	plaintext := []byte("hello, TDF decrypt from WASM!")

	// Encrypt via WASM
	tdfBytes := f.mustEncrypt(t, "https://kas.example.com", nil, plaintext)

	// Unwrap DEK host-side
	c := parseTDF(t, tdfBytes)
	dek := unwrapDEK(t, c.Manifest, f.privPEM)

	// Decrypt via WASM
	decrypted := f.mustDecrypt(t, tdfBytes, dek)

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("round-trip mismatch:\n  got:  %q\n  want: %q", decrypted, plaintext)
	}
}

func TestTDFDecryptAllAlgorithmCombos(t *testing.T) {
	combos := []struct {
		name       string
		rootAlg    uint32
		segAlg     uint32
	}{
		{"HS256/HS256", algHS256, algHS256},
		{"HS256/GMAC", algHS256, algGMAC},
		{"GMAC/HS256", algGMAC, algHS256},
		{"GMAC/GMAC", algGMAC, algGMAC},
	}

	f := newEncryptFixture(t)
	plaintext := []byte("algorithm combo test payload")

	for _, combo := range combos {
		t.Run(combo.name, func(t *testing.T) {
			tdfBytes := f.mustEncryptWithAlgs(t, "https://kas.example.com", nil, plaintext, combo.rootAlg, combo.segAlg)
			c := parseTDF(t, tdfBytes)
			dek := unwrapDEK(t, c.Manifest, f.privPEM)

			decrypted := f.mustDecrypt(t, tdfBytes, dek)
			if !bytes.Equal(decrypted, plaintext) {
				t.Fatalf("round-trip mismatch:\n  got:  %q\n  want: %q", decrypted, plaintext)
			}
		})
	}
}

func TestTDFDecryptEmptyPayload(t *testing.T) {
	f := newEncryptFixture(t)

	tdfBytes := f.mustEncrypt(t, "https://kas.example.com", nil, []byte{})
	c := parseTDF(t, tdfBytes)
	dek := unwrapDEK(t, c.Manifest, f.privPEM)

	decrypted := f.mustDecrypt(t, tdfBytes, dek)
	if len(decrypted) != 0 {
		t.Fatalf("expected empty plaintext, got %d bytes: %q", len(decrypted), decrypted)
	}
}

func TestTDFDecryptIntegrityFailure(t *testing.T) {
	f := newEncryptFixture(t)
	plaintext := []byte("tamper detection test")

	tdfBytes := f.mustEncrypt(t, "https://kas.example.com", nil, plaintext)
	c := parseTDF(t, tdfBytes)
	dek := unwrapDEK(t, c.Manifest, f.privPEM)

	// Tamper with a byte in the middle of the TDF (in the payload area).
	// The payload starts after the first ZIP local file header.
	tampered := make([]byte, len(tdfBytes))
	copy(tampered, tdfBytes)
	// Find a byte in the payload area and flip it. The payload entry
	// starts early in the ZIP, so offset ~50 should be in the encrypted data.
	tampered[50] ^= 0xFF

	resultLen, _ := f.callDecryptRaw(t, tampered, dek, 1024*1024)
	if resultLen != 0 {
		t.Fatal("expected decrypt to fail on tampered TDF")
	}
	errMsg := f.callGetError(t)
	if errMsg == "" {
		t.Fatal("expected error message for tampered TDF")
	}
}

func TestTDFDecryptWrongDEK(t *testing.T) {
	f := newEncryptFixture(t)
	plaintext := []byte("wrong key test")

	tdfBytes := f.mustEncrypt(t, "https://kas.example.com", nil, plaintext)

	// Use a different key (all zeros, definitely not the real DEK)
	wrongDEK := make([]byte, 32)

	resultLen, _ := f.callDecryptRaw(t, tdfBytes, wrongDEK, 1024*1024)
	if resultLen != 0 {
		t.Fatal("expected decrypt to fail with wrong DEK")
	}
	errMsg := f.callGetError(t)
	if errMsg == "" {
		t.Fatal("expected error message for wrong DEK")
	}
}

func TestTDFDecryptInvalidZIP(t *testing.T) {
	f := newEncryptFixture(t)

	garbage := []byte("this is not a ZIP file at all")
	dek := make([]byte, 32)

	resultLen, _ := f.callDecryptRaw(t, garbage, dek, 1024*1024)
	if resultLen != 0 {
		t.Fatal("expected decrypt to fail on garbage input")
	}
	errMsg := f.callGetError(t)
	if errMsg == "" {
		t.Fatal("expected error message for invalid ZIP")
	}
}

func TestTDFDecryptBufferTooSmall(t *testing.T) {
	f := newEncryptFixture(t)
	plaintext := []byte("buffer size test with enough data to exceed tiny buffer")

	tdfBytes := f.mustEncrypt(t, "https://kas.example.com", nil, plaintext)
	c := parseTDF(t, tdfBytes)
	dek := unwrapDEK(t, c.Manifest, f.privPEM)

	// Use a buffer too small for the plaintext
	resultLen, _ := f.callDecryptRaw(t, tdfBytes, dek, 5)
	if resultLen != 0 {
		t.Fatal("expected decrypt to fail with small output buffer")
	}
	errMsg := f.callGetError(t)
	if errMsg == "" {
		t.Fatal("expected error message for buffer too small")
	}
}

// ── Multi-segment tests ─────────────────────────────────────────────

func TestTDFDecryptMultiSegmentRoundTrip(t *testing.T) {
	f := newEncryptFixture(t)
	// 100 bytes with 30-byte segments → 4 segments (30+30+30+10)
	plaintext := bytes.Repeat([]byte("abcdefghij"), 10)

	tdfBytes := f.mustEncryptMultiSeg(t, "https://kas.example.com", nil, plaintext, 30)
	c := parseTDF(t, tdfBytes)

	if len(c.Manifest.Segments) != 4 {
		t.Fatalf("expected 4 segments, got %d", len(c.Manifest.Segments))
	}

	dek := unwrapDEK(t, c.Manifest, f.privPEM)
	decrypted := f.mustDecrypt(t, tdfBytes, dek)

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("multi-segment round-trip mismatch:\n  got len:  %d\n  want len: %d", len(decrypted), len(plaintext))
	}
}

func TestTDFDecryptMultiSegmentAlgorithmCombos(t *testing.T) {
	combos := []struct {
		name    string
		rootAlg uint32
		segAlg  uint32
	}{
		{"HS256/HS256", algHS256, algHS256},
		{"HS256/GMAC", algHS256, algGMAC},
		{"GMAC/HS256", algGMAC, algHS256},
		{"GMAC/GMAC", algGMAC, algGMAC},
	}

	f := newEncryptFixture(t)
	plaintext := bytes.Repeat([]byte("X"), 100)

	for _, combo := range combos {
		t.Run(combo.name, func(t *testing.T) {
			resultLen, outPtr := f.callEncryptRaw(t, f.pubPEM, "https://kas.example.com", nil,
				plaintext, 2*1024*1024, combo.rootAlg, combo.segAlg, 25)
			if resultLen == 0 {
				t.Fatalf("tdf_encrypt returned 0: %s", f.callGetError(t))
			}
			tdfBytes, ok := f.mod.Memory().Read(outPtr, resultLen)
			if !ok {
				t.Fatal("read TDF output from WASM memory")
			}
			tdfCopy := make([]byte, len(tdfBytes))
			copy(tdfCopy, tdfBytes)

			c := parseTDF(t, tdfCopy)
			if len(c.Manifest.Segments) != 4 {
				t.Fatalf("expected 4 segments, got %d", len(c.Manifest.Segments))
			}

			dek := unwrapDEK(t, c.Manifest, f.privPEM)
			decrypted := f.mustDecrypt(t, tdfCopy, dek)
			if !bytes.Equal(decrypted, plaintext) {
				t.Fatalf("round-trip mismatch: got len %d, want %d", len(decrypted), len(plaintext))
			}
		})
	}
}

func TestTDFDecryptMultiSegmentIntegrityFailure(t *testing.T) {
	f := newEncryptFixture(t)
	plaintext := bytes.Repeat([]byte("Z"), 90)

	tdfBytes := f.mustEncryptMultiSeg(t, "https://kas.example.com", nil, plaintext, 30)
	c := parseTDF(t, tdfBytes)
	dek := unwrapDEK(t, c.Manifest, f.privPEM)

	// Tamper with a byte in the second segment area.
	// Local file header is ~40 bytes, first segment is 30+28=58 bytes,
	// so offset ~100 should be in the second segment.
	tampered := make([]byte, len(tdfBytes))
	copy(tampered, tdfBytes)
	tampered[100] ^= 0xFF

	resultLen, _ := f.callDecryptRaw(t, tampered, dek, 1024*1024)
	if resultLen != 0 {
		t.Fatal("expected decrypt to fail on tampered multi-segment TDF")
	}
	errMsg := f.callGetError(t)
	if errMsg == "" {
		t.Fatal("expected error message for tampered multi-segment TDF")
	}
}

func TestTDFDecryptMultiSegmentExactDivision(t *testing.T) {
	f := newEncryptFixture(t)
	// 60 bytes with 20-byte segments → exactly 3 segments
	plaintext := bytes.Repeat([]byte("ab"), 30)

	tdfBytes := f.mustEncryptMultiSeg(t, "https://kas.example.com", nil, plaintext, 20)
	c := parseTDF(t, tdfBytes)

	if len(c.Manifest.Segments) != 3 {
		t.Fatalf("expected 3 segments, got %d", len(c.Manifest.Segments))
	}
	// All segments should be equal size
	for i, seg := range c.Manifest.Segments {
		if seg.Size != 20 {
			t.Errorf("segment %d size: got %d, want 20", i, seg.Size)
		}
	}

	dek := unwrapDEK(t, c.Manifest, f.privPEM)
	decrypted := f.mustDecrypt(t, tdfBytes, dek)
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("round-trip mismatch")
	}
}

// ── Cross-SDK tests ─────────────────────────────────────────────────
//
// These tests create TDFs using the experimental tdf.NewWriter (which
// matches the standard SDK's format) and then decrypt them via the WASM
// module's tdf_decrypt export. This validates that the two implementations
// agree on segment integrity computation, manifest structure, and ZIP layout.

// createTDFViaWriter assembles a complete TDF byte stream using the
// experimental Writer API. If segmentSize <= 0, the entire plaintext is
// written as a single segment.
func createTDFViaWriter(t *testing.T, pubPEM string, plaintext []byte, segmentSize int, writerOpts ...tdf.Option[*tdf.WriterConfig]) []byte {
	t.Helper()
	ctx := context.Background()

	writer, err := tdf.NewWriter(ctx, writerOpts...)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	var tdfBuf bytes.Buffer

	if segmentSize <= 0 || segmentSize >= len(plaintext) {
		// Single segment — copy to avoid EncryptInPlace modifying the caller's buffer.
		chunk := make([]byte, len(plaintext))
		copy(chunk, plaintext)
		seg, err := writer.WriteSegment(ctx, 0, chunk)
		if err != nil {
			t.Fatalf("WriteSegment: %v", err)
		}
		if _, err := io.Copy(&tdfBuf, seg.TDFData); err != nil {
			t.Fatalf("copy segment data: %v", err)
		}
	} else {
		// Multi-segment
		offset := 0
		for i := 0; offset < len(plaintext); i++ {
			end := offset + segmentSize
			if end > len(plaintext) {
				end = len(plaintext)
			}
			// Copy to avoid EncryptInPlace modifying the caller's buffer.
			chunk := make([]byte, end-offset)
			copy(chunk, plaintext[offset:end])
			seg, err := writer.WriteSegment(ctx, i, chunk)
			if err != nil {
				t.Fatalf("WriteSegment(%d): %v", i, err)
			}
			if _, err := io.Copy(&tdfBuf, seg.TDFData); err != nil {
				t.Fatalf("copy segment %d data: %v", i, err)
			}
			offset = end
		}
	}

	kasKey := &policy.SimpleKasKey{
		KasUri: "https://kas.example.com",
		PublicKey: &policy.SimpleKasPublicKey{
			Algorithm: policy.Algorithm_ALGORITHM_RSA_2048,
			Kid:       "test-kid",
			Pem:       pubPEM,
		},
	}

	fin, err := writer.Finalize(ctx, tdf.WithDefaultKAS(kasKey))
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	tdfBuf.Write(fin.Data)
	return tdfBuf.Bytes()
}

func TestTDFDecryptCrossSDK(t *testing.T) {
	f := newEncryptFixture(t)
	plaintext := []byte("cross-SDK decrypt: Writer → WASM")

	// Create TDF via experimental Writer (standard SDK format)
	tdfBytes := createTDFViaWriter(t, f.pubPEM, plaintext, 0)

	// Unwrap DEK from manifest using test RSA private key
	c := parseTDF(t, tdfBytes)
	dek := unwrapDEK(t, c.Manifest, f.privPEM)

	// Decrypt via WASM module
	decrypted := f.mustDecrypt(t, tdfBytes, dek)

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("cross-SDK round-trip mismatch:\n  got:  %q\n  want: %q", decrypted, plaintext)
	}
}

func TestTDFDecryptCrossSDKMultiSegment(t *testing.T) {
	f := newEncryptFixture(t)
	// 90 bytes with 30-byte segments → 3 segments
	plaintext := bytes.Repeat([]byte("crossSDK!X"), 9)

	tdfBytes := createTDFViaWriter(t, f.pubPEM, plaintext, 30)

	c := parseTDF(t, tdfBytes)
	if len(c.Manifest.Segments) != 3 {
		t.Fatalf("expected 3 segments, got %d", len(c.Manifest.Segments))
	}

	dek := unwrapDEK(t, c.Manifest, f.privPEM)
	decrypted := f.mustDecrypt(t, tdfBytes, dek)

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("cross-SDK multi-segment mismatch:\n  got:  %q\n  want: %q", decrypted, plaintext)
	}
}

func TestTDFDecryptCrossSDKAlgorithmCombos(t *testing.T) {
	combos := []struct {
		name    string
		rootAlg tdf.IntegrityAlgorithm
		segAlg  tdf.IntegrityAlgorithm
	}{
		{"HS256/HS256", tdf.HS256, tdf.HS256},
		{"HS256/GMAC", tdf.HS256, tdf.GMAC},
		{"GMAC/HS256", tdf.GMAC, tdf.HS256},
		{"GMAC/GMAC", tdf.GMAC, tdf.GMAC},
	}

	f := newEncryptFixture(t)
	plaintext := []byte("cross-SDK algorithm combo test payload")

	for _, combo := range combos {
		t.Run(combo.name, func(t *testing.T) {
			tdfBytes := createTDFViaWriter(t, f.pubPEM, plaintext, 0,
				tdf.WithIntegrityAlgorithm(combo.rootAlg),
				tdf.WithSegmentIntegrityAlgorithm(combo.segAlg),
			)

			c := parseTDF(t, tdfBytes)
			dek := unwrapDEK(t, c.Manifest, f.privPEM)

			decrypted := f.mustDecrypt(t, tdfBytes, dek)
			if !bytes.Equal(decrypted, plaintext) {
				t.Fatalf("cross-SDK round-trip mismatch:\n  got:  %q\n  want: %q", decrypted, plaintext)
			}
		})
	}
}
