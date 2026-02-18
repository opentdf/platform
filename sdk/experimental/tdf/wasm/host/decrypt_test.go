package host

import (
	"bytes"
	"testing"
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
