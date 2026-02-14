package host

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// ── WASM binary encoding helpers (test only) ────────────────────────

// appendULEB128 appends v in unsigned LEB128 encoding.
func appendULEB128(buf []byte, v uint32) []byte {
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		buf = append(buf, b)
		if v == 0 {
			break
		}
	}
	return buf
}

// appendWASMString appends a length-prefixed WASM string.
func appendWASMString(buf []byte, s string) []byte {
	buf = appendULEB128(buf, uint32(len(s)))
	return append(buf, s...)
}

// appendWASMSection appends a complete WASM section.
func appendWASMSection(buf []byte, id byte, payload []byte) []byte {
	buf = append(buf, id)
	buf = appendULEB128(buf, uint32(len(payload)))
	return append(buf, payload...)
}

// appendWASMFuncType appends a function type: (i32 × nParams) → i32.
func appendWASMFuncType(buf []byte, nParams int) []byte {
	buf = append(buf, 0x60) // func type marker
	buf = appendULEB128(buf, uint32(nParams))
	for range nParams {
		buf = append(buf, 0x7f) // i32
	}
	buf = append(buf, 0x01, 0x7f) // 1 result: i32
	return buf
}

// appendWASMImport appends a function import entry.
func appendWASMImport(buf []byte, module, name string, typeIdx int) []byte {
	buf = appendWASMString(buf, module)
	buf = appendWASMString(buf, name)
	buf = append(buf, 0x00) // import kind: function
	buf = appendULEB128(buf, uint32(typeIdx))
	return buf
}

// buildABITestModule constructs a minimal WASM module that imports all
// expected host functions from the "crypto" and "io" modules with the
// correct type signatures. If this module instantiates successfully
// against registered host modules, the ABI is correct.
func buildABITestModule() []byte {
	// Function types:
	//   0: (i32, i32) → i32
	//   1: (i32, i32, i32, i32, i32) → i32
	//   2: (i32, i32, i32, i32) → i32
	var types []byte
	types = appendULEB128(types, 3)
	types = appendWASMFuncType(types, 2)
	types = appendWASMFuncType(types, 5)
	types = appendWASMFuncType(types, 4)

	var imports []byte
	imports = appendULEB128(imports, 10) // 8 crypto + 2 io
	imports = appendWASMImport(imports, "crypto", "random_bytes", 0)
	imports = appendWASMImport(imports, "crypto", "aes_gcm_encrypt", 1)
	imports = appendWASMImport(imports, "crypto", "aes_gcm_decrypt", 1)
	imports = appendWASMImport(imports, "crypto", "hmac_sha256", 1)
	imports = appendWASMImport(imports, "crypto", "rsa_oaep_sha1_encrypt", 1)
	imports = appendWASMImport(imports, "crypto", "rsa_oaep_sha1_decrypt", 1)
	imports = appendWASMImport(imports, "crypto", "rsa_generate_keypair", 2)
	imports = appendWASMImport(imports, "crypto", "get_last_error", 0)
	imports = appendWASMImport(imports, "io", "read_input", 0)
	imports = appendWASMImport(imports, "io", "write_output", 0)

	var memory []byte
	memory = appendULEB128(memory, 1) // 1 memory
	memory = append(memory, 0x00)     // no max
	memory = appendULEB128(memory, 100)

	var exports []byte
	exports = appendULEB128(exports, 1)
	exports = appendWASMString(exports, "memory")
	exports = append(exports, 0x02) // memory
	exports = appendULEB128(exports, 0)

	mod := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00} // magic + version
	mod = appendWASMSection(mod, 0x01, types)
	mod = appendWASMSection(mod, 0x02, imports)
	mod = appendWASMSection(mod, 0x05, memory)
	mod = appendWASMSection(mod, 0x07, exports)
	return mod
}

// ── Test setup ──────────────────────────────────────────────────────

// minimalWASM is a hand-encoded WASM module with 100 pages (6.4 MB) of
// exported memory. Used to test host functions directly with real memory.
//
//	(module (memory (export "memory") 100))
var minimalWASM = []byte{
	0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic + version
	0x05, 0x03, 0x01, 0x00, 0x64, // memory section: 1 memory, no max, 100 pages
	0x07, 0x0a, 0x01, 0x06, 0x6d, 0x65, 0x6d, 0x6f, // export section
	0x72, 0x79, 0x02, 0x00, // "memory", kind=memory, index=0
}

// setupTestModule creates a wazero runtime with a minimal WASM module
// that has writable memory. Clears stale error state.
func setupTestModule(t *testing.T) (context.Context, api.Module) {
	t.Helper()
	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)
	t.Cleanup(func() { rt.Close(ctx) })

	compiled, err := rt.CompileModule(ctx, minimalWASM)
	if err != nil {
		t.Fatalf("compile minimal WASM: %v", err)
	}
	mod, err := rt.InstantiateModule(ctx, compiled, wazero.NewModuleConfig())
	if err != nil {
		t.Fatalf("instantiate minimal WASM: %v", err)
	}

	getAndClearLastError() // clear stale state from prior tests
	return ctx, mod
}

// memSize returns the memory size in bytes of a 100-page WASM module.
const memSize uint32 = 100 * 65536 // 6,553,600

// ── Registration & ABI conformance ──────────────────────────────────

func TestRegister(t *testing.T) {
	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)
	t.Cleanup(func() { rt.Close(ctx) })

	err := Register(ctx, rt, IOConfig{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
}

func TestRegisterABIConformance(t *testing.T) {
	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)
	t.Cleanup(func() { rt.Close(ctx) })

	// Register host modules first.
	if err := Register(ctx, rt, IOConfig{}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Build a guest module that imports every host function with the exact
	// signatures the WASM guest (hostcrypto package) expects. If any module
	// name, export name, or type signature is wrong, instantiation fails.
	guest := buildABITestModule()
	compiled, err := rt.CompileModule(ctx, guest)
	if err != nil {
		t.Fatalf("compile ABI test module: %v", err)
	}
	mod, err := rt.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithName("abi_test"))
	if err != nil {
		t.Fatalf("instantiate ABI test module (import mismatch?): %v", err)
	}
	defer mod.Close(ctx)
}

// ── Happy-path tests ────────────────────────────────────────────────

func TestRandomBytes(t *testing.T) {
	ctx, mod := setupTestModule(t)

	const offset uint32 = 0
	const n uint32 = 32

	result := hostRandomBytes(ctx, mod, offset, n)
	if result == errSentinel {
		t.Fatalf("hostRandomBytes returned error: %s", getAndClearLastError())
	}
	if result != n {
		t.Fatalf("expected %d bytes, got %d", n, result)
	}

	buf, ok := mod.Memory().Read(offset, n)
	if !ok {
		t.Fatal("failed to read random bytes from WASM memory")
	}
	// 32 random bytes being all zeros is astronomically unlikely.
	allZero := true
	for _, b := range buf {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("random bytes are all zeros")
	}
}

func TestAesGcmRoundTrip(t *testing.T) {
	ctx, mod := setupTestModule(t)

	key, err := ocrypto.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("hello, wasm world!")

	// Memory layout:
	//   0..31:     key (32 bytes)
	//   32..49:    plaintext (18 bytes)
	//   1024..:    ciphertext output
	//   2048..:    decrypted output
	if !mod.Memory().Write(0, key) {
		t.Fatal("write key")
	}
	if !mod.Memory().Write(32, plaintext) {
		t.Fatal("write plaintext")
	}

	// Encrypt
	ctLen := hostAesGcmEncrypt(ctx, mod, 0, 32, 32, uint32(len(plaintext)), 1024)
	if ctLen == errSentinel {
		t.Fatalf("encrypt error: %s", getAndClearLastError())
	}
	// nonce(12) + ciphertext + tag(16) = plaintext_len + 28
	if expected := uint32(len(plaintext)) + 28; ctLen != expected {
		t.Fatalf("ciphertext length: got %d, want %d", ctLen, expected)
	}

	// Decrypt
	ptLen := hostAesGcmDecrypt(ctx, mod, 0, 32, 1024, ctLen, 2048)
	if ptLen == errSentinel {
		t.Fatalf("decrypt error: %s", getAndClearLastError())
	}

	decrypted, ok := mod.Memory().Read(2048, ptLen)
	if !ok {
		t.Fatal("read decrypted data")
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestHmacSHA256(t *testing.T) {
	ctx, mod := setupTestModule(t)

	key := []byte("test-hmac-key")
	data := []byte("data to authenticate")

	// Memory layout:
	//   0..12:    key (13 bytes)
	//   64..83:   data (20 bytes)
	//   128..159: output (32 bytes)
	if !mod.Memory().Write(0, key) {
		t.Fatal("write key")
	}
	if !mod.Memory().Write(64, data) {
		t.Fatal("write data")
	}

	result := hostHmacSHA256(ctx, mod, 0, uint32(len(key)), 64, uint32(len(data)), 128)
	if result == errSentinel {
		t.Fatalf("hmac error: %s", getAndClearLastError())
	}
	if result != 32 {
		t.Fatalf("hmac length: got %d, want 32", result)
	}

	got, ok := mod.Memory().Read(128, 32)
	if !ok {
		t.Fatal("read hmac output")
	}

	// Compare with direct ocrypto call.
	want := ocrypto.CalculateSHA256Hmac(key, data)
	if !bytes.Equal(got, want) {
		t.Fatalf("hmac mismatch:\n  got:  %x\n  want: %x", got, want)
	}
}

func TestRsaGenerateKeypairAndRoundTrip(t *testing.T) {
	ctx, mod := setupTestModule(t)

	// Memory layout (generous offsets to avoid overlap):
	//   0..4095:      private key PEM
	//   4096..8191:   public key PEM
	//   8192..8195:   pub key length (LE uint32)
	//   16384..16415: plaintext (32 bytes)
	//   32768..33023: ciphertext (256 bytes for RSA-2048)
	//   49152..49407: decrypted output (256 bytes)
	const (
		privOff   uint32 = 0
		pubOff    uint32 = 4096
		pubLenOff uint32 = 8192
		ptOff     uint32 = 16384
		ctOff     uint32 = 32768
		decOff    uint32 = 49152
	)

	// Generate keypair
	privLen := hostRsaGenerateKeypair(ctx, mod, 2048, privOff, pubOff, pubLenOff)
	if privLen == errSentinel {
		t.Fatalf("keygen error: %s", getAndClearLastError())
	}

	// Read public key length
	pubLenBytes, ok := mod.Memory().Read(pubLenOff, 4)
	if !ok {
		t.Fatal("read pub len")
	}
	pubLen := binary.LittleEndian.Uint32(pubLenBytes)

	// Validate PEM format
	privPEM, ok := mod.Memory().Read(privOff, privLen)
	if !ok {
		t.Fatal("read private key")
	}
	pubPEM, ok := mod.Memory().Read(pubOff, pubLen)
	if !ok {
		t.Fatal("read public key")
	}
	if block, _ := pem.Decode(privPEM); block == nil {
		t.Fatal("private key is not valid PEM")
	}
	if block, _ := pem.Decode(pubPEM); block == nil {
		t.Fatal("public key is not valid PEM")
	}

	// Encrypt with the generated public key
	plaintext := []byte("RSA round-trip test data")
	if !mod.Memory().Write(ptOff, plaintext) {
		t.Fatal("write plaintext")
	}

	ctLen := hostRsaOaepSha1Encrypt(ctx, mod, pubOff, pubLen, ptOff, uint32(len(plaintext)), ctOff)
	if ctLen == errSentinel {
		t.Fatalf("encrypt error: %s", getAndClearLastError())
	}

	// Decrypt with the generated private key
	ptLen := hostRsaOaepSha1Decrypt(ctx, mod, privOff, privLen, ctOff, ctLen, decOff)
	if ptLen == errSentinel {
		t.Fatalf("decrypt error: %s", getAndClearLastError())
	}

	decrypted, ok := mod.Memory().Read(decOff, ptLen)
	if !ok {
		t.Fatal("read decrypted data")
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("RSA round-trip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestReadWriteIO(t *testing.T) {
	ctx, mod := setupTestModule(t)

	inputData := []byte("input stream data for WASM")
	var outputBuf bytes.Buffer

	cfg := IOConfig{
		Input:  bytes.NewReader(inputData),
		Output: &outputBuf,
	}

	readFn := newReadInput(cfg)
	writeFn := newWriteOutput(cfg)

	// Test read_input: host reads from input into WASM memory at offset 0.
	const readOff uint32 = 0
	n := readFn(ctx, mod, readOff, uint32(len(inputData)))
	if n == errSentinel {
		t.Fatalf("read_input error: %s", getAndClearLastError())
	}
	if n != uint32(len(inputData)) {
		t.Fatalf("read_input: got %d bytes, want %d", n, len(inputData))
	}
	got, ok := mod.Memory().Read(readOff, n)
	if !ok {
		t.Fatal("read from WASM memory after read_input")
	}
	if !bytes.Equal(got, inputData) {
		t.Fatalf("read_input data mismatch: got %q, want %q", got, inputData)
	}

	// Second read should return 0 (EOF).
	n2 := readFn(ctx, mod, readOff, 128)
	if n2 != 0 {
		t.Fatalf("expected EOF (0), got %d", n2)
	}

	// Test write_output: write data from WASM memory to host output.
	outputData := []byte("output from WASM")
	const writeOff uint32 = 4096
	if !mod.Memory().Write(writeOff, outputData) {
		t.Fatal("write output data to WASM memory")
	}
	wn := writeFn(ctx, mod, writeOff, uint32(len(outputData)))
	if wn == errSentinel {
		t.Fatalf("write_output error: %s", getAndClearLastError())
	}
	if wn != uint32(len(outputData)) {
		t.Fatalf("write_output: wrote %d bytes, want %d", wn, len(outputData))
	}
	if !bytes.Equal(outputBuf.Bytes(), outputData) {
		t.Fatalf("write_output mismatch: got %q, want %q", outputBuf.Bytes(), outputData)
	}
}

// ── Error-path tests ────────────────────────────────────────────────

func TestGetLastError(t *testing.T) {
	ctx, mod := setupTestModule(t)

	// Trigger an error: AES-GCM with a 1-byte key (invalid).
	if !mod.Memory().Write(0, []byte{0x42}) {
		t.Fatal("write bad key")
	}
	result := hostAesGcmEncrypt(ctx, mod, 0, 1, 0, 0, 1024)
	if result != errSentinel {
		t.Fatal("expected error sentinel for bad key")
	}

	// Retrieve the error via the host function.
	const errBufOff uint32 = 2048
	const errBufCap uint32 = 512
	errLen := hostGetLastError(ctx, mod, errBufOff, errBufCap)
	if errLen == 0 {
		t.Fatal("expected non-empty error message")
	}

	errMsg, ok := mod.Memory().Read(errBufOff, errLen)
	if !ok {
		t.Fatal("read error message")
	}
	if !strings.Contains(strings.ToLower(string(errMsg)), "key") {
		t.Errorf("expected error about key, got: %q", string(errMsg))
	}

	// Error should be cleared after read.
	errLen2 := hostGetLastError(ctx, mod, errBufOff, errBufCap)
	if errLen2 != 0 {
		t.Fatal("expected error to be cleared after get_last_error")
	}
}

func TestGetLastError_NoError(t *testing.T) {
	ctx, mod := setupTestModule(t)

	const errBufOff uint32 = 0
	const errBufCap uint32 = 256
	errLen := hostGetLastError(ctx, mod, errBufOff, errBufCap)
	if errLen != 0 {
		msg, _ := mod.Memory().Read(errBufOff, errLen)
		t.Fatalf("expected 0 (no error), got %d: %q", errLen, msg)
	}
}

func TestGetLastError_Truncation(t *testing.T) {
	ctx, mod := setupTestModule(t)

	// Trigger an error with a message longer than our capacity.
	if !mod.Memory().Write(0, []byte{0x42}) {
		t.Fatal("write bad key")
	}
	result := hostAesGcmEncrypt(ctx, mod, 0, 1, 0, 0, 1024)
	if result != errSentinel {
		t.Fatal("expected error sentinel")
	}

	// Read with a very small capacity — should truncate.
	const errBufOff uint32 = 2048
	const tinyCapacity uint32 = 5
	errLen := hostGetLastError(ctx, mod, errBufOff, tinyCapacity)
	if errLen == 0 {
		t.Fatal("expected non-empty (truncated) error message")
	}
	if errLen > tinyCapacity {
		t.Fatalf("error length %d exceeds capacity %d", errLen, tinyCapacity)
	}
}

func TestAesGcmEncrypt_EmptyKey(t *testing.T) {
	ctx, mod := setupTestModule(t)

	// keyLen=0 should trigger errReadKey (readBytes returns nil for length 0).
	result := hostAesGcmEncrypt(ctx, mod, 0, 0, 0, 10, 1024)
	if result != errSentinel {
		t.Fatal("expected error sentinel for empty key")
	}
	msg := getAndClearLastError()
	if msg == "" {
		t.Fatal("expected lastError to be set")
	}
}

func TestAesGcmDecrypt_CorruptedCiphertext(t *testing.T) {
	ctx, mod := setupTestModule(t)

	key, err := ocrypto.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	if !mod.Memory().Write(0, key) {
		t.Fatal("write key")
	}

	// Write garbage as "ciphertext" — must be >= 28 bytes to pass ocrypto's
	// length check, but will fail authentication.
	garbage := bytes.Repeat([]byte{0xAB}, 64)
	if !mod.Memory().Write(1024, garbage) {
		t.Fatal("write garbage ciphertext")
	}

	result := hostAesGcmDecrypt(ctx, mod, 0, 32, 1024, 64, 2048)
	if result != errSentinel {
		t.Fatal("expected error sentinel for corrupted ciphertext")
	}
	msg := getAndClearLastError()
	if msg == "" {
		t.Fatal("expected lastError to be set for corrupted ciphertext")
	}
}

func TestAesGcmDecrypt_EmptyKey(t *testing.T) {
	ctx, mod := setupTestModule(t)

	result := hostAesGcmDecrypt(ctx, mod, 0, 0, 1024, 64, 2048)
	if result != errSentinel {
		t.Fatal("expected error sentinel for empty key")
	}
	msg := getAndClearLastError()
	if !strings.Contains(msg, "key") {
		t.Errorf("expected error about key, got: %q", msg)
	}
}

func TestAesGcmDecrypt_EmptyCiphertext(t *testing.T) {
	ctx, mod := setupTestModule(t)

	key, err := ocrypto.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	if !mod.Memory().Write(0, key) {
		t.Fatal("write key")
	}

	// ctLen=0 → readBytes returns nil → errReadCT
	result := hostAesGcmDecrypt(ctx, mod, 0, 32, 1024, 0, 2048)
	if result != errSentinel {
		t.Fatal("expected error sentinel for empty ciphertext")
	}
	msg := getAndClearLastError()
	if !strings.Contains(msg, "ciphertext") {
		t.Errorf("expected error about ciphertext, got: %q", msg)
	}
}

func TestRsaOaepSha1Decrypt_WrongKey(t *testing.T) {
	ctx, mod := setupTestModule(t)

	// Generate two different keypairs.
	kp1, err := ocrypto.NewRSAKeyPair(2048)
	if err != nil {
		t.Fatal(err)
	}
	kp2, err := ocrypto.NewRSAKeyPair(2048)
	if err != nil {
		t.Fatal(err)
	}

	pubPEM1, err := kp1.PublicKeyInPemFormat()
	if err != nil {
		t.Fatal(err)
	}
	privPEM2, err := kp2.PrivateKeyInPemFormat()
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt with key 1's public key.
	pubBytes := []byte(pubPEM1)
	if !mod.Memory().Write(0, pubBytes) {
		t.Fatal("write pub key")
	}
	plaintext := []byte("secret data")
	if !mod.Memory().Write(4096, plaintext) {
		t.Fatal("write plaintext")
	}

	ctLen := hostRsaOaepSha1Encrypt(ctx, mod, 0, uint32(len(pubBytes)), 4096, uint32(len(plaintext)), 8192)
	if ctLen == errSentinel {
		t.Fatalf("encrypt error: %s", getAndClearLastError())
	}

	// Decrypt with key 2's private key — should fail.
	privBytes := []byte(privPEM2)
	if !mod.Memory().Write(16384, privBytes) {
		t.Fatal("write wrong priv key")
	}

	result := hostRsaOaepSha1Decrypt(ctx, mod, 16384, uint32(len(privBytes)), 8192, ctLen, 32768)
	if result != errSentinel {
		t.Fatal("expected error sentinel when decrypting with wrong key")
	}
	msg := getAndClearLastError()
	if msg == "" {
		t.Fatal("expected lastError to be set for wrong-key decrypt")
	}
}

func TestRandomBytes_OOBWrite(t *testing.T) {
	ctx, mod := setupTestModule(t)

	// Write past the end of WASM memory (100 pages = 6,553,600 bytes).
	result := hostRandomBytes(ctx, mod, memSize-1, 32)
	if result != errSentinel {
		t.Fatal("expected error sentinel for OOB write")
	}
	msg := getAndClearLastError()
	if !strings.Contains(msg, "out of bounds") {
		t.Errorf("expected OOB error, got: %q", msg)
	}
}

func TestHmacSHA256_OOBOutput(t *testing.T) {
	ctx, mod := setupTestModule(t)

	key := []byte("key")
	data := []byte("data")
	if !mod.Memory().Write(0, key) {
		t.Fatal("write key")
	}
	if !mod.Memory().Write(64, data) {
		t.Fatal("write data")
	}

	// Output at the very end of memory — 32 bytes won't fit.
	result := hostHmacSHA256(ctx, mod, 0, uint32(len(key)), 64, uint32(len(data)), memSize-1)
	if result != errSentinel {
		t.Fatal("expected error sentinel for OOB output")
	}
	msg := getAndClearLastError()
	if !strings.Contains(msg, "out of bounds") {
		t.Errorf("expected OOB error, got: %q", msg)
	}
}

func TestReadInput_NilReader(t *testing.T) {
	ctx, mod := setupTestModule(t)

	readFn := newReadInput(IOConfig{Input: nil})
	result := readFn(ctx, mod, 0, 128)
	if result != 0 {
		t.Fatalf("expected 0 (EOF) for nil reader, got %d", result)
	}
}

func TestWriteOutput_NilWriter(t *testing.T) {
	ctx, mod := setupTestModule(t)

	if !mod.Memory().Write(0, []byte("data")) {
		t.Fatal("write data")
	}

	writeFn := newWriteOutput(IOConfig{Output: nil})
	result := writeFn(ctx, mod, 0, 4)
	if result != errSentinel {
		t.Fatal("expected error sentinel for nil writer")
	}
	msg := getAndClearLastError()
	if msg == "" {
		t.Fatal("expected lastError for nil writer")
	}
}

func TestSuccessDoesNotLeaveStaleError(t *testing.T) {
	ctx, mod := setupTestModule(t)

	// Trigger an error first so lastErr is non-empty.
	hostAesGcmEncrypt(ctx, mod, 0, 0, 0, 0, 0)
	stale := getAndClearLastError()
	if stale == "" {
		t.Fatal("setup: expected an error to be set")
	}

	// Now trigger a new error and clear it.
	hostAesGcmEncrypt(ctx, mod, 0, 0, 0, 0, 0)
	getAndClearLastError()

	// Perform a successful operation.
	key, err := ocrypto.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	if !mod.Memory().Write(0, key) {
		t.Fatal("write key")
	}
	if !mod.Memory().Write(64, []byte("hello")) {
		t.Fatal("write plaintext")
	}
	result := hostAesGcmEncrypt(ctx, mod, 0, 32, 64, 5, 1024)
	if result == errSentinel {
		t.Fatalf("unexpected error: %s", getAndClearLastError())
	}

	// Verify no stale error lingers.
	leftover := getAndClearLastError()
	if leftover != "" {
		t.Fatalf("successful call left stale error: %q", leftover)
	}
}
