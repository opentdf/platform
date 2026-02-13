package host

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/sdk/experimental/tdf"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// ── WASM binary compilation (cached per test run) ───────────────────

var (
	wasmBinary    []byte
	wasmBuildOnce sync.Once
	wasmBuildErr  error
)

func compileWASM(t *testing.T) []byte {
	t.Helper()
	wasmBuildOnce.Do(func() {
		dir, err := os.Getwd()
		if err != nil {
			wasmBuildErr = fmt.Errorf("getwd: %w", err)
			return
		}
		for {
			if _, statErr := os.Stat(filepath.Join(dir, "go.work")); statErr == nil {
				break
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				wasmBuildErr = fmt.Errorf("go.work not found")
				return
			}
			dir = parent
		}

		tmpFile, err := os.CreateTemp("", "tdf-wasm-test-*.wasm")
		if err != nil {
			wasmBuildErr = fmt.Errorf("create temp: %w", err)
			return
		}
		tmpPath := tmpFile.Name()
		tmpFile.Close()
		defer os.Remove(tmpPath)

		cmd := exec.Command("go", "build", "-o", tmpPath, "./sdk/experimental/tdf/wasm/")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
		if output, err := cmd.CombinedOutput(); err != nil {
			wasmBuildErr = fmt.Errorf("go build: %v\n%s", err, output)
			return
		}

		wasmBinary, wasmBuildErr = os.ReadFile(tmpPath)
	})
	if wasmBuildErr != nil {
		t.Skipf("skipping: WASM build failed: %v", wasmBuildErr)
	}
	return wasmBinary
}

// ── Test fixture ────────────────────────────────────────────────────

type encryptFixture struct {
	ctx     context.Context
	mod     api.Module
	pubPEM  string
	privPEM string
}

func newEncryptFixture(t *testing.T) *encryptFixture {
	t.Helper()
	wasmBytes := compileWASM(t)

	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)
	t.Cleanup(func() { rt.Close(ctx) })

	// Use a test WASI with no-op proc_exit so the module stays alive
	// after main() returns (Go 1.25 wasip1 calls proc_exit(0)).
	if err := registerTestWASI(ctx, rt); err != nil {
		t.Fatalf("register test WASI: %v", err)
	}

	if err := Register(ctx, rt, IOConfig{}); err != nil {
		t.Fatalf("register host modules: %v", err)
	}

	compiled, err := rt.CompileModule(ctx, wasmBytes)
	if err != nil {
		t.Fatalf("compile WASM: %v", err)
	}

	// Skip _start during instantiation — we call it manually below so we
	// can catch the proc_exit panic and keep the module alive.
	cfg := wazero.NewModuleConfig().
		WithStdout(io.Discard).
		WithStderr(io.Discard).
		WithStartFunctions() // skip _start
	mod, err := rt.InstantiateModule(ctx, compiled, cfg)
	if err != nil {
		t.Fatalf("instantiate WASM module: %v", err)
	}

	// Call _start manually. Go's wasip1 runtime calls proc_exit(0) after
	// main() returns; our custom WASI turns that into a panic (non-ExitError)
	// so the module stays alive for wasmexport calls.
	_, startErr := mod.ExportedFunction("_start").Call(ctx)
	if startErr != nil {
		// Expected: procExitSignal panic wrapped as error.
		if !strings.Contains(startErr.Error(), "proc_exit") {
			t.Fatalf("unexpected _start error: %v", startErr)
		}
	}

	kp, err := ocrypto.NewRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("generate RSA keypair: %v", err)
	}
	pub, err := kp.PublicKeyInPemFormat()
	if err != nil {
		t.Fatalf("public key PEM: %v", err)
	}
	priv, err := kp.PrivateKeyInPemFormat()
	if err != nil {
		t.Fatalf("private key PEM: %v", err)
	}

	return &encryptFixture{ctx: ctx, mod: mod, pubPEM: pub, privPEM: priv}
}

func (f *encryptFixture) wasmMalloc(t *testing.T, size uint32) uint32 {
	t.Helper()
	results, err := f.mod.ExportedFunction("malloc").Call(f.ctx, uint64(size))
	if err != nil {
		t.Fatalf("malloc(%d): %v", size, err)
	}
	return uint32(results[0])
}

func (f *encryptFixture) writeToWASM(t *testing.T, data []byte) uint32 {
	t.Helper()
	if len(data) == 0 {
		return 0
	}
	ptr := f.wasmMalloc(t, uint32(len(data)))
	if !f.mod.Memory().Write(ptr, data) {
		t.Fatalf("write %d bytes at WASM offset %d", len(data), ptr)
	}
	return ptr
}

func (f *encryptFixture) callGetError(t *testing.T) string {
	t.Helper()
	const bufCap = 1024
	bufPtr := f.wasmMalloc(t, bufCap)
	results, err := f.mod.ExportedFunction("get_error").Call(f.ctx, uint64(bufPtr), uint64(bufCap))
	if err != nil {
		t.Fatalf("get_error: %v", err)
	}
	n := uint32(results[0])
	if n == 0 {
		return ""
	}
	msg, ok := f.mod.Memory().Read(bufPtr, n)
	if !ok {
		t.Fatal("read error message from WASM memory")
	}
	return string(msg)
}

// callEncryptRaw invokes tdf_encrypt and returns the raw result length.
// Does NOT fail on error — caller decides how to handle resultLen == 0.
func (f *encryptFixture) callEncryptRaw(
	t *testing.T,
	kasPubPEM, kasURL string,
	attrs []string,
	plaintext []byte,
	outCapacity uint32,
) (resultLen uint32, outPtr uint32) {
	t.Helper()

	kasPubPtr := f.writeToWASM(t, []byte(kasPubPEM))
	kasURLPtr := f.writeToWASM(t, []byte(kasURL))

	var attrBytes []byte
	if len(attrs) > 0 {
		attrBytes = []byte(strings.Join(attrs, "\n"))
	}
	attrPtr := f.writeToWASM(t, attrBytes)
	ptPtr := f.writeToWASM(t, plaintext)
	outPtr = f.wasmMalloc(t, outCapacity)

	results, err := f.mod.ExportedFunction("tdf_encrypt").Call(f.ctx,
		uint64(kasPubPtr), uint64(len(kasPubPEM)),
		uint64(kasURLPtr), uint64(len(kasURL)),
		uint64(attrPtr), uint64(len(attrBytes)),
		uint64(ptPtr), uint64(len(plaintext)),
		uint64(outPtr), uint64(outCapacity),
	)
	if err != nil {
		t.Fatalf("tdf_encrypt call failed: %v", err)
	}
	return uint32(results[0]), outPtr
}

// mustEncrypt calls tdf_encrypt and fails the test if it returns 0.
func (f *encryptFixture) mustEncrypt(t *testing.T, kasURL string, attrs []string, plaintext []byte) []byte {
	t.Helper()
	resultLen, outPtr := f.callEncryptRaw(t, f.pubPEM, kasURL, attrs, plaintext, 1024*1024)
	if resultLen == 0 {
		t.Fatalf("tdf_encrypt returned 0: %s", f.callGetError(t))
	}
	tdfBytes, ok := f.mod.Memory().Read(outPtr, resultLen)
	if !ok {
		t.Fatal("read TDF output from WASM memory")
	}
	out := make([]byte, len(tdfBytes))
	copy(out, tdfBytes)
	return out
}

// ── TDF parsing helpers ─────────────────────────────────────────────

type tdfContent struct {
	ManifestRaw []byte
	Manifest    tdf.Manifest
	Payload     []byte
}

func parseTDF(t *testing.T, tdfBytes []byte) tdfContent {
	t.Helper()
	r, err := zip.NewReader(bytes.NewReader(tdfBytes), int64(len(tdfBytes)))
	if err != nil {
		t.Fatalf("parse TDF ZIP: %v", err)
	}

	var c tdfContent
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open ZIP entry %s: %v", f.Name, err)
		}
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, rc); err != nil {
			rc.Close()
			t.Fatalf("read ZIP entry %s: %v", f.Name, err)
		}
		rc.Close()

		switch f.Name {
		case "0.payload":
			c.Payload = buf.Bytes()
		case "0.manifest.json":
			c.ManifestRaw = buf.Bytes()
		}
	}
	if c.Payload == nil {
		t.Fatal("0.payload not found in TDF ZIP")
	}
	if c.ManifestRaw == nil {
		t.Fatal("0.manifest.json not found in TDF ZIP")
	}
	if err := json.Unmarshal(c.ManifestRaw, &c.Manifest); err != nil {
		t.Fatalf("parse manifest JSON: %v\n%s", err, c.ManifestRaw)
	}
	return c
}

// unwrapDEK RSA-decrypts the wrapped key from the manifest to recover the DEK.
func unwrapDEK(t *testing.T, m tdf.Manifest, privPEM string) []byte {
	t.Helper()
	if len(m.KeyAccessObjs) == 0 {
		t.Fatal("no key access objects in manifest")
	}
	wrappedKey, err := base64.StdEncoding.DecodeString(m.KeyAccessObjs[0].WrappedKey)
	if err != nil {
		t.Fatalf("decode wrapped key: %v", err)
	}
	dec, err := ocrypto.NewAsymDecryption(privPEM)
	if err != nil {
		t.Fatalf("create RSA decryptor: %v", err)
	}
	dek, err := dec.Decrypt(wrappedKey)
	if err != nil {
		t.Fatalf("RSA-unwrap DEK: %v", err)
	}
	if len(dek) != 32 {
		t.Fatalf("DEK length: got %d, want 32", len(dek))
	}
	return dek
}

// ── Integration tests ───────────────────────────────────────────────

func TestTDFEncryptRoundTrip(t *testing.T) {
	f := newEncryptFixture(t)
	plaintext := []byte("hello, TDF from WASM!")

	tdfBytes := f.mustEncrypt(t, "https://kas.example.com", nil, plaintext)
	c := parseTDF(t, tdfBytes)
	dek := unwrapDEK(t, c.Manifest, f.privPEM)

	aesGcm, err := ocrypto.NewAESGcm(dek)
	if err != nil {
		t.Fatalf("create AES-GCM: %v", err)
	}
	decrypted, err := aesGcm.Decrypt(c.Payload)
	if err != nil {
		t.Fatalf("AES-GCM decrypt payload: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("round-trip mismatch:\n  got:  %q\n  want: %q", decrypted, plaintext)
	}
}

func TestTDFEncryptManifestFields(t *testing.T) {
	f := newEncryptFixture(t)
	plaintext := []byte("manifest field test")
	kasURL := "https://kas.example.com"

	tdfBytes := f.mustEncrypt(t, kasURL, nil, plaintext)
	c := parseTDF(t, tdfBytes)
	m := c.Manifest

	// Schema version
	if m.TDFVersion != "4.3.0" {
		t.Errorf("TDFVersion: got %q, want %q", m.TDFVersion, "4.3.0")
	}

	// Encryption info top-level
	if m.KeyAccessType != "split" {
		t.Errorf("KeyAccessType: got %q, want %q", m.KeyAccessType, "split")
	}
	if m.Method.Algorithm != "AES-256-GCM" {
		t.Errorf("Method.Algorithm: got %q, want %q", m.Method.Algorithm, "AES-256-GCM")
	}
	if !m.Method.IsStreamable {
		t.Error("Method.IsStreamable: got false, want true")
	}

	// Key access
	if len(m.KeyAccessObjs) != 1 {
		t.Fatalf("KeyAccessObjs count: got %d, want 1", len(m.KeyAccessObjs))
	}
	ka := m.KeyAccessObjs[0]
	if ka.KeyType != "wrapped" {
		t.Errorf("KeyType: got %q, want %q", ka.KeyType, "wrapped")
	}
	if ka.KasURL != kasURL {
		t.Errorf("KasURL: got %q, want %q", ka.KasURL, kasURL)
	}
	if ka.Protocol != "kas" {
		t.Errorf("Protocol: got %q, want %q", ka.Protocol, "kas")
	}
	if ka.PolicyBinding.Alg != "HS256" {
		t.Errorf("PolicyBinding.Alg: got %q, want %q", ka.PolicyBinding.Alg, "HS256")
	}
	if ka.WrappedKey == "" {
		t.Error("WrappedKey is empty")
	}

	// Integrity
	if m.RootSignature.Algorithm != "HS256" {
		t.Errorf("RootSignature.Algorithm: got %q, want %q", m.RootSignature.Algorithm, "HS256")
	}
	if m.SegmentHashAlgorithm != "HS256" {
		t.Errorf("SegmentHashAlgorithm: got %q, want %q", m.SegmentHashAlgorithm, "HS256")
	}

	// Single segment
	if len(m.Segments) != 1 {
		t.Fatalf("Segments count: got %d, want 1", len(m.Segments))
	}
	seg := m.Segments[0]
	if seg.Size != int64(len(plaintext)) {
		t.Errorf("Segment.Size: got %d, want %d", seg.Size, len(plaintext))
	}
	expectedEncSize := int64(len(plaintext) + 28) // nonce(12) + tag(16)
	if seg.EncryptedSize != expectedEncSize {
		t.Errorf("Segment.EncryptedSize: got %d, want %d", seg.EncryptedSize, expectedEncSize)
	}
	if m.DefaultSegmentSize != seg.Size {
		t.Errorf("DefaultSegmentSize: got %d, want %d", m.DefaultSegmentSize, seg.Size)
	}
	if m.DefaultEncryptedSegSize != seg.EncryptedSize {
		t.Errorf("DefaultEncryptedSegSize: got %d, want %d", m.DefaultEncryptedSegSize, seg.EncryptedSize)
	}

	// Payload
	if m.Payload.Type != "reference" {
		t.Errorf("Payload.Type: got %q, want %q", m.Payload.Type, "reference")
	}
	if m.Payload.URL != "0.payload" {
		t.Errorf("Payload.URL: got %q, want %q", m.Payload.URL, "0.payload")
	}
	if m.Payload.Protocol != "zip" {
		t.Errorf("Payload.Protocol: got %q, want %q", m.Payload.Protocol, "zip")
	}
	if m.Payload.MimeType != "application/octet-stream" {
		t.Errorf("Payload.MimeType: got %q, want %q", m.Payload.MimeType, "application/octet-stream")
	}
	if !m.Payload.IsEncrypted {
		t.Error("Payload.IsEncrypted: got false, want true")
	}

	// Policy is non-empty base64
	if m.Policy == "" {
		t.Error("Policy is empty")
	}
	if _, err := base64.StdEncoding.DecodeString(m.Policy); err != nil {
		t.Errorf("Policy is not valid base64: %v", err)
	}
}

func TestTDFEncryptPolicyBinding(t *testing.T) {
	f := newEncryptFixture(t)
	plaintext := []byte("binding verification test")

	tdfBytes := f.mustEncrypt(t, "https://kas.example.com", nil, plaintext)
	c := parseTDF(t, tdfBytes)
	dek := unwrapDEK(t, c.Manifest, f.privPEM)

	// Recompute binding: HMAC-SHA256(dek, base64Policy) → hex → base64
	mac := hmac.New(sha256.New, dek)
	mac.Write([]byte(c.Manifest.Policy))
	hmacResult := mac.Sum(nil)
	hexStr := hex.EncodeToString(hmacResult)
	expected := base64.StdEncoding.EncodeToString([]byte(hexStr))

	actual := c.Manifest.KeyAccessObjs[0].PolicyBinding.Hash
	if actual != expected {
		t.Fatalf("policy binding mismatch:\n  got:  %s\n  want: %s", actual, expected)
	}
}

func TestTDFEncryptSegmentIntegrity(t *testing.T) {
	f := newEncryptFixture(t)
	plaintext := []byte("integrity verification data 12345")

	tdfBytes := f.mustEncrypt(t, "https://kas.example.com", nil, plaintext)
	c := parseTDF(t, tdfBytes)
	dek := unwrapDEK(t, c.Manifest, f.privPEM)

	// cipher = payload[12:] (ciphertext+tag, without nonce)
	if len(c.Payload) < 28 {
		t.Fatalf("payload too short: %d bytes", len(c.Payload))
	}
	cipher := c.Payload[12:]

	// Segment hash: HMAC-SHA256(dek, cipher) → base64
	segMac := hmac.New(sha256.New, dek)
	segMac.Write(cipher)
	segmentSig := segMac.Sum(nil)
	expectedSegHash := base64.StdEncoding.EncodeToString(segmentSig)
	if c.Manifest.Segments[0].Hash != expectedSegHash {
		t.Fatalf("segment hash mismatch:\n  got:  %s\n  want: %s", c.Manifest.Segments[0].Hash, expectedSegHash)
	}

	// Root signature: HMAC-SHA256(dek, raw_segment_hmac) → base64
	rootMac := hmac.New(sha256.New, dek)
	rootMac.Write(segmentSig)
	rootSig := rootMac.Sum(nil)
	expectedRootSig := base64.StdEncoding.EncodeToString(rootSig)
	if c.Manifest.RootSignature.Signature != expectedRootSig {
		t.Fatalf("root signature mismatch:\n  got:  %s\n  want: %s", c.Manifest.RootSignature.Signature, expectedRootSig)
	}
}

func TestTDFEncryptPolicyUUID(t *testing.T) {
	f := newEncryptFixture(t)

	tdfBytes := f.mustEncrypt(t, "https://kas.example.com", nil, []byte("uuid test"))
	c := parseTDF(t, tdfBytes)

	policyJSON, err := base64.StdEncoding.DecodeString(c.Manifest.Policy)
	if err != nil {
		t.Fatalf("decode base64 policy: %v", err)
	}
	var policy tdf.Policy
	if err := json.Unmarshal(policyJSON, &policy); err != nil {
		t.Fatalf("parse policy JSON: %v\n%s", err, policyJSON)
	}

	uuidRe := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !uuidRe.MatchString(policy.UUID) {
		t.Errorf("UUID not valid v4 format: %q", policy.UUID)
	}
}

func TestTDFEncryptWithAttributes(t *testing.T) {
	f := newEncryptFixture(t)
	attrs := []string{
		"https://example.com/attr/Classification/value/S",
		"https://example.com/attr/Env/value/Production",
	}

	tdfBytes := f.mustEncrypt(t, "https://kas.example.com", attrs, []byte("classified"))
	c := parseTDF(t, tdfBytes)

	policyJSON, err := base64.StdEncoding.DecodeString(c.Manifest.Policy)
	if err != nil {
		t.Fatalf("decode policy: %v", err)
	}
	var policy tdf.Policy
	if err := json.Unmarshal(policyJSON, &policy); err != nil {
		t.Fatalf("parse policy: %v", err)
	}

	if len(policy.Body.DataAttributes) != len(attrs) {
		t.Fatalf("attribute count: got %d, want %d", len(policy.Body.DataAttributes), len(attrs))
	}
	for i, want := range attrs {
		got := policy.Body.DataAttributes[i].Attribute
		if got != want {
			t.Errorf("attribute[%d]: got %q, want %q", i, got, want)
		}
	}
}

func TestTDFEncryptEmptyPlaintext(t *testing.T) {
	f := newEncryptFixture(t)

	tdfBytes := f.mustEncrypt(t, "https://kas.example.com", nil, []byte{})
	c := parseTDF(t, tdfBytes)
	dek := unwrapDEK(t, c.Manifest, f.privPEM)

	// Empty plaintext → payload is nonce(12) + tag(16) = 28 bytes
	if len(c.Payload) != 28 {
		t.Fatalf("payload length for empty plaintext: got %d, want 28", len(c.Payload))
	}

	aesGcm, err := ocrypto.NewAESGcm(dek)
	if err != nil {
		t.Fatalf("create AES-GCM: %v", err)
	}
	decrypted, err := aesGcm.Decrypt(c.Payload)
	if err != nil {
		t.Fatalf("decrypt empty payload: %v", err)
	}
	if len(decrypted) != 0 {
		t.Fatalf("expected empty decrypted, got %d bytes", len(decrypted))
	}

	if c.Manifest.Segments[0].Size != 0 {
		t.Errorf("segment plaintext size: got %d, want 0", c.Manifest.Segments[0].Size)
	}
	if c.Manifest.Segments[0].EncryptedSize != 28 {
		t.Errorf("segment encrypted size: got %d, want 28", c.Manifest.Segments[0].EncryptedSize)
	}
}

func TestTDFEncryptDeterministicSizes(t *testing.T) {
	f := newEncryptFixture(t)
	plaintext := []byte("deterministic size check")

	tdf1 := f.mustEncrypt(t, "https://kas.example.com", nil, plaintext)
	tdf2 := f.mustEncrypt(t, "https://kas.example.com", nil, plaintext)

	c1 := parseTDF(t, tdf1)
	c2 := parseTDF(t, tdf2)

	if c1.Manifest.Segments[0].Size != c2.Manifest.Segments[0].Size {
		t.Error("segment plaintext sizes differ between encryptions")
	}
	if c1.Manifest.Segments[0].EncryptedSize != c2.Manifest.Segments[0].EncryptedSize {
		t.Error("segment encrypted sizes differ between encryptions")
	}

	// Payloads must differ (different DEK + nonce each time)
	if bytes.Equal(c1.Payload, c2.Payload) {
		t.Error("payloads identical across encryptions — expected different DEK/nonce")
	}
}

// ── Error-path tests ────────────────────────────────────────────────

func TestTDFEncryptErrorInvalidKey(t *testing.T) {
	f := newEncryptFixture(t)

	resultLen, _ := f.callEncryptRaw(t, "not-a-valid-pem", "https://kas.example.com", nil, []byte("test"), 1024*1024)
	if resultLen != 0 {
		t.Fatal("expected 0 for invalid PEM key")
	}
	errMsg := f.callGetError(t)
	if errMsg == "" {
		t.Fatal("expected error message for invalid key")
	}
}

func TestTDFEncryptErrorBufferTooSmall(t *testing.T) {
	f := newEncryptFixture(t)

	resultLen, _ := f.callEncryptRaw(t, f.pubPEM, "https://kas.example.com", nil, []byte("needs more space"), 10)
	if resultLen != 0 {
		t.Fatal("expected 0 for buffer too small")
	}
	errMsg := f.callGetError(t)
	if !strings.Contains(errMsg, "buffer too small") {
		t.Fatalf("expected 'buffer too small' error, got: %q", errMsg)
	}
}

func TestTDFEncryptGetErrorClearsAfterRead(t *testing.T) {
	f := newEncryptFixture(t)

	// Trigger an error
	resultLen, _ := f.callEncryptRaw(t, "bad-key", "https://kas.example.com", nil, []byte("x"), 1024*1024)
	if resultLen != 0 {
		t.Fatal("expected error")
	}

	// First read should return the error
	msg := f.callGetError(t)
	if msg == "" {
		t.Fatal("expected error message on first read")
	}

	// Second read should be empty (error cleared)
	msg2 := f.callGetError(t)
	if msg2 != "" {
		t.Fatalf("expected empty after clear, got: %q", msg2)
	}
}
