//nolint:forbidigo // We use Println here because we are printing results.
package cmd

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/sdk/experimental/tdf"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// ── WASM binary compilation (cached per process) ─────────────────────

var (
	wasmBinaryCache   []byte
	wasmBuildOnce     sync.Once
	wasmBuildCacheErr error
)

func compileWASMBinary() ([]byte, error) {
	wasmBuildOnce.Do(func() {
		dir, err := os.Getwd()
		if err != nil {
			wasmBuildCacheErr = fmt.Errorf("getwd: %w", err)
			return
		}
		for {
			if _, statErr := os.Stat(filepath.Join(dir, "go.work")); statErr == nil {
				break
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				wasmBuildCacheErr = fmt.Errorf("go.work not found")
				return
			}
			dir = parent
		}

		tmpFile, err := os.CreateTemp("", "tdf-wasm-verify-*.wasm")
		if err != nil {
			wasmBuildCacheErr = fmt.Errorf("create temp: %w", err)
			return
		}
		tmpPath := tmpFile.Name()
		tmpFile.Close()
		defer os.Remove(tmpPath)

		fmt.Print("   compiling WASM module ... ")
		cmd := exec.Command("go", "build", "-o", tmpPath, "./sdk/experimental/tdf/wasm/")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
		if output, err := cmd.CombinedOutput(); err != nil {
			wasmBuildCacheErr = fmt.Errorf("go build: %v\n%s", err, output)
			return
		}
		fmt.Println("done")

		wasmBinaryCache, wasmBuildCacheErr = os.ReadFile(tmpPath)
	})
	return wasmBinaryCache, wasmBuildCacheErr
}

// ── Inlined host module registration ─────────────────────────────────
//
// These functions replicate sdk/experimental/tdf/wasm/host/{crypto,io,host}.go
// to avoid importing that unpublished package. All crypto is delegated to
// lib/ocrypto, matching the WASM host ABI spec.

const wasmErrSentinel = 0xFFFFFFFF

var (
	wasmLastErrMu  sync.Mutex
	wasmLastErrMsg string
)

func wasmSetLastError(err error) {
	wasmLastErrMu.Lock()
	wasmLastErrMsg = err.Error()
	wasmLastErrMu.Unlock()
}

func wasmGetAndClearLastError() string {
	wasmLastErrMu.Lock()
	msg := wasmLastErrMsg
	wasmLastErrMsg = ""
	wasmLastErrMu.Unlock()
	return msg
}

func wasmReadBytes(mod api.Module, ptr, length uint32) []byte {
	if length == 0 {
		return nil
	}
	buf, ok := mod.Memory().Read(ptr, length)
	if !ok {
		return nil
	}
	return buf
}

func wasmWriteBytes(mod api.Module, ptr uint32, data []byte) bool {
	if len(data) == 0 {
		return true
	}
	return mod.Memory().Write(ptr, data)
}

type wasmHostErr string

func (e wasmHostErr) Error() string { return string(e) }

const (
	wasmErrOOB    wasmHostErr = "host: memory access out of bounds"
	wasmErrKey    wasmHostErr = "host: failed to read key from WASM memory"
	wasmErrCT     wasmHostErr = "host: failed to read ciphertext from WASM memory"
)

func registerCryptoHost(ctx context.Context, rt wazero.Runtime) error {
	_, err := rt.NewHostModuleBuilder("crypto").
		NewFunctionBuilder().WithFunc(wasmHostRandomBytes).Export("random_bytes").
		NewFunctionBuilder().WithFunc(wasmHostAesGcmEncrypt).Export("aes_gcm_encrypt").
		NewFunctionBuilder().WithFunc(wasmHostAesGcmDecrypt).Export("aes_gcm_decrypt").
		NewFunctionBuilder().WithFunc(wasmHostHmacSHA256).Export("hmac_sha256").
		NewFunctionBuilder().WithFunc(wasmHostRsaOaepSha1Encrypt).Export("rsa_oaep_sha1_encrypt").
		NewFunctionBuilder().WithFunc(wasmHostRsaOaepSha1Decrypt).Export("rsa_oaep_sha1_decrypt").
		NewFunctionBuilder().WithFunc(wasmHostRsaGenerateKeypair).Export("rsa_generate_keypair").
		NewFunctionBuilder().WithFunc(wasmHostGetLastError).Export("get_last_error").
		Instantiate(ctx)
	return err
}

func registerIOHost(ctx context.Context, rt wazero.Runtime) error {
	_, err := rt.NewHostModuleBuilder("io").
		NewFunctionBuilder().WithFunc(func(context.Context, api.Module, uint32, uint32) uint32 {
			return 0 // EOF — no input configured
		}).Export("read_input").
		NewFunctionBuilder().WithFunc(func(context.Context, api.Module, uint32, uint32) uint32 {
			wasmSetLastError(wasmHostErr("host: no output writer configured"))
			return wasmErrSentinel
		}).Export("write_output").
		Instantiate(ctx)
	return err
}

func wasmHostRandomBytes(_ context.Context, mod api.Module, outPtr, n uint32) uint32 {
	buf, err := ocrypto.RandomBytes(int(n))
	if err != nil {
		wasmSetLastError(err)
		return wasmErrSentinel
	}
	if !wasmWriteBytes(mod, outPtr, buf) {
		wasmSetLastError(wasmErrOOB)
		return wasmErrSentinel
	}
	return n
}

func wasmHostAesGcmEncrypt(_ context.Context, mod api.Module, keyPtr, keyLen, ptPtr, ptLen, outPtr uint32) uint32 {
	key := wasmReadBytes(mod, keyPtr, keyLen)
	pt := wasmReadBytes(mod, ptPtr, ptLen)
	if key == nil {
		wasmSetLastError(wasmErrKey)
		return wasmErrSentinel
	}
	aesGcm, err := ocrypto.NewAESGcm(key)
	if err != nil {
		wasmSetLastError(err)
		return wasmErrSentinel
	}
	ct, err := aesGcm.Encrypt(pt)
	if err != nil {
		wasmSetLastError(err)
		return wasmErrSentinel
	}
	if !wasmWriteBytes(mod, outPtr, ct) {
		wasmSetLastError(wasmErrOOB)
		return wasmErrSentinel
	}
	return uint32(len(ct))
}

func wasmHostAesGcmDecrypt(_ context.Context, mod api.Module, keyPtr, keyLen, ctPtr, ctLen, outPtr uint32) uint32 {
	key := wasmReadBytes(mod, keyPtr, keyLen)
	ct := wasmReadBytes(mod, ctPtr, ctLen)
	if key == nil {
		wasmSetLastError(wasmErrKey)
		return wasmErrSentinel
	}
	if ct == nil {
		wasmSetLastError(wasmErrCT)
		return wasmErrSentinel
	}
	aesGcm, err := ocrypto.NewAESGcm(key)
	if err != nil {
		wasmSetLastError(err)
		return wasmErrSentinel
	}
	pt, err := aesGcm.Decrypt(ct)
	if err != nil {
		wasmSetLastError(err)
		return wasmErrSentinel
	}
	if !wasmWriteBytes(mod, outPtr, pt) {
		wasmSetLastError(wasmErrOOB)
		return wasmErrSentinel
	}
	return uint32(len(pt))
}

func wasmHostHmacSHA256(_ context.Context, mod api.Module, keyPtr, keyLen, dataPtr, dataLen, outPtr uint32) uint32 {
	key := wasmReadBytes(mod, keyPtr, keyLen)
	data := wasmReadBytes(mod, dataPtr, dataLen)
	if key == nil {
		wasmSetLastError(wasmErrKey)
		return wasmErrSentinel
	}
	mac := ocrypto.CalculateSHA256Hmac(key, data)
	if !wasmWriteBytes(mod, outPtr, mac) {
		wasmSetLastError(wasmErrOOB)
		return wasmErrSentinel
	}
	return uint32(len(mac))
}

func wasmHostRsaOaepSha1Encrypt(_ context.Context, mod api.Module, pubPtr, pubLen, ptPtr, ptLen, outPtr uint32) uint32 {
	pubPEM := wasmReadBytes(mod, pubPtr, pubLen)
	pt := wasmReadBytes(mod, ptPtr, ptLen)
	if pubPEM == nil {
		wasmSetLastError(wasmErrKey)
		return wasmErrSentinel
	}
	enc, err := ocrypto.NewAsymEncryption(string(pubPEM))
	if err != nil {
		wasmSetLastError(err)
		return wasmErrSentinel
	}
	ct, err := enc.Encrypt(pt)
	if err != nil {
		wasmSetLastError(err)
		return wasmErrSentinel
	}
	if !wasmWriteBytes(mod, outPtr, ct) {
		wasmSetLastError(wasmErrOOB)
		return wasmErrSentinel
	}
	return uint32(len(ct))
}

func wasmHostRsaOaepSha1Decrypt(_ context.Context, mod api.Module, privPtr, privLen, ctPtr, ctLen, outPtr uint32) uint32 {
	privPEM := wasmReadBytes(mod, privPtr, privLen)
	ct := wasmReadBytes(mod, ctPtr, ctLen)
	if privPEM == nil {
		wasmSetLastError(wasmErrKey)
		return wasmErrSentinel
	}
	if ct == nil {
		wasmSetLastError(wasmErrCT)
		return wasmErrSentinel
	}
	dec, err := ocrypto.NewAsymDecryption(string(privPEM))
	if err != nil {
		wasmSetLastError(err)
		return wasmErrSentinel
	}
	pt, err := dec.Decrypt(ct)
	if err != nil {
		wasmSetLastError(err)
		return wasmErrSentinel
	}
	if !wasmWriteBytes(mod, outPtr, pt) {
		wasmSetLastError(wasmErrOOB)
		return wasmErrSentinel
	}
	return uint32(len(pt))
}

func wasmHostRsaGenerateKeypair(_ context.Context, mod api.Module, bits, privOut, pubOut, pubLenPtr uint32) uint32 {
	kp, err := ocrypto.NewRSAKeyPair(int(bits))
	if err != nil {
		wasmSetLastError(err)
		return wasmErrSentinel
	}
	privPEM, err := kp.PrivateKeyInPemFormat()
	if err != nil {
		wasmSetLastError(err)
		return wasmErrSentinel
	}
	pubPEM, err := kp.PublicKeyInPemFormat()
	if err != nil {
		wasmSetLastError(err)
		return wasmErrSentinel
	}
	privBytes := []byte(privPEM)
	pubBytes := []byte(pubPEM)
	if !wasmWriteBytes(mod, privOut, privBytes) || !wasmWriteBytes(mod, pubOut, pubBytes) {
		wasmSetLastError(wasmErrOOB)
		return wasmErrSentinel
	}
	var pubLenLE [4]byte
	binary.LittleEndian.PutUint32(pubLenLE[:], uint32(len(pubBytes)))
	if !wasmWriteBytes(mod, pubLenPtr, pubLenLE[:]) {
		wasmSetLastError(wasmErrOOB)
		return wasmErrSentinel
	}
	return uint32(len(privBytes))
}

func wasmHostGetLastError(_ context.Context, mod api.Module, outPtr, outCapacity uint32) uint32 {
	msg := wasmGetAndClearLastError()
	if msg == "" {
		return 0
	}
	msgBytes := []byte(msg)
	if uint32(len(msgBytes)) > outCapacity {
		msgBytes = msgBytes[:outCapacity]
	}
	if !wasmWriteBytes(mod, outPtr, msgBytes) {
		return 0
	}
	return uint32(len(msgBytes))
}

// ── WASM runtime ─────────────────────────────────────────────────────

type wasmRuntime struct {
	ctx context.Context
	mod api.Module
	rt  wazero.Runtime
}

func newWASMRuntime(ctx context.Context) (*wasmRuntime, error) {
	wasmBytes, err := compileWASMBinary()
	if err != nil {
		return nil, fmt.Errorf("compile WASM: %w", err)
	}

	rt := wazero.NewRuntime(ctx)

	// Register WASI with proc_exit override to keep module alive after
	// main() returns (Go wasip1 calls proc_exit(0)).
	builder := rt.NewHostModuleBuilder("wasi_snapshot_preview1")
	wasi_snapshot_preview1.NewFunctionExporter().ExportFunctions(builder)
	builder.NewFunctionBuilder().
		WithFunc(func(_ context.Context, _ api.Module, code uint32) {
			panic(fmt.Sprintf("proc_exit(%d)", code))
		}).Export("proc_exit")
	if _, err := builder.Instantiate(ctx); err != nil {
		rt.Close(ctx) //nolint:errcheck
		return nil, fmt.Errorf("register WASI: %w", err)
	}

	if err := registerCryptoHost(ctx, rt); err != nil {
		rt.Close(ctx) //nolint:errcheck
		return nil, fmt.Errorf("register crypto host: %w", err)
	}
	if err := registerIOHost(ctx, rt); err != nil {
		rt.Close(ctx) //nolint:errcheck
		return nil, fmt.Errorf("register IO host: %w", err)
	}

	compiled, err := rt.CompileModule(ctx, wasmBytes)
	if err != nil {
		rt.Close(ctx) //nolint:errcheck
		return nil, fmt.Errorf("compile module: %w", err)
	}

	cfg := wazero.NewModuleConfig().
		WithStdout(io.Discard).
		WithStderr(io.Discard).
		WithStartFunctions() // skip _start — call manually below
	mod, err := rt.InstantiateModule(ctx, compiled, cfg)
	if err != nil {
		rt.Close(ctx) //nolint:errcheck
		return nil, fmt.Errorf("instantiate module: %w", err)
	}

	// Call _start manually; proc_exit panic is expected.
	_, startErr := mod.ExportedFunction("_start").Call(ctx)
	if startErr != nil {
		if !strings.Contains(startErr.Error(), "proc_exit") {
			rt.Close(ctx) //nolint:errcheck
			return nil, fmt.Errorf("unexpected _start error: %w", startErr)
		}
	}

	return &wasmRuntime{ctx: ctx, mod: mod, rt: rt}, nil
}

func (w *wasmRuntime) Close() {
	w.rt.Close(w.ctx) //nolint:errcheck
}

func (w *wasmRuntime) malloc(size uint32) (uint32, error) {
	results, err := w.mod.ExportedFunction("tdf_malloc").Call(w.ctx, uint64(size))
	if err != nil {
		return 0, fmt.Errorf("tdf_malloc(%d): %w", size, err)
	}
	return uint32(results[0]), nil
}

func (w *wasmRuntime) writeToWASM(data []byte) (uint32, error) {
	if len(data) == 0 {
		return 0, nil
	}
	ptr, err := w.malloc(uint32(len(data)))
	if err != nil {
		return 0, err
	}
	if !w.mod.Memory().Write(ptr, data) {
		return 0, fmt.Errorf("write %d bytes at WASM offset %d", len(data), ptr)
	}
	return ptr, nil
}

func (w *wasmRuntime) wasmGetError() string {
	const bufCap = 1024
	bufPtr, err := w.malloc(bufCap)
	if err != nil {
		return "malloc for error buffer: " + err.Error()
	}
	results, err := w.mod.ExportedFunction("get_error").Call(w.ctx, uint64(bufPtr), uint64(bufCap))
	if err != nil {
		return "get_error call: " + err.Error()
	}
	n := uint32(results[0])
	if n == 0 {
		return ""
	}
	msg, ok := w.mod.Memory().Read(bufPtr, n)
	if !ok {
		return "read error message from WASM memory"
	}
	return string(msg)
}

// decrypt calls the WASM tdf_decrypt export.
func (w *wasmRuntime) decrypt(tdfBytes, dek []byte) ([]byte, error) {
	tdfPtr, err := w.writeToWASM(tdfBytes)
	if err != nil {
		return nil, fmt.Errorf("write TDF to WASM: %w", err)
	}
	dekPtr, err := w.writeToWASM(dek)
	if err != nil {
		return nil, fmt.Errorf("write DEK to WASM: %w", err)
	}
	// Output buffer sized to TDF input — plaintext is always smaller.
	outCap := uint32(len(tdfBytes))
	outPtr, err := w.malloc(outCap)
	if err != nil {
		return nil, fmt.Errorf("malloc output: %w", err)
	}

	results, err := w.mod.ExportedFunction("tdf_decrypt").Call(w.ctx,
		uint64(tdfPtr), uint64(len(tdfBytes)),
		uint64(dekPtr), uint64(len(dek)),
		uint64(outPtr), uint64(outCap),
	)
	if err != nil {
		return nil, fmt.Errorf("tdf_decrypt call: %w", err)
	}
	resultLen := uint32(results[0])
	if resultLen == 0 {
		if errMsg := w.wasmGetError(); errMsg != "" {
			return nil, fmt.Errorf("tdf_decrypt: %s", errMsg)
		}
		return nil, nil // empty plaintext
	}
	ptBytes, ok := w.mod.Memory().Read(outPtr, resultLen)
	if !ok {
		return nil, fmt.Errorf("read plaintext from WASM memory")
	}
	out := make([]byte, len(ptBytes))
	copy(out, ptBytes)
	return out, nil
}

// encrypt calls the WASM tdf_encrypt export.
func (w *wasmRuntime) encrypt(kasPubPEM, kasURL string, plaintext []byte, segmentSize uint32) ([]byte, error) {
	kasPubPtr, err := w.writeToWASM([]byte(kasPubPEM))
	if err != nil {
		return nil, fmt.Errorf("write KAS pub PEM to WASM: %w", err)
	}
	kasURLPtr, err := w.writeToWASM([]byte(kasURL))
	if err != nil {
		return nil, fmt.Errorf("write KAS URL to WASM: %w", err)
	}
	ptPtr, err := w.writeToWASM(plaintext)
	if err != nil {
		return nil, fmt.Errorf("write plaintext to WASM: %w", err)
	}

	// Output buffer: TDF overhead is modest; 2x plaintext + 64KB should suffice.
	outCap := uint32(len(plaintext)*2 + 65536) //nolint:mnd
	outPtr, err := w.malloc(outCap)
	if err != nil {
		return nil, fmt.Errorf("malloc output: %w", err)
	}

	const (
		algHS256     = 0
		attrPtrZero  = 0
		attrLenZero  = 0
	)

	results, callErr := w.mod.ExportedFunction("tdf_encrypt").Call(w.ctx,
		uint64(kasPubPtr), uint64(len(kasPubPEM)),
		uint64(kasURLPtr), uint64(len(kasURL)),
		uint64(attrPtrZero), uint64(attrLenZero), // no attributes
		uint64(ptPtr), uint64(len(plaintext)),
		uint64(outPtr), uint64(outCap),
		uint64(algHS256), uint64(algHS256), // HS256 for root + segment integrity
		uint64(segmentSize),
	)
	if callErr != nil {
		return nil, fmt.Errorf("tdf_encrypt call: %w", callErr)
	}
	resultLen := uint32(results[0])
	if resultLen == 0 {
		if errMsg := w.wasmGetError(); errMsg != "" {
			return nil, fmt.Errorf("tdf_encrypt: %s", errMsg)
		}
		return nil, fmt.Errorf("tdf_encrypt returned 0 bytes with no error")
	}
	tdfBytes, ok := w.mod.Memory().Read(outPtr, resultLen)
	if !ok {
		return nil, fmt.Errorf("read TDF output from WASM memory")
	}
	out := make([]byte, len(tdfBytes))
	copy(out, tdfBytes)
	return out, nil
}

// ── TDF creation + DEK extraction helpers ────────────────────────────

// createTDFWithLocalKey creates a TDF using the experimental Writer with the
// given RSA public key (local, not from KAS). Returns the TDF bytes.
func createTDFWithLocalKey(pubPEM string, payload []byte, segmentSize int) ([]byte, error) {
	ctx := context.Background()
	writer, err := tdf.NewWriter(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewWriter: %w", err)
	}

	var tdfBuf bytes.Buffer
	if segmentSize <= 0 || segmentSize >= len(payload) {
		chunk := make([]byte, len(payload))
		copy(chunk, payload)
		seg, err := writer.WriteSegment(ctx, 0, chunk)
		if err != nil {
			return nil, fmt.Errorf("WriteSegment: %w", err)
		}
		if _, err := io.Copy(&tdfBuf, seg.TDFData); err != nil {
			return nil, fmt.Errorf("copy segment data: %w", err)
		}
	} else {
		offset := 0
		for i := 0; offset < len(payload); i++ {
			end := offset + segmentSize
			if end > len(payload) {
				end = len(payload)
			}
			chunk := make([]byte, end-offset)
			copy(chunk, payload[offset:end])
			seg, err := writer.WriteSegment(ctx, i, chunk)
			if err != nil {
				return nil, fmt.Errorf("WriteSegment(%d): %w", i, err)
			}
			if _, err := io.Copy(&tdfBuf, seg.TDFData); err != nil {
				return nil, fmt.Errorf("copy segment %d data: %w", i, err)
			}
			offset = end
		}
	}

	kasKey := &policy.SimpleKasKey{
		KasUri: "https://kas.local",
		PublicKey: &policy.SimpleKasPublicKey{
			Algorithm: policy.Algorithm_ALGORITHM_RSA_2048,
			Kid:       "local-test",
			Pem:       pubPEM,
		},
	}
	fin, err := writer.Finalize(ctx, tdf.WithDefaultKAS(kasKey))
	if err != nil {
		return nil, fmt.Errorf("Finalize: %w", err)
	}
	tdfBuf.Write(fin.Data)
	return tdfBuf.Bytes(), nil
}

// unwrapDEKLocal RSA-decrypts the wrapped key from a TDF manifest using a local
// private key, returning the 32-byte DEK.
func unwrapDEKLocal(tdfBytes []byte, privPEM string) ([]byte, error) {
	r, err := zip.NewReader(bytes.NewReader(tdfBytes), int64(len(tdfBytes)))
	if err != nil {
		return nil, fmt.Errorf("parse TDF ZIP: %w", err)
	}

	var manifestRaw []byte
	for _, f := range r.File {
		if f.Name == "0.manifest.json" {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("open manifest entry: %w", err)
			}
			manifestRaw, err = io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return nil, fmt.Errorf("read manifest: %w", err)
			}
			break
		}
	}
	if manifestRaw == nil {
		return nil, fmt.Errorf("0.manifest.json not found in TDF ZIP")
	}

	var manifest tdf.Manifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if len(manifest.KeyAccessObjs) == 0 {
		return nil, fmt.Errorf("no key access objects in manifest")
	}

	wrappedKey, err := base64.StdEncoding.DecodeString(manifest.KeyAccessObjs[0].WrappedKey)
	if err != nil {
		return nil, fmt.Errorf("decode wrapped key: %w", err)
	}
	dec, err := ocrypto.NewAsymDecryption(privPEM)
	if err != nil {
		return nil, fmt.Errorf("create RSA decryptor: %w", err)
	}
	dek, err := dec.Decrypt(wrappedKey)
	if err != nil {
		return nil, fmt.Errorf("RSA-unwrap DEK: %w", err)
	}
	if len(dek) != 32 { //nolint:mnd
		return nil, fmt.Errorf("DEK length: got %d, want 32", len(dek))
	}
	return dek, nil
}

// ── Verification functions ───────────────────────────────────────────

// verifyWriterToWASM creates a TDF via the experimental Writer with a local key
// pair, unwraps the DEK, and decrypts through the WASM module via wazero.
func verifyWriterToWASM(wrt *wasmRuntime, payload []byte) error {
	kp, err := ocrypto.NewRSAKeyPair(2048) //nolint:mnd
	if err != nil {
		return fmt.Errorf("generate RSA keypair: %w", err)
	}
	pubPEM, err := kp.PublicKeyInPemFormat()
	if err != nil {
		return fmt.Errorf("public key PEM: %w", err)
	}
	privPEM, err := kp.PrivateKeyInPemFormat()
	if err != nil {
		return fmt.Errorf("private key PEM: %w", err)
	}

	tdfBytes, err := createTDFWithLocalKey(pubPEM, payload, 0)
	if err != nil {
		return fmt.Errorf("create TDF: %w", err)
	}
	dek, err := unwrapDEKLocal(tdfBytes, privPEM)
	if err != nil {
		return fmt.Errorf("unwrap DEK: %w", err)
	}
	decrypted, err := wrt.decrypt(tdfBytes, dek)
	if err != nil {
		return fmt.Errorf("WASM decrypt: %w", err)
	}
	if !bytes.Equal(decrypted, payload) {
		return fmt.Errorf("plaintext mismatch: got %d bytes, want %d bytes", len(decrypted), len(payload))
	}
	return nil
}

// verifyWriterMultiSegToWASM creates a multi-segment TDF via the experimental
// Writer and decrypts through the WASM module via wazero.
func verifyWriterMultiSegToWASM(wrt *wasmRuntime, payload []byte) error {
	kp, err := ocrypto.NewRSAKeyPair(2048) //nolint:mnd
	if err != nil {
		return fmt.Errorf("generate RSA keypair: %w", err)
	}
	pubPEM, err := kp.PublicKeyInPemFormat()
	if err != nil {
		return fmt.Errorf("public key PEM: %w", err)
	}
	privPEM, err := kp.PrivateKeyInPemFormat()
	if err != nil {
		return fmt.Errorf("private key PEM: %w", err)
	}

	segSize := len(payload) / 3 //nolint:mnd // split into ~3 segments
	if segSize < 1 {
		segSize = 1
	}
	tdfBytes, err := createTDFWithLocalKey(pubPEM, payload, segSize)
	if err != nil {
		return fmt.Errorf("create TDF: %w", err)
	}
	dek, err := unwrapDEKLocal(tdfBytes, privPEM)
	if err != nil {
		return fmt.Errorf("unwrap DEK: %w", err)
	}
	decrypted, err := wrt.decrypt(tdfBytes, dek)
	if err != nil {
		return fmt.Errorf("WASM decrypt: %w", err)
	}
	if !bytes.Equal(decrypted, payload) {
		return fmt.Errorf("plaintext mismatch: got %d bytes, want %d bytes", len(decrypted), len(payload))
	}
	return nil
}
