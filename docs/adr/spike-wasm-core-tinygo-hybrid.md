# SDK-WASM-1: Spike — TinyGo Hybrid WASM Core Engine

**Status:** Draft
**Time box:** 2 weeks (10 working days)
**Depends on:** None
**Blocks:** SDK-WASM-2, SDK-WASM-3, SDK-WASM-4
**CI Canary:** `.github/workflows/tinygo-wasm-canary.yaml` (informational, not blocking)

---

## Objective

Validate that a TinyGo-compiled WASM module can perform TDF3 single-segment
encrypt/decrypt with all crypto delegated to host functions, producing output
that the existing Go SDK can consume.

---

## Go / No-Go Criteria

| # | Question | Pass Threshold |
|---|----------|----------------|
| 1 | TinyGo compiles TDF logic to WASM? | Clean build, no runtime panics |
| 2 | Host crypto callbacks work across WASM boundary? | All 8 host functions round-trip correctly |
| 3 | Binary size acceptable? | < 300KB gzipped |
| 4 | Output is a valid TDF? | Go SDK `LoadTDF` → `Reader.Read` decrypts it |
| 5 | Performance acceptable? | Encrypt throughput within 3x of native Go SDK |

---

## Architecture Under Test

```
┌───────────────────────────────────────────────────────────────┐
│               TinyGo WASM Module (target: ~100-150KB gz)      │
│                                                               │
│  //go:wasmexport tdf_encrypt                                  │
│  //go:wasmexport tdf_decrypt_manifest                         │
│  //go:wasmexport tdf_decrypt_segment                          │
│  //go:wasmexport malloc                                       │
│  //go:wasmexport free                                         │
│                                                               │
│  Internal:                                                    │
│    ├── Manifest structs + tinyjson codegen                    │
│    ├── Policy object construction                             │
│    ├── Key XOR split/merge                                    │
│    ├── Segment bookkeeping + integrity check                  │
│    ├── ZIP archive writer (zipstream)                         │
│    └── encoding/base64 (TinyGo-native, no host call)          │
│                                                               │
│  //go:wasmimport crypto random_bytes                          │
│  //go:wasmimport crypto aes_gcm_encrypt                       │
│  //go:wasmimport crypto aes_gcm_decrypt                       │
│  //go:wasmimport crypto hmac_sha256                           │
│  //go:wasmimport crypto rsa_oaep_sha1_encrypt                 │
│  //go:wasmimport crypto rsa_oaep_sha1_decrypt                 │
│  //go:wasmimport crypto rsa_generate_keypair                  │
│  //go:wasmimport crypto get_last_error                        │
└──────────────────────────┬────────────────────────────────────┘
                           │ shared linear memory
             ┌─────────────┼──────────────┐
             ▼             ▼              ▼
       ┌──────────┐  ┌──────────┐  ┌───────────┐
       │ Browser  │  │ Wazero   │  │ wasmtime  │
       │ host.js  │  │ host.go  │  │ host.py   │
       │ (stretch)│  │ (spike)  │  │ (future)  │
       └──────────┘  └──────────┘  └───────────┘
```

---

## Host Function ABI

### Conventions

**Data exchange:** Shared linear memory. WASM module exports `malloc`/`free`.
Caller allocates output buffers in WASM memory before invoking host functions.

**Parameter types:** `go:wasmimport` only supports primitives
(`uint32`, `int32`, `uint64`, `int64`, `float32`, `float64`, `uintptr`).
All byte data passed as `(ptr, len)` pairs pointing into WASM linear memory.

**Error reporting:** Host functions return `uint32` result length on success,
or `0xFFFFFFFF` (max uint32) on error. On error, call `get_last_error` to
retrieve a UTF-8 error message.

**Output sizing:** Callers must pre-allocate sufficient output buffers.
Known output sizes:

| Operation | Output size |
|-----------|-------------|
| `random_bytes` | Exactly `n` bytes requested |
| `aes_gcm_encrypt` | `input_len + 12 (nonce) + 16 (tag)` |
| `aes_gcm_decrypt` | `input_len - 12 (nonce) - 16 (tag)` |
| `hmac_sha256` | Exactly 32 bytes |
| `rsa_oaep_sha1_encrypt` | Key size in bytes (e.g., 256 for RSA-2048) |
| `rsa_oaep_sha1_decrypt` | ≤ key size in bytes |
| `rsa_generate_keypair` | Variable (PEM-encoded); use 4096-byte buffer |

### Spike Functions (8)

```go
// ── Random ──────────────────────────────────────────────────

// Fills out_ptr with n cryptographically random bytes.
// Returns: n on success, 0xFFFFFFFF on error.
//go:wasmimport crypto random_bytes
func _random_bytes(out_ptr, n uint32) uint32

// ── AES-256-GCM (one-shot) ─────────────────────────────────

// Encrypts plaintext with AES-256-GCM.
// Writes [nonce (12) || ciphertext || tag (16)] to out_ptr.
// Returns: output length on success, 0xFFFFFFFF on error.
//go:wasmimport crypto aes_gcm_encrypt
func _aes_gcm_encrypt(
    key_ptr, key_len uint32,    // 32 bytes (AES-256)
    pt_ptr, pt_len uint32,      // plaintext
    out_ptr uint32,              // pre-allocated: pt_len + 28
) uint32

// Decrypts AES-256-GCM ciphertext.
// Input: [nonce (12) || ciphertext || tag (16)].
// Writes plaintext to out_ptr.
// Returns: plaintext length on success, 0xFFFFFFFF on error.
//go:wasmimport crypto aes_gcm_decrypt
func _aes_gcm_decrypt(
    key_ptr, key_len uint32,    // 32 bytes (AES-256)
    ct_ptr, ct_len uint32,      // nonce || ciphertext || tag
    out_ptr uint32,              // pre-allocated: ct_len - 28
) uint32

// ── HMAC-SHA256 ─────────────────────────────────────────────

// Computes HMAC-SHA256. Writes 32 bytes to out_ptr.
// Returns: 32 on success, 0xFFFFFFFF on error.
//go:wasmimport crypto hmac_sha256
func _hmac_sha256(
    key_ptr, key_len uint32,
    data_ptr, data_len uint32,
    out_ptr uint32,              // pre-allocated: 32 bytes
) uint32

// ── RSA-OAEP-SHA1 ──────────────────────────────────────────

// Encrypts with RSA-OAEP (SHA-1 hash, SHA-1 MGF1).
// pub_pem_ptr: PEM-encoded RSA public key.
// Returns: ciphertext length on success, 0xFFFFFFFF on error.
//go:wasmimport crypto rsa_oaep_sha1_encrypt
func _rsa_oaep_sha1_encrypt(
    pub_pem_ptr, pub_pem_len uint32,
    pt_ptr, pt_len uint32,       // plaintext (≤ key_size - 42 bytes)
    out_ptr uint32,               // pre-allocated: key_size bytes
) uint32

// Decrypts with RSA-OAEP (SHA-1 hash, SHA-1 MGF1).
// priv_pem_ptr: PEM-encoded RSA private key.
// Returns: plaintext length on success, 0xFFFFFFFF on error.
//go:wasmimport crypto rsa_oaep_sha1_decrypt
func _rsa_oaep_sha1_decrypt(
    priv_pem_ptr, priv_pem_len uint32,
    ct_ptr, ct_len uint32,
    out_ptr uint32,               // pre-allocated: key_size bytes
) uint32

// ── RSA Key Generation ──────────────────────────────────────

// Generates RSA-2048 keypair. Writes PEM-encoded private key
// to priv_out_ptr, public key to pub_out_ptr.
// Returns: private key PEM length on success, 0xFFFFFFFF on error.
// Public key length written to pub_len_ptr (uint32, little-endian).
//go:wasmimport crypto rsa_generate_keypair
func _rsa_generate_keypair(
    bits uint32,                  // 2048
    priv_out_ptr uint32,          // pre-allocated: 4096 bytes
    pub_out_ptr uint32,           // pre-allocated: 4096 bytes
    pub_len_ptr uint32,           // 4 bytes; host writes pub key length here
) uint32

// ── Error Handling ──────────────────────────────────────────

// Retrieves last error message (UTF-8). Returns message length,
// or 0 if no error. Clears the error after reading.
//go:wasmimport crypto get_last_error
func _get_last_error(out_ptr, out_capacity uint32) uint32
```

### Future EC Functions (not in spike)

These are needed for EC-wrapped TDFs and EC-mode KAS sessions:

```go
// ── EC Operations (post-spike) ──────────────────────────────

// Generate ephemeral EC keypair (P-256/P-384/P-521).
//go:wasmimport crypto ec_generate_keypair
func _ec_generate_keypair(curve uint32, priv_out, pub_out, pub_len_ptr uint32) uint32

// ECDH shared secret derivation.
//go:wasmimport crypto ecdh_derive
func _ecdh_derive(priv_pem_ptr, priv_pem_len, pub_pem_ptr, pub_pem_len, out_ptr uint32) uint32

// HKDF-SHA256 key derivation.
//go:wasmimport crypto hkdf_sha256
func _hkdf_sha256(salt_ptr, salt_len, ikm_ptr, ikm_len, info_ptr, info_len, out_ptr, out_len uint32) uint32
```

---

## What Stays Inside the WASM Module

These operations use only TinyGo-compatible stdlib packages and need no
host delegation:

| Operation | Package | TinyGo Status |
|-----------|---------|---------------|
| Base64 encode/decode | `encoding/base64` | Passes all tests |
| Hex encode/decode | `encoding/hex` | Passes all tests |
| CRC32 (ZIP integrity) | `hash/crc32` | Likely works (no reflect) |
| ZIP archive writing | `encoding/binary`, `bytes`, `io` | Importable; validated in Phase 1 |
| JSON marshal/unmarshal | tinyjson (codegen) | Designed for TinyGo WASM |
| Key XOR split/merge | `^` byte operator | No imports needed |
| Segment bookkeeping | `sort`, `sync` | `sync` passes; `sort.Ints` works |
| GMAC extraction | Byte slice `[len-16:]` | No imports needed |
| UUID generation | Host-provided or hardcoded | Avoid `google/uuid` dep |

---

## Task Breakdown

### Phase 1: Foundation (Days 1-3)

#### Task 1.1 — Scaffold WASM module project

- New directory: `sdk/experimental/tdf/`
- `go.mod` targeting TinyGo-compatible deps only
- Makefile targets:

  ```makefile
  tinygo-build:
      tinygo build -o tdfcore.wasm -target=wasip1 \
          -no-debug -scheduler=none -gc=leaking
  wasm-opt:
      wasm-opt -Oz tdfcore.wasm -o tdfcore.opt.wasm
  size-check:
      @ls -la tdfcore.wasm tdfcore.opt.wasm
      @gzip -k -f tdfcore.opt.wasm
      @ls -la tdfcore.opt.wasm.gz
  ```

- WASM exports: `malloc`, `free`, plus TDF entry points
- **Deliverable:** Empty module compiles with TinyGo, measure baseline size

#### Task 1.2 — Extract and adapt manifest structs

- Copy manifest structs from `sdk/manifest.go` (~10 structs)
- Add `//go:generate tinyjson -all manifest.go`
- Run tinyjson codegen, verify marshal/unmarshal round-trip
- Validate: struct tags (`json:"..."`, `omitempty`) produce correct output
- Note: tinyjson is **case-sensitive** (unlike `encoding/json`); verify
  existing manifests parse correctly
- **Deliverable:** TinyGo builds module with manifest JSON round-trip passing

#### Task 1.3 — Extract and adapt zipstream writer

- Copy `sdk/internal/zipstream/` (segment_writer, zip_headers,
  zip_primitives, crc32combine)
- Remove any TinyGo-incompatible imports
- Test: produce a ZIP under TinyGo, verify `archive/zip` (std Go) can read it
- Validate `encoding/binary.Write` with `binary.LittleEndian` works
- Validate `hash/crc32.ChecksumIEEE` works
- **Deliverable:** TinyGo-compiled module produces valid ZIP files

**Day 3 checkpoint:** Module compiles, marshals manifests, writes ZIPs.
Measure binary size (expecting ~80-200KB gzipped with no crypto).

---

### Phase 2: Host Crypto Interface (Days 4-6)

#### Task 2.1 — Define shared memory helpers

WASM-side Go wrappers that hide pointer arithmetic:

```go
// Example wrapper
func RandomBytes(n int) ([]byte, error) {
    buf := make([]byte, n)
    ptr := uintptr(unsafe.Pointer(&buf[0]))
    result := _random_bytes(uint32(ptr), uint32(n))
    if result == 0xFFFFFFFF {
        return nil, getLastError()
    }
    return buf, nil
}

func AesGcmEncrypt(key, plaintext []byte) ([]byte, error) {
    outLen := len(plaintext) + 28 // nonce + tag
    out := make([]byte, outLen)
    result := _aes_gcm_encrypt(
        uint32(uintptr(unsafe.Pointer(&key[0]))), uint32(len(key)),
        uint32(uintptr(unsafe.Pointer(&plaintext[0]))), uint32(len(plaintext)),
        uint32(uintptr(unsafe.Pointer(&out[0]))),
    )
    if result == 0xFFFFFFFF {
        return nil, getLastError()
    }
    return out[:result], nil
}
```

- Wrapper for each of the 8 host functions
- Clean Go API matching current ocrypto signatures where possible
- **Deliverable:** `sdk/experimental/tdf/hostcrypto/` package with typed Go wrappers

#### Task 2.2 — Implement Wazero host (Go)

- New directory: `sdk/experimental/tdf/host/wazero/`
- Register host module `crypto` with all 8 functions
- Implementation delegates to Go `crypto/*` and `lib/ocrypto`
- Unit test each function: call from WASM, compare output to
  `lib/ocrypto` equivalent
- **Deliverable:** All 8 host functions pass individual round-trip tests

#### Task 2.3 — Implement browser host (JS) *(stretch goal)*

- `sdk/experimental/tdf/host/browser/host.js`
- `random_bytes` → `crypto.getRandomValues()`
- `aes_gcm_encrypt/decrypt` → `SubtleCrypto.encrypt/decrypt`
  with `AES-GCM` algorithm
- `hmac_sha256` → `SubtleCrypto.sign` with `HMAC`/`SHA-256`
- `rsa_oaep_sha1_encrypt/decrypt` → `SubtleCrypto.encrypt/decrypt`
  with `RSA-OAEP` (note: SHA-1 requires explicit `hash: "SHA-1"`)
- `rsa_generate_keypair` → `SubtleCrypto.generateKey`
  with `RSA-OAEP`, 2048 bits, export as PEM via `exportKey("pkcs8")`
  and `exportKey("spki")`
- Caveat: SubtleCrypto is async; host must use sync bridge
  (SharedArrayBuffer + Atomics) or pre-compute
- **Deliverable:** Browser host passes same unit tests as Wazero host

**Day 6 checkpoint:** All 8 host functions verified individually in Wazero.
Browser host stretch goal either done or documented as feasible.

---

### Phase 3: TDF Encrypt + Round-Trip (Days 7-8)

#### Task 3.1 — Implement single-segment TDF3 encrypt

Exported WASM function:
```go
//go:wasmexport tdf_encrypt
func tdfEncrypt(
    kas_pub_pem_ptr, kas_pub_pem_len uint32,
    kas_url_ptr, kas_url_len uint32,
    attr_ptr, attr_len uint32,
    pt_ptr, pt_len uint32,
    out_ptr, out_capacity uint32,
) uint32
```

Minimal encrypt path (~200-300 lines new code):

1. `RandomBytes(32)` → DEK
2. `RsaOaepSha1Encrypt(kas_pub_pem, DEK)` → wrapped key
3. Build policy object JSON (tinyjson)
4. `base64.StdEncoding.Encode(policy_json)` → policy string (WASM-native)
5. `HmacSha256(DEK, policy_b64)` → policy binding
6. Build KeyAccess struct
7. `AesGcmEncrypt(DEK, plaintext)` → ciphertext
8. `HmacSha256(DEK, ciphertext)` → segment signature (HS256 mode)
9. `HmacSha256(DEK, aggregate_hash)` → root signature
10. Marshal manifest (tinyjson)
11. Write ZIP (zipstream): `0.payload` + `0.manifest.json`
12. Return TDF bytes

#### Task 3.2 — Round-trip validation

Go test using Wazero:

```go
func TestWASMEncrypt_GoDecrypt(t *testing.T) {
    // 1. Load WASM module in Wazero with crypto host
    // 2. Call tdf_encrypt with test plaintext + KAS public key
    // 3. Decrypt with sdk.LoadTDF() + Reader.Read()
    // 4. Assert plaintext matches
    // 5. Assert manifest parses and validates
}
```

- Test vectors: 0 bytes, 1 byte, 1KB, 1MB, 4MB (max segment)
- Verify manifest JSON is schema-valid
- Verify segment integrity hashes are correct
- Verify policy binding matches

**Day 8 checkpoint:** WASM-produced TDF decrypts with Go SDK. All test
vectors pass.

---

### Phase 4: Measurement & Report (Days 9-10)

#### Task 4.1 — Binary size measurement

| Build variant | Measure |
|---------------|---------|
| `tinygo build -no-debug -scheduler=none` | Raw `.wasm` |
| + `wasm-opt -Oz` | Optimized |
| + `gzip -9` | Gzipped |
| + `brotli -9` | Brotli |

Also measure per-component contribution:
- Baseline (empty main + malloc/free)
- + tinyjson runtime
- + zipstream
- + manifest structs
- + TDF encrypt logic

#### Task 4.2 — Performance benchmark

| Payload | Metric | WASM (Wazero) | Native Go SDK | Ratio |
|---------|--------|---------------|---------------|-------|
| 1 KB | Encrypt latency | | | |
| 1 MB | Encrypt throughput | | | |
| 4 MB | Encrypt throughput | | | |
| 1 MB | Memory high-water | | | |

Profile time split: host functions vs TDF logic vs JSON marshal vs ZIP write.

#### Task 4.3 — Write spike findings

**Deliverable:** Update this document with results and go/no-go decision.

```markdown
## Results

### Go / No-Go Decision: [GO | NO-GO]

### Binary Size
| Variant          | Size     |
|------------------|----------|
| Raw WASM         | ___ KB   |
| wasm-opt -Oz     | ___ KB   |
| Gzipped          | ___ KB   |
| Brotli           | ___ KB   |

### Correctness
- TDF round-trip:              [PASS | FAIL]
- Manifest schema validation:  [PASS | FAIL]
- All test vectors:            [PASS | FAIL]

### Performance
| Payload | WASM (Wazero) | Native Go | Ratio |
|---------|---------------|-----------|-------|

### Risks Identified
1. ...

### Recommendation for M2
...
```

---

## Explicitly Out of Scope

| Excluded | Rationale |
|----------|-----------|
| NanoTDF | Same primitives as TDF3; validates with TDF3 |
| EC key wrapping | RSA is simpler; EC adds 3 host functions but same pattern |
| Decrypt inside WASM | Round-trip proved by Go SDK decrypt; WASM decrypt is M2 |
| KAS communication | Out of WASM scope per architecture (host callback) |
| Assertions | Optional manifest feature; doesn't affect core feasibility |
| Multi-segment TDF | Single segment proves the pattern; multi is just a loop |
| Browser host | Stretch goal; Wazero host sufficient for go/no-go |
| Streaming AES-GCM | TDF code is one-shot per segment; WebCrypto has no streaming GCM |
| Python/Java hosts | Future milestone; Wazero proves the embedding pattern |

---

## Dependencies & Prerequisites

| Need | Install | Blocking? |
|------|---------|-----------|
| TinyGo ≥ 0.40 | `brew install tinygo` | Yes |
| Wazero | `go get github.com/tetratelabs/wazero` | Yes |
| tinyjson codegen | `go install github.com/CosmWasm/tinyjson/...@latest` | Yes |
| wasm-opt (Binaryen) | `brew install binaryen` | No (optimization only) |
| RSA test keypair | Already in repo: `kas-private.pem`, `kas-cert.pem` | No |

---

## Key Technical Risks

| Risk | How spike retires it | Fallback |
|------|---------------------|----------|
| tinyjson can't handle manifest structs | Task 1.2: codegen + round-trip test | `json-iterator/tinygo` or hand-roll |
| `encoding/binary` breaks under TinyGo | Task 1.3: ZIP writer build + test | Manual byte packing |
| `hash/crc32` broken in TinyGo | Task 1.3: ZIP CRC validation | Delegate CRC to host |
| Shared memory pointer passing too fragile | Task 2.1: wrapper implementation | WASI stdio for data exchange |
| tinyjson case-sensitivity breaks parsing | Task 1.2: cross-validate with Go SDK | Normalize field names in codegen |
| Binary size exceeds 300KB gz | Task 4.1: per-component measurement | Drop `fmt`, use custom errors |
| `unsafe.Pointer` usage differs in TinyGo | Task 2.1: pointer arithmetic tests | Use TinyGo-specific memory helpers |

---

## Estimated Effort

| Phase | Days | Confidence | Key risk |
|-------|------|------------|----------|
| 1. Foundation | 3 | High | tinyjson + zipstream under TinyGo |
| 2. Host crypto | 3 | Medium | WASM memory ABI correctness |
| 3. TDF encrypt + validation | 2 | Medium | Integration of all components |
| 4. Measurement + report | 2 | High | Mechanical |
| **Total** | **10** | | |

---

## Future ABI Evolution (Post-Spike)

If spike passes, the ABI grows to support EC-wrapped TDFs:

```
Spike (8 functions):
  random_bytes, aes_gcm_encrypt, aes_gcm_decrypt, hmac_sha256,
  rsa_oaep_sha1_encrypt, rsa_oaep_sha1_decrypt,
  rsa_generate_keypair, get_last_error

M2 adds EC support (+3 functions = 11 total):
  ec_generate_keypair, ecdh_derive, hkdf_sha256

M3 may add (+1-2 functions):
  sha256 (for tdfSalt in EC path, unless hardcoded)
  pem_parse (if key format validation moves to host)
```
