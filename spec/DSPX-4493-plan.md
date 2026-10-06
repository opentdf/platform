---
ticket: DSPX-4493
title: Implementation plan — deterministic AES-GCM IVs for the Go SDK's ZTDF writer
status: draft
authors:
    - dmihalcik@virtru.com
branches:
    - opentdf/platform:DSPX-4493
prs: []
created: 2026-09-28T00:00:00Z
updated: 2026-09-28T00:00:00Z
spec: ./DSPX-4493.md
---

# DSPX-4493 — Deterministic AES-GCM IVs for the Go SDK's ZTDF writer

## Context

`SDK.CreateTDF` and the chunked writer encrypt every payload segment with
`ocrypto.AesGcm.EncryptInPlace`, built on Go's `cipher.NewGCMWithRandomNonce`.
The nonce is drawn at random inside the stdlib and the writer never sees it.
That is NIST SP 800-38D **§8.2.2 (RBG-based)** IV construction, and §8.3 caps it
at 2^32 invocations per key because uniqueness is only probabilistic — collision
probability over `n` segments is `≈ n²/2^97`.

The parent epic (DSPX-4502, *Large File TDF Security and Support*) targets
50 TiB payloads. At that scale the probabilistic bound stops being comfortable:

| payload | segment size | segments | P(IV collision) |
|---|---|---|---|
| 50 TiB | 16 KiB (`minSegmentSize`) | 2^31.6 | **2^-33.7** |
| 50 TiB | 2 MiB (default) | 2^24.6 | 2^-47.7 |
| 4 PiB | 2 MiB (`maxPayloadSegments`) | 2^31 | 2^-35.0 |

A 50 TiB file written at the minimum segment size lands essentially *on* NIST's
approved §8.3 ceiling, with no margin. And a stream whose length cannot be
measured has no segment ceiling at all today — `maxPayloadSegments` bounds only
the declared-size path (`sdk/tdf.go:57-67`; DSPX-4905 tracks the gap) — so its
exposure is unbounded.

An IV collision under a reused key is not graceful degradation: the two
ciphertexts XOR to the XOR of their plaintexts, *and* the GHASH subkey becomes
recoverable, which forges tags for everything else under that key.

This change switches the writer to SP 800-38D **§8.2.1 (deterministic)**:

```
byte  0 .. 7              8  9 10 11
     +--------------------+------------+
     | MessageID (64b)    | part (32b) |   big-endian
     | RBG, per TDF       | 0,1,2,...  |
     +--------------------+------------+
```

Non-repetition within a stream becomes a guarantee rather than a probability.
The IV is still the 12-byte prefix of each encrypted segment, so **the wire
format does not change and existing readers are unaffected** — writer-side only,
no manifest or spec-version change.

Mirrors the construction already merged in web-sdk
(`lib/tdf3/src/ciphers/gcm-iv-counter.ts`, DSPX-4496); java-sdk is DSPX-4495.
All three must land on literally the same layout, including reserving counter
value 0 (web-sdk calls it invocation 0, this plan calls it part 0) for
key-access-object metadata. Risk math belongs to DSPX-4492.

---

## Decisions

**Index-derived, not a stateful counter.** web-sdk's `GcmIvCounter.next()` works
there because its writer is a sequential stream. Go's
`chunkedWriter.WriteSegment(ctx, index int, data []byte)` takes **sparse,
out-of-order, concurrent** indices (`sdk/chunked_writer.go:737`, unlocked past
:761). A shared `next()` would need a mutex on the hot path, and a retried write
would burn a part number — making the exhaustion bound depend on failure history
and breaking the index→part correspondence. So: `part = index + 1`, a pure
function. The random fallback separately counts actual encryption attempts;
retries consume that budget even though they retain the same part number.

**Part 0 is load-bearing, not cosmetic.** `splitDEK`
(`sdk/key_splitter.go:488-507`) runs its randomization loop `count-1` times, so
with a single split the sole share **is the DEK verbatim**. In the common
single-KAS case `encryptMetadata` therefore seals under the payload key.
Reserving part 0 is the only thing keeping metadata off segment 0's IV.

**Metadata is pinned on first manifest build.** `buildManifest`
(`sdk/chunked_writer.go:1049`) re-resolves key access on *every* `GetManifest`
and `Finalize`, each with that call's own `WithChunkedEncryptedMetadata`.
Combined with the above, `GetManifest("A")` then `Finalize("B")` would seal two
plaintexts under the same key and IV. New sentinel
`ErrChunkedMetadataChanged` rejects the second value. `CreateTDF` is immune —
`staticKeyAccess.resolve` returns cached KAOs (`sdk/key_splitter.go:349-351`).

**Metadata ciphertext is cached per share key.** Pinning the plaintext alone
does not bound encryption calls: the random fallback would draw another nonce
on every manifest build. One writer-owned registry supplies the same sealer
for equal key bytes, including when a share equals the DEK, and caches each
share's encrypted metadata. Concurrent builds share the cache. Payload writes,
metadata cache misses, and retries therefore use the same per-key accounting.

**Every enabled FIPS mode uses random nonces inside `ocrypto`.**
`fips140.Enabled()` selects the approved random-nonce path for both `on` and
`only`, including FIPS mode enabled at build time. Outside FIPS mode, a
capability probe can still select the fallback if deterministic GCM is
unavailable. No SDK production code branches on FIPS. Applications see a
smaller segment ceiling, a larger default segment size, and an encryption
budget that failed attempts can exhaust before the segment ceiling is reached.

**The new `ocrypto` API is not written around IVs.** Surveying libsodium
(`crypto_secretstream`: opaque state + *header*), Google Tink (`StreamingAEAD`:
random *prefix* ‖ BE32 segment ‖ flag), Rust `aead::stream`, and the AWS
Encryption SDK (*message ID* + frame sequence), the universal pattern is a
**keyed object built from a per-message random value and addressed by an
ordinal** — no library puts raw nonce bytes in its public API. We follow that,
with one divergence: the ordinal is an explicit argument rather than an
auto-advancing counter, because `WriteSegment` takes sparse, out-of-order,
concurrent indices.

The sealer binds the key and message ID at construction. The SDK registry
reuses that sealer for every use of the same key in a message, so payload and
metadata cannot acquire independent fallback budgets. The writer still needs
the DEK for signatures, but it does not assemble IVs at encryption call sites.
Doc comments and encrypt-direction KATs in `ocrypto` pin the byte layout against
fixtures.

---

## FIPS compatibility

`cipher.NewGCM` — the only stdlib route to a caller-supplied IV — is refused
outright under strict mode, as are `NewGCMWithNonceSize` and
`NewGCMWithTagSize` (`$GOROOT/src/crypto/cipher/gcm.go:26-31, 40-44, 56-60`:
*"use of GCM with arbitrary IVs is not allowed in FIPS 140-only mode"*).
Under `fips140=on`, `NewGCM` succeeds but its encryption service remains
non-approved. A successful construction probe is therefore not sufficient
to preserve FIPS behavior. Go describes `only` as a testing/debugging mode;
production FIPS mode can be enabled through `GOFIPS140` at build time or
`GODEBUG=fips140=on`. See the [Go FIPS documentation](https://go.dev/doc/security/fips140#the-fips140-godebug-option).

**Select policy first, then probe capability.** `fips140.Enabled()` landed in
Go 1.24 and works with the `go 1.25.0` floor in `go.work` and
`lib/ocrypto/go.mod`. Behind a `sync.OnceValue`, return the random-nonce mode
whenever it reports true. Only when FIPS is disabled, probe `cipher.NewGCM`
against a throwaway key: success selects deterministic nonces, failure selects
the random fallback. Neither `fips140.Enforced()` nor a Go version bump is
needed. The probe must never override the enabled-FIPS policy.

**Degradation is total and internal.** `AesGcmSealer` keeps one API in both
modes. Under the fallback it ignores `part` for IV derivation, seals with
`cipher.NewGCMWithRandomNonce`, and splits the stdlib-prepended 12-byte nonce
back off as the `header` return. The wire layout and call sites are identical;
the `MessageID` is drawn but unused. SDK production code does not branch on
the mode; tests distinguish the guarantees of the two constructions.

**One exported knob carries the consequence.** `ocrypto.MaxMessageParts()`
returns `1<<32 - 1` deterministically and `1<<26` on the fallback, and `Seal`
range-checks `part` against it in *both* modes. This bounds ordinals, not the
number of encryption calls. In fallback mode, `Seal` also atomically consumes
one of `1<<26` encryption attempts before invoking the AEAD. The counter is
shared by copies of a sealer, saturates at the limit, and is never refunded
after an archive failure, cancellation after encryption, or a panic. Rejected
part numbers and metadata cache hits do not invoke the AEAD or consume budget.
Exhaustion returns `ErrMessageInvocationsExhausted`; continuing requires a fresh
message and key. The SDK's registry shares this counter between payload and
metadata when their keys are equal and retains it across manifest rebuilds.

`1<<26` is chosen from the birthday bound `P ≈ n²/2^97`, where `n` counts
actual random-nonce encryption attempts under the key. The table reserves one
attempt for metadata and assumes no failed encryption attempts:

| max invocations | `P(collision)` | payload @16 KiB | payload @2 MiB | payload @4 MiB |
|---|---|---|---|---|
| 2^32 (NIST §8.3 ceiling) | 2^-33 | 64 TiB − 16 KiB | 8 PiB − 2 MiB | 16 PiB − 4 MiB |
| **2^26 (chosen)** | **2^-45** | 1 TiB − 16 KiB | 128 TiB − 2 MiB | **256 TiB − 4 MiB** |
| 2^24 | 2^-49 | 256 GiB − 16 KiB | 32 TiB − 2 MiB | 64 TiB − 4 MiB |

2^26 sits 6 bits under NIST's approved ceiling — a 4096× safety margin on
collision probability — while still clearing the epic's 50 TiB target by 5× at
the maximum segment size. 2^24 would not clear 50 TiB at the default size.

**The SDK derives segment sizing from that one number**, rather than learning
about FIPS: pick the smallest allowed segment size ≥ the current 2 MiB default,
clamped to `maxSegmentSize` (4 MiB), such that
`maxPayloadSegments × size ≥ 256 TiB − 4 MiB`, where `maxPayloadSegments`
reserves part 0 and applies the platform's integer limit. Deterministically
that leaves 2 MiB unchanged; on the fallback it yields 4 MiB, because
`(2^26 − 1) × 4 MiB = 256 TiB − 4 MiB` (281,474,972,516,352 bytes).
This is the capacity for successful first attempts with at most one metadata
encryption under the DEK. Failed attempts reduce the remaining capacity;
segment sizing cannot guarantee completion after an arbitrary number of retries.

Two notes for the spec, ADR, and PR body:

1. **This is a Go restriction, not a NIST one.** SP 800-38D §8.2.1 explicitly
   approves the deterministic construction. Go's FIPS module even implements one
   — `crypto/internal/fips140/aes/gcm.NewGCMWithCounterNonce`, FIPS 140-3 IG C.H
   Scenario 3 — but it is unexported and its layout is a 32-bit module-name
   prefix plus a **64-bit** strictly-increasing counter, incompatible with both
   our 8‖4 split and with out-of-order indices. Not a path; the right citation
   for why the fallback exists.
2. **The module indicator lands the right way round.** `GCM.Seal` calls
   `fips140.RecordNonApproved()` where `SealWithRandomNonce` calls
   `RecordApproved()` (`.../fips140/aes/gcm/gcm.go:63-66`, `gcm_nonces.go:41`).
   With FIPS disabled, deterministic segment encryption is a non-approved
   *service* in Go's indicator. Whenever FIPS is enabled, including `on` and
   `only`, the random fallback preserves the approved encryption service.

Rejected: `fips140.WithoutEnforcement` (Go 1.26, `$GOROOT/api/go1.26.txt:17`)
would let us keep deterministic IVs under strict mode. It needs a version
bump, and silently disabling an enforcement the operator explicitly asked for —
while still recording the service as non-approved — is the wrong trade. Record
it as a considered option in the ADR.

---

## Implementation

### Step 1 — `lib/ocrypto`: the sealer

New file **`lib/ocrypto/message_sealer.go`**. The public API never says "IV" or
"nonce"; the doc comments say both, plainly, with the NIST citation.

```go
const MessageIDSize = 8                       // GcmStandardNonceSize - 4
var ErrInvalidMessageID     = errors.New("invalid message id")
var ErrMessagePartsExhausted = errors.New("message part number exceeds the limit for one key")
var ErrMessageInvocationsExhausted = errors.New("message encryption limit exhausted; start a new message with a fresh key")

// MessageID is the per-TDF random value shared by every part of a message,
// across all keys it is sealed under. Copied on construction: a caller
// reusing its randomness buffer must not retroactively change sealed parts.
type MessageID struct{ b [MessageIDSize]byte }

func NewMessageID(r io.Reader) (MessageID, error)       // io.ReadFull, 8 bytes
func MessageIDFromBytes(b []byte) (MessageID, error)    // length-check + copy
func (m MessageID) Bytes() []byte                       // copy, for threading/tests

// MaxMessageParts is the exclusive upper bound on part numbers under one key.
// 1<<32-1 with the deterministic construction, 1<<26 on the random fallback.
// In fallback mode it is also the maximum number of AEAD encryption attempts.
func MaxMessageParts() uint32

type AesGcmSealer struct{ /* pointer to shared AEAD, id, mode, atomic usage state */ }

// A key is fresh for this message. Reuse the returned sealer for every
// encryption under that key; separate constructors do not share accounting.
// Copies of the returned value share the same usage state.
func NewAESGcmSealer(key []byte, id MessageID) (AesGcmSealer, error)

// Seal encrypts plaintext as part `part`, returning the part header and the
// ciphertext+tag. The header is the 12-byte AES-GCM IV, which the reader
// expects as the part's prefix. Never expose encryptions of different
// plaintexts under the same key, message ID, and part in deterministic mode.
// Returns ErrMessagePartsExhausted at or above MaxMessageParts(). In fallback
// mode every AEAD encryption attempt consumes budget, including repeated
// parts; exhaustion returns ErrMessageInvocationsExhausted before encryption.
func (s AesGcmSealer) Seal(part uint32, plaintext []byte) (header, ciphertext []byte, err error)
```

Header is returned **separately from** ciphertext, not joined: under
`SegmentHS256`, `segmentIntegrity` MACs its whole argument
(`sdk/tdf.go:1648-1655`), so a joined blob would silently change that hash.

There is deliberately **no** `Unseal`. Readers must keep accepting
pre-DSPX-4493 TDFs whose IVs are random, so the reader must never validate the
construction — it takes the IV off the wire, as it already does.

Mode selection, once per process:

```go
var deterministic = sync.OnceValue(func() bool {
	if fips140.Enabled() { // Go 1.24+: includes on, only, and build-time enablement
		return false
	}
	block, _ := aes.NewCipher(make([]byte, 32))
	_, err := cipher.NewGCM(block) // capability probe only after FIPS policy
	return err == nil
})
```

`NewAESGcmSealer` builds `cipher.NewGCM` or `cipher.NewGCMWithRandomNonce`
accordingly and caches the AEAD. Deterministic sealing reads immutable state;
fallback sealing also reserves an invocation using a saturating atomic
compare-and-swap loop. Both support concurrent `WriteSegment` calls, and copies
share the state pointer rather than copying an atomic counter. On the fallback,
`Seal` range-checks `part`, reserves budget, then discards `part` and splits the
stdlib-prepended nonce off the front of `aead.Seal(nil, nil, plaintext, nil)` as
the header. A reserved attempt is never returned to the budget. Wrap any
construction failure in the existing `ErrUnsupportedAESGCMConfiguration`.

Keep mode selection and an injectable invocation limit internal to `ocrypto`.
Tests can select the random implementation and a small budget without changing
process-global state or performing millions of encryptions. Production always
uses the selected mode's real limit. The SDK receives accounting through the
sealer, not through a FIPS-specific counter of its own.

Port the web-sdk doc comment (the "uniqueness across TDFs rests entirely on the
fixed field" paragraph) onto `MessageID`; cross-SDK consistency in the
rationale is worth having.

**`lib/ocrypto/aes_gcm.go` keeps its existing behavior.** `Encrypt`/`Decrypt` stay on
`NewGCMWithRandomNonce`; they are correct for one-shot key wrapping and have
callers in `otdfctl`, `service`, `sdk/kas_client.go`, and
`lib/ocrypto/{kem,hybrid_common,protected_key}.go`. `EncryptInPlace` becomes
repo-dead but is exported on a published module — mark `// Deprecated:` and
keep it and its test.

### Step 2 — `sdk`: part policy and segment sizing

`sdk/tdf.go` const block (:34-68, beside `maxPayloadSegments` so the two
ceilings stay adjacent and cross-referenced):

```go
const metadataPart uint32 = 0                       // reserved; payload starts at 1
func segmentPart(index int) (uint32, error)         // index+1, or ErrChunkedSegmentIndexExhausted
```

`maxPayloadSegments` (today `math.MaxInt32`) becomes a `var` derived from
`ocrypto.MaxMessageParts() - 1` (part 0 is spent on metadata), still clamped by
`math.MaxInt32` on 32-bit builds. `sdk/tdf_config.go:16-19`'s
`defaultSegmentSize` likewise becomes a derived `var`: the smallest allowed size
≥ 2 MiB, clamped to `maxSegmentSize`, with
`maxPayloadSegments × defaultSegmentSize ≥ 256 TiB − 4 MiB`. Keep
`maxSegmentSize` a fixed 4 MiB constant when `defaultSegmentSize` stops being
a constant. Use `int64` capacity arithmetic. `segmentCount`
(`sdk/tdf.go:434-448`) needs no change — it already enforces the ceiling.

Document the capacity of successful first attempts on both derived values,
pointing at `ocrypto.MaxMessageParts`. Also document that failed encryption
attempts can cause `ErrMessageInvocationsExhausted` before the ordinal limit.

`sdk/chunked_writer.go` — new sentinel in the var block (:105-184), kept
distinct from `ErrChunkedInvalidSegmentIndex` because "negative index" is a bug
while "too many segments" is a capacity limit a caller can act on. Reachable in
normal use on the FIPS fallback (1 TiB − 16 KiB at `minSegmentSize`), so the
message must name the remedy:

```go
ErrChunkedSegmentIndexExhausted = errors.New("chunked: too many segments for one key; use a larger segment size")
```

`chunkedWriterConfig` (:350-405) gains `sealers *messageSealers`, the unexported
per-message registry described below. If nil, `newChunkedWriter` (:581-609)
draws its message ID from `cfg.rand` **after** the DEK, then builds the registry
using the configured factory. `withChunkedRand` stays a deterministic
32-then-8-byte draw. `CreateTDF` supplies the registry it already used to seal
metadata, preserving both ciphertext cache and invocation accounting.

### Step 3 — the sealer seam and `WriteSegment`

Replace `sdk/chunked_writer.go:55-79`, renaming `segmentCipher` →
`segmentSealer` to match. The current contract ("a fresh nonce per call … a
cipher that returns a repeated nonce produces a manifest that verifies against
nothing") is now exactly backwards:

```go
type segmentSealer interface {
	Seal(part uint32, data []byte) (header, ciphertext []byte, err error)
}
type segmentSealerFactory func(dek []byte, id ocrypto.MessageID) (segmentSealer, error)

func defaultSegmentSealerFactory(dek []byte, id ocrypto.MessageID) (segmentSealer, error) {
	return ocrypto.NewAESGcmSealer(dek, id)
}
```

Add an unexported `messageSealers` registry with one immutable message ID, the
factory, a mutex, and entries keyed by a copied `[kKeySize]byte` key. Validate
the key length before converting; never key entries by split ID or KAS URL,
which can change while the underlying key stays the same. Each entry holds
one `segmentSealer` plus its cached encrypted metadata and a cache-valid flag.
Keep entries for the writer's lifetime so returning to a previously used key
cannot reset its budget. Fresh shares from repeated split operations add
entries; document this memory cost. Do not expose or log registry keys.

The writer's `stream segmentSealer` replaces `block` and comes from the DEK's
registry entry. Payload writes use that field directly, with no registry lock
on their hot path. The writer also retains a metadata closure over the same
registry. Every use of equal key bytes obtains the same sealer, so the
single-split metadata path shares the payload's fallback counter.

The interface documentation must preserve the concurrency and input-ownership
contracts, explain deterministic part uniqueness and fallback invocation
accounting, and retain the 12-byte header plus 16-byte tag wire contract.

In `WriteSegment` (:737): compute `part` next to the existing `index < 0` check
and **before** the reservation at :759-760, so a rejected index never enters
`w.segments`. Then at :827:

```go
header, ciphertext, err := w.stream.Seal(part, data)
```

Rename the `nonce` local to `header` at :840, :842, :873, :875, and the existing
archive `header` local to `zipHeader` to distinguish the two prefixes. CRC
order and the `io.MultiReader` layout are unchanged. Preserve the invocation
exhaustion sentinel through error wrapping so callers can distinguish it from
an index limit.

Add a comment at the encryption site recording the **deterministic retry
analysis**: retrying a failed index re-derives the same IV, so a retry with
different bytes is a same-key/same-IV encryption. Verified safe today — every failure path between
:828 and :851 is a bare `return nil, err` that constructs no
`ChunkedSegmentResult`; the archive receives a length and a CRC, never bytes
(:848); `CleanupSegment` rolls that back or fences the writer (:822); and a
committed index can never be retried (`ErrChunkedSegmentAlreadyWritten`, :752).
At most one ciphertext per (key, IV) leaves the function. That is a property of
this error handling, not of the IV construction, and is one refactor away from
being false — the comment must say so.

In fallback mode every reserved AEAD attempt consumes budget even if
the archive subsequently rejects the segment. Cleanup releases the segment
reservation, not the cryptographic budget. A retry draws a fresh nonce and
consumes another attempt; once exhausted, retries cannot restore the writer's
capacity. Failures before the AEAD, such as an invalid part, consume nothing.

### Step 4 — thread a metadata sealer (part 0) through both resolvers

Thread a **capability, not a value**. Handing resolvers a `MessageID` would let
one ask for part 7 and collide with segment 6; handing them a closure already
bound to part 0 removes the choice. Same shape as the existing
`segmentSealerFactory`, so the file already reads this way:

```go
// sdk/key_splitter.go
type metadataSealer func(key []byte, plaintext string) (string, error)
```

`sdk/tdf.go:653`'s `encryptMetadata` is replaced by a constructor for that
closure, `newMetadataSealer(sealers *messageSealers) metadataSealer`. Under the
registry mutex it finds or constructs the *share* key's entry. A cache hit
returns the existing encrypted metadata without sealing. A miss calls that
entry's `Seal(metadataPart, ...)` and assembles `emb := header || ciphertext`,
then caches the complete encoded `EncryptedMetadata` before releasing the
mutex. This makes concurrent misses for equal keys perform one encryption.
The `Iv == Cipher[:12]` invariant that the reader (`sdk/tdf.go:1414-1438`, which
ignores `Iv` and feeds the whole blob to `Decrypt`) and
`sdk/key_access_test.go:68` rely on now holds *by construction*.
`EncryptedMetadata`'s wire shape is unchanged.

The parameter threads through, one per signature:

```go
// sdk/key_splitter.go:440 / :420
func buildKeyAccessObjects(shares []splitShare, base64Policy, metadata string, seal metadataSealer) ([]KeyAccess, error)
func resolvePolicyAndKeyAccess(fqns []string, shares []splitShare, metadata string, seal metadataSealer) (string, []KeyAccess, error)
// sdk/key_splitter.go:321
type keyAccessResolver interface {
	resolve(ctx context.Context, dek []byte, seal metadataSealer, cfg *chunkedFinalizeConfig) (string, []KeyAccess, error)
}
// sdk/tdf.go:564
func (s SDK) resolveKeyAccess(ctx context.Context, tdfConfig *TDFConfig, dek []byte, seal metadataSealer) (string, []KeyAccess, error)
```

`newTDFChunkedWriter` (`sdk/tdf.go:338-372`) is where the paths are stitched —
draw the `MessageID` and construct the shared registry before resolving key
access, then hand the same registry to the writer:

```go
id, err := ocrypto.NewMessageID(rand.Reader)
sealers := newMessageSealers(id, defaultSegmentSealerFactory)
sealMetadata := newMetadataSealer(sealers)
base64Policy, kaos, err := s.resolveKeyAccess(ctx, tdfConfig, dek, sealMetadata)
newChunkedWriter(chunkedWriterConfig{ ..., sealers: sealers })
```

`buildManifest` (:1049) becomes
`w.keyAccess.resolve(ctx, w.dek, w.sealMetadata, cfg)`.
Construct and retain `w.sealMetadata` once over the writer's registry; never
construct a new registry on a manifest build or retry. A cached ciphertext
survives a later KAS wrapping or manifest-building error. If sealing itself
fails, retain the entry and its budget even though no ciphertext is cached.
`staticKeyAccess.resolve` ignores the new parameter — note the asymmetry on the
struct.

### Step 5 — pin the metadata (close the part-0 hole)

On `chunkedWriter`: `metadataMu sync.Mutex` + `metadataPin *string`, guarded
separately from `w.mu` because `buildManifest` deliberately runs with the read
lock released. Atomically check or set the pin immediately before `resolve`,
then release `metadataMu` before calling the resolver. Pin even an empty value;
never clear the pin after a build failure. Every later build must match before
it can use the per-key ciphertext cache:

```go
ErrChunkedMetadataChanged = errors.New("chunked: encrypted metadata differs from an earlier manifest build")
```

Its doc comment carries the *why*: part 0 may already have been spent on the
first value, and for a single-split TDF the metadata key is the DEK itself.
Update the "reads no mutable writer state and takes no lock" note at
:1043-1045 to name the pin and registry exceptions. Holding the registry lock across a metadata cache
miss covers only local encryption and encoding, never KAS resolution or a
network call. This also makes one flavor of an already-acknowledged footgun loud —
see `getManifestSnapshot`'s comment at :1008-1011.

### Step 6 — tests

Mechanical updates: `sdk/chunked_test.go:1605` (`failingCipher`) and
`:1848-1858` (`blockingCipher`) move to `Seal` — same arity as today, plus the
`part` parameter, which `blockingCipher` forwards to its `inner`;
`withChunkedCipherFactory` → `withChunkedSealerFactory` at its definition and
call sites; `sdk/key_access_test.go:170,185,196,208` pass a `metadataSealer`
(`decodeEncryptedMetadata` at :50-71 needs no change). `lib/ocrypto/aes_gcm_test.go`,
`protected_key_test.go`, `tests-bdd/`, and `examples/` are unaffected.

New — `lib/ocrypto/message_sealer_test.go`:

- `MessageIDFromBytes` length rejection (0/7/9/12) and the copy defense.
- **Deterministic only: exact-bytes header layout** over parts `0`, `1`,
  `0x01020304`, and `MaxMessageParts()-1`; distinctness.
- **Deterministic only: encrypt-direction KATs** — promote the three existing
  decrypt vectors in `aes_gcm_test.go:18-41` to `Seal` fixtures. These pin the
  construction against known-answer bytes rather than against itself. This
  is what recovers the auditability the opaque API gives up, so it is not
  optional.
- **Deterministic only:** byte-identical output for the same part and plaintext.
- **Shared:** short-reader errors, part boundaries, 12-byte headers, unchanged
  inputs, decrypt round-trips, and concurrent sealing under `-race`. Exercise
  the selected mode's boundary, including that rejected parts consume no budget.
- **Fallback:** inject the random mode internally so this also runs in a normal
  build. Assert fresh headers for repeated and distinct parts and round-trips
  through `AesGcm.Decrypt`, without expecting a message-ID prefix, a counter
  suffix, or fixed ciphertext bytes.
- **Fallback invocation budget:** use a small injected limit to check the last
  permitted encryption, exhaustion on the next call even for part zero, shared
  accounting through copied sealers, and concurrent calls admitting exactly the
  limit without overshoot or wraparound. The ordinal limit and invocation count
  are independent checks. Reservations survive an injected post-reservation
  failure or panic.
- **FIPS policy:** run subprocesses with `fips140=off`, `on`, and `only` and
  assert the selected construction and public limit. Both enabled settings must
  select the random implementation; test this independently of any conditional
  skips so the old probe-only implementation fails the test.

New — `sdk/chunked_iv_test.go`:

- **Deterministic layout:** write 0..4, assert header `[0:8]` identical and
  `[8:12] == BE(index+1)`.
- **Sparse/out-of-order:** write 7, 0, 3 and verify each result decrypts in both
  modes. In deterministic mode also assert parts 8, 1, 4; this assertion is the
  one a stateful `next()` fails.
- **Concurrent:** N goroutines on distinct indices; distinct headers and correct
  decryption in both modes, with exact layout assertions only in deterministic mode.
- **Deterministic metadata shares the message ID** — once via the chunked path
  (`WithChunkedEncryptedMetadata`) and once via `SDK.CreateTDF` with
  `TDFConfig.metaData`. The second catches a mis-threaded `newTDFChunkedWriter`.
  In fallback mode verify metadata decryption and `Iv == Cipher[:12]` instead.
- **Exhaustion**: table-test `segmentPart` directly (`-1`, `0`, `1`,
  `maxPayloadSegments - 1`, `maxPayloadSegments`, `+1`) rather than driving
  billions of indices through `zipstream`; plus one oversized `WriteSegment`
  asserting the sentinel *and* that `w.segments` stayed empty. Skip only inputs
  that cannot be represented by the architecture's `int`.
- **Retry after encryption:** use a real sealer, fail the archive after sealing
  index 0, assert the call returns no result, then retry with different bytes.
  In deterministic mode the IV remains `id||BE(1)` and only the successful
  attempt's ciphertext is returned. In fallback mode the retry uses a fresh
  nonce. Retain the separate pre-encryption `failingCipher` tests.
- **Metadata pin**: `GetManifest("A")` + `Finalize("B")` → `ErrChunkedMetadataChanged`;
  also cover concurrent conflicting builds and failures after pinning.
- **Metadata cache:** repeated and concurrent `GetManifest("A")` calls with
  equal share keys return byte-identical `EncryptedMetadata` in both modes,
  with one seal per key. Keep the cache across a later wrapping/build failure
  and reuse it during `Finalize`. Changing KAS URLs or split IDs must not reset
  it. Fresh share keys get separate entries, so their ciphertext is not expected
  to be byte-identical across manifest builds.
- **Shared budget:** inject a counting sealer with a small invocation budget
  through the existing factory seam. Verify equal key bytes yield one factory
  call and one budget for payload and single-split metadata, metadata cache
  hits cost nothing, failed archive writes still consume attempts, and
  exhaustion propagates through both `WriteSegment` and manifest building.
  Include the `CreateTDF` setup path so early metadata sealing cannot lose its
  budget when the chunked writer is constructed.
- **Derived sizing**: assert `maxPayloadSegments` and `defaultSegmentSize`
  satisfy the ≥ 256 TiB − 4 MiB rule for both `MaxMessageParts()` values and
  supported integer widths. The fallback must have exactly `2^26 − 1`
  payload parts, a 4 MiB default, and capacity 281,474,972,516,352 bytes before
  failed attempts. Test a pure sizing helper with both limits without a FIPS build.
- **Round-trip**: an existing decrypt test must pass unchanged — the real proof
  the wire format did not move.

Partition construction-specific subtests explicitly. Skip deterministic KATs
and layout assertions when that construction is unavailable; never force
`cipher.NewGCM` through FIPS enforcement. Shared round-trip, boundary, cache,
retry, and concurrency coverage must run in every mode. Test-only mode checks
in `sdk/` are allowed; production behavior stays encapsulated in `ocrypto`.

### Step 7 — documentation deliverables

- **`spec/DSPX-4493.md`** — fill the empty scaffold: Problem/Motivation (the
  birthday table above), Proposed Solution (layout diagram), Inputs/Outputs
  (the signatures from Steps 1–4), Edge Cases (both enabled FIPS modes, ordinal
  and invocation exhaustion, retry, part 0, metadata caching), Out of Scope
  (readers, manifest/spec version, java/web SDKs), and testable Acceptance
  Criteria. Cross-reference DSPX-4905: the new `WriteSegment` guard also bounds
  unmeasured streams, which already use that path, while broader streaming-limit
  policy remains in that ticket.
- **Go doc comments** — NIST §8.2.1 citation, layout diagram, key/ID binding,
  and the shared-accounting contract on `MessageID`/`Seal`, matching the web-sdk
  reference's density. Plus the FIPS consequence on `maxPayloadSegments` and
  `defaultSegmentSize`, which is where an application developer will meet it.
- **`adr/decisions/2026-09-28-deterministic-gcm-iv-construction.md`** — follow
  `adr/adr-template.md`. Two decisions, so two option lists: the construction
  (keep RBG IVs; §8.2.1 stateless index-derived; §8.2.1 stateful counter;
  per-segment key derivation) and the FIPS strategy (hard error; select the
  random path with `fips140.Enabled()` and enforce a shared invocation budget;
  capability probe alone; `fips140.WithoutEnforcement`; require Go 1.26 and
  read `fips140.Enforced()`). Explain why probe-only selection misses `on`.
  Consequences must cover the module-indicator direction, the 2^-45 bound over
  actual attempts, metadata-cache lifetime, and the exact 256 TiB − 4 MiB
  fallback capacity before retries.
- **Jira** — post a comment on DSPX-4493 summarizing the Go-specific decisions
  (the FIPS fallback + its math, shared invocation accounting, index-derived
  parts, the part-0 pin and cache, the retry analysis) so DSPX-4495/4496 stay
  aligned. Flag explicitly that the FIPS fallback and its 2^26 cap are
  Go-specific and should *not* be mirrored.

### Commit split

1. `feat(ocrypto): add AesGcmSealer for deterministic per-part AES-GCM` — Step 1 + tests.
2. `feat(sdk): share per-key sealers across payload and cached metadata` — Steps 2–5.
3. `docs: record the deterministic AES-GCM IV construction` — Step 7.

Keep the SDK integration together so payload encryption, deterministic metadata,
its pin/cache, and shared invocation accounting land in one buildable commit.
Include each step's tests from Step 6 with its implementation commit.

Signed + DCO per `AGENTS.md`: `git commit -S -s`. Both CHANGELOGs are
release-please generated — do not hand-edit.

---

## Verification

```bash
make fmt
make lint                                    # 0 new issues
make test                                    # -race, all modules
(cd sdk && go test -run TestREADMECodeBlocks)
(cd lib/ocrypto && go test ./... -race)
```

Targeted:

```bash
(cd sdk && go test -race -run 'TestChunked|TestKeyAccess|TestCreateTDF' ./...)
(cd lib/ocrypto && go test -run 'TestMessageID|TestAesGcmSealer' -v ./...)
```

Run the mode-aware suites with FIPS explicitly disabled and with each enabled
setting. Only deterministic KAT/layout subtests may skip in the enabled modes;
shared behavior and fallback budget tests must actually execute:

```bash
for mode in off on only; do
  (cd lib/ocrypto && GODEBUG=fips140="$mode" go test -race -v \
    -run 'TestMessageID|TestAesGcmSealer' ./...)
  (cd sdk && GODEBUG=fips140="$mode" go test -race -v \
    -run 'TestChunked|TestKeyAccess|TestCreateTDF' ./...)
done
```

Also run the scoped suites with `GOFIPS140=certified` and no `GODEBUG` override
on a supported toolchain/environment, verifying build-time FIPS enablement
selects the fallback. Record the toolchain and module version used.

Then confirm cross-mode interop using separate processes: encrypt under
`fips140=on` and `only`, decrypt with `off`, and perform the reverse for both
enabled modes. All must round-trip — the fallback changes how the header is
chosen, never what it means. Check logs for the shared tests and invocation
budget tests, not just an overall passing status.

Backward compatibility — the load-bearing check. A TDF written by this branch
must decrypt with an unmodified reader, and a TDF written before it must still
decrypt here. Cover locally with the existing round-trip tests, then cross-SDK
per `AGENTS.md:60-74`:

```bash
gh workflow run xtest.yml --repo opentdf/tests --ref main \
  -f platform-ref=DSPX-4493 -f otdfctl-ref=DSPX-4493 -f java-ref=main -f js-ref=main
```

Before accepting the result, check the workflow's resolved versions and build
logs: the Go client (`otdfctl-ref`) must resolve to this branch's pushed SHA
and build against its SDK. `platform-ref` alone changes the server, not the Go
client under test. Record the resolved client SHA with the test evidence.

Confirm the ZTDF round-trip tests actually ran rather than `SKIPPED`. web-sdk's
mirror of this construction has already merged, so a go-writes/js-reads and
js-writes/go-reads pass is the cheap confirmation both SDKs still agree the IV
is nothing more than the segment prefix.

Manual spot-check with FIPS disabled — assert the leading 8 bytes are constant
across segments and the trailing 4 count 1, 2, 3…:

```bash
cd examples && go run . encrypt --file <large-file>   # then hexdump segment prefixes
```
