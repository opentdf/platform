---
# Required
status: 'proposed'
date: '2026-09-29'
tags:
 - sdk
 - ocrypto
 - cryptography
 - fips
# Optional
driver: 'Dave Mihalcik'
deciders: 'OpenTDF platform team'
consulted: 'java-sdk (DSPX-4495) and web-sdk (DSPX-4496) owners'
informed: 'OpenTDF SDK consumers'
---
# Deterministic AES-GCM IV construction for the Go SDK's TDF writer

## Context and Problem Statement

Every payload segment the Go SDK writes is encrypted with
`cipher.NewGCMWithRandomNonce`: the 12-byte IV is drawn at random inside the
standard library and the writer never sees it. That is NIST SP 800-38D
**§8.2.2 (RBG-based)** IV construction, which §8.3 caps at 2^32 invocations per
key because uniqueness is only probabilistic — over `n` random 96-bit IVs the
collision probability is about `n²/2^97`.

The parent epic (DSPX-4502, *Large File TDF Security and Support*) targets
50 TiB payloads. A 50 TiB file at the 16 KiB minimum segment size needs 2^31.6
segments and lands at `P ≈ 2^-33.7`, essentially *on* NIST's approved ceiling
with no margin. A stream whose length cannot be measured has no segment
ceiling at all today (DSPX-4905).

An IV collision under a reused key is not graceful degradation: the two
ciphertexts XOR to the XOR of their plaintexts, **and** the GHASH subkey
becomes recoverable, which forges authentication tags for everything else under
that key.

Two decisions follow, recorded together because the second only exists as a
consequence of the first: **how to construct the IV**, and **what to do where
Go will not let us construct it that way**.

## Decision Drivers

* The wire format must not change. Readers take the IV off the wire as the
  segment's 12-byte prefix, and TDFs written before this change must keep
  decrypting indefinitely.
* `chunkedWriter.WriteSegment(ctx, index, data)` accepts **sparse,
  out-of-order and concurrent** indices, and a failed write may be retried.
* All three OpenTDF SDKs must land on a construction readers cannot tell
  apart; web-sdk (DSPX-4496) has already merged a counter.
* Enabling FIPS 140-3 should require no application or library change outside
  `lib/ocrypto`.
* The public `ocrypto` API should not expose raw nonce bytes.
* The code that keeps IVs unique should be small enough to audit in one sitting.

## Considered Options

**IV construction**

* Keep RBG-based IVs (§8.2.2)
* §8.2.1 deterministic, stateless: fixed field ‖ index-derived invocation
* §8.2.1 deterministic, stateful: fixed field ‖ counter advanced per call
* Per-segment key derivation

**FIPS strategy**

* Hard error where a caller-supplied IV is unavailable
* Detect policy, fall back to random IVs, and reduce the seal cap
* Probe `cipher.NewGCM` only, and fall back on failure
* `fips140.WithoutEnforcement`
* Require Go 1.26 and branch on `fips140.Enforced()`

## Decision Outcome

Chosen: **§8.2.1 deterministic, stateful**, with
`IV = 64-bit per-sealer random fixed field ‖ 32-bit big-endian counter`. An
`ocrypto.AesGcmSealer` owns one key, its fixed field, and an atomic counter;
every `Seal` takes the next counter value. The writer holds one sealer for the
DEK, and each key access object's metadata is sealed by a throwaway sealer of
its own.

Chosen: **detect policy, fall back to random IVs, and reduce the seal cap**.
`ocrypto` checks `fips140.Enabled()` first and probes `cipher.NewGCM` second,
behind a `sync.OnceValue`. The fallback is total and internal — same API, same
wire bytes, same call sites — and surfaces only as a smaller `MaxSeals()`, from
which the SDK derives its segment sizing. On that path the same counter is the
key's encryption budget.

### Consequences

* 🟩 **Good**, because non-repetition under one sealer is a property of the
  counter rather than a probability, removing the birthday bound as a
  constraint on payload size.
* 🟩 **Good**, because the wire format is untouched: writer-side only, no
  manifest field and no spec version change, and no reader-side validation
  that would break pre-existing TDFs.
* 🟩 **Good**, because callers hold no ordinal. Sparse, out-of-order,
  concurrent and retried writes each take a fresh IV, so retry safety is a
  property of the construction rather than of `WriteSegment`'s error handling.
* 🟩 **Good**, because the state lives with the key and nowhere else. There is
  no message ID to thread through key access resolution, no key→sealer
  registry, no reserved metadata part, and no pin on the encrypted metadata:
  re-sealing metadata on every manifest build simply takes a new IV.
* 🟩 **Good**, because the AEAD is built once per key instead of once per
  segment, and the hot path costs one atomic add.
* 🟥 **Bad**, because in a single-split TDF the metadata key *is* the DEK, and
  the metadata and payload sealers count independently from 0. They are kept
  apart only by their independently drawn 64-bit fixed fields, a `2^-64`
  chance per metadata seal. That is structural within a sealer, probabilistic
  between them.
* 🟥 **Bad**, because the IV no longer says which segment it encrypts:
  concurrent writers take counters in arrival order.
* 🟥 **Bad**, because a retried or discarded seal spends a counter value, so a
  payload at exactly `maxPayloadSegments` segments has no headroom for
  retries. `ErrSealerExhausted` is the backstop.
* 🟥 **Bad**, because under FIPS 140-3 the SDK behaves measurably differently:
  `MaxSeals()` drops from 2^32-1 to 2^26 and the default segment size grows
  from 2 MiB to 4 MiB. That difference is deliberate and is the only
  application-visible one.
* 🟥 **Bad**, because in non-FIPS builds Go's module indicator now records
  segment encryption as a **non-approved service**: `GCM.Seal` calls
  `fips140.RecordNonApproved()` where `SealWithRandomNonce` calls
  `RecordApproved()`. The indicator lands the right way round — under
  `fips140=only`, the only mode where anyone reads it, the fallback keeps it
  approved — but the distinction is worth knowing.

## Validation

* Encrypt-direction known-answer tests in `lib/ocrypto/message_sealer_test.go`
  pin the IV byte layout against fixtures rather than against the
  implementation, by seeding the fixed field and counter. This is what recovers
  the auditability an opaque API gives up, and is the reason it is not
  optional. The same file covers exhaustion without wrap, concurrent counters
  landing on exactly `0..n-1`, and distinct fixed fields for two sealers over
  one key.
* `sdk/chunked_iv_test.go` covers the writer's half: sequential, out-of-order
  and concurrent writes take distinct counters under one fixed field, a
  retried segment takes a fresh IV, metadata is sealed by its own sealer (in
  both the chunked writer and `CreateTDF`), metadata may change between
  manifest builds, the segment-index ceiling, and the derived segment sizing
  for *both* values `MaxSeals()` can take.
* The SDK suite passes under `GODEBUG=fips140=on`, which is the claim that the
  fallback is invisible above `ocrypto`. Tests that assert header *bytes* probe
  for the mode and skip or relax to a uniqueness check.

## Pros and Cons of the Options

### IV construction

#### Keep RBG-based IVs (§8.2.2)

* 🟩 **Good**, because no change, and it is an approved construction.
* 🟥 **Bad**, because the collision bound is the thing the epic outgrows.
* 🟥 **Bad**, because the exposure of an unmeasurable stream is unbounded.

#### §8.2.1 deterministic, stateless

`IV = per-message random ID ‖ part number`, part 0 reserved for metadata and
segment `i` taking part `i + 1`. This was the first implementation (#4118).

* 🟩 **Good**, because it survives sparse, out-of-order, concurrent and
  retried writes without shared state.
* 🟩 **Good**, because the index↔IV correspondence is inspectable.
* 🟥 **Bad**, because the caller owns uniqueness, and a caller that passes one
  part twice gets IV reuse with no diagnostic.
* 🟥 **Bad**, because a retry re-derives the same IV, so retry safety rests on
  `WriteSegment` never emitting bytes on a path that later fails — one
  refactor away from being false.
* 🟥 **Bad**, because the reserved metadata part must be spent exactly once
  under a key that, for a single split, is the DEK: that forced a key→sealer
  registry shared between `CreateTDF` and the writer, a message ID threaded
  through key access resolution, a per-key metadata cache, and a pin refusing
  changed metadata (`ErrChunkedMetadataChanged`).

#### §8.2.1 deterministic, stateful (chosen)

This is also web-sdk's `GcmIvCounter.next()`.

* 🟩 **Good**, because the caller cannot repeat an ordinal.
* 🟩 **Good**, because the shared counter is one `atomic.Uint64` add, not a
  mutex, on the segment hot path.
* 🟥 **Bad**, because a retried write burns a counter value, making the
  exhaustion bound depend on failure history.
* 🟥 **Bad**, because it destroys the index↔IV correspondence for
  out-of-order writes.

#### Per-segment key derivation

* 🟩 **Good**, because IV reuse across segments stops mattering.
* 🟥 **Bad**, because it changes what the KAS hands back and how the reader
  decrypts — a wire and spec change across all three SDKs, for a problem the
  IV construction solves on the writer alone.

### FIPS strategy

#### Hard error where a caller-supplied IV is unavailable

* 🟩 **Good**, because the construction is then the same everywhere.
* 🟥 **Bad**, because enabling FIPS would break every writer, which is the
  opposite of the "no changes outside `ocrypto`" driver.

#### Detect policy, fall back, reduce the cap (chosen)

* 🟩 **Good**, because it catches `fips140=on`, where `cipher.NewGCM` succeeds
  but the resulting `Seal` is non-approved.
* 🟩 **Good**, because it needs only `fips140.Enabled()` (Go 1.24), and the
  probe covers `fips140=only` and anything not yet anticipated.
* 🟩 **Good**, because the consequence reaches applications through one
  number, `MaxSeals()`, from which the segment sizing is derived.
* 🟩 **Good**, because the counter that builds IVs on one path is the budget on
  the other, so both paths share one exhaustion rule and one error.
* 🟥 **Bad**, because it keeps two code paths in `Seal` forever.

#### Probe `cipher.NewGCM` only

* 🟩 **Good**, because it is version- and GODEBUG-independent.
* 🟥 **Bad**, because it silently keeps deterministic IVs under
  `fips140=on` — a production FIPS deployment — recording every segment
  encryption as a non-approved service. **Rejected for this reason.**

#### `fips140.WithoutEnforcement`

* 🟩 **Good**, because deterministic IVs would be kept in every mode.
* 🟥 **Bad**, because it is Go 1.26, and because silently disabling an
  enforcement the operator explicitly asked for — while still recording the
  service as non-approved — is the wrong trade.

#### Require Go 1.26 and branch on `fips140.Enforced()`

* 🟩 **Good**, because it distinguishes the modes exactly.
* 🟥 **Bad**, because it puts a Go 1.26 floor on a published module for a
  distinction `fips140.Enabled()` plus a probe already covers well enough.

## More Information

* NIST SP 800-38D §8.2.1 (deterministic construction), §8.2.2 (RBG-based),
  §8.3 (invocation limits).
* Cap selection. On the fallback `MaxSeals()` is 2^26, six bits under NIST's
  approved 2^32 ceiling — a 4096× margin on collision probability,
  `P ≈ 2^-45` — which still reaches 256 TiB at the 4 MiB maximum segment size,
  5× the epic's 50 TiB target. 2^24 (`P ≈ 2^-49`) would reach only 64 TiB and
  was rejected as too tight.
* Go's own approved deterministic GCM,
  `crypto/internal/fips140/aes/gcm.NewGCMWithCounterNonce` (FIPS 140-3 IG C.H
  Scenario 3), is unexported and uses a 32-bit prefix with a 64-bit
  strictly-increasing counter — close in spirit to this construction, but
  incompatible with our 8‖4 split. It is the right citation for *why* the
  fallback exists, not a path out of it.
* API shape precedent: libsodium `crypto_secretstream`, Google Tink
  `StreamingAEAD`, Rust `aead::stream`, and the AWS Encryption SDK all expose a
  keyed object built from a per-message random value, with no raw nonce bytes
  in the public API.
* Peer tickets: DSPX-4493 (this work), DSPX-4495 (java-sdk), DSPX-4496
  (web-sdk, merged; `lib/tdf3/src/ciphers/gcm-iv-counter.ts`). The FIPS
  fallback and its 2^26 cap are **Go-specific and should not be mirrored**.
  DSPX-4492 owns risk quantification for the existing construction; DSPX-4905
  owns the unmeasurable-stream segment ceiling.
