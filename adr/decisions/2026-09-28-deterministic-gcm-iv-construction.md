---
# Required
status: 'proposed'
date: '2026-10-15'
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

The Go SDK encrypted every payload segment with `cipher.NewGCMWithRandomNonce`:
NIST SP 800-38D **§8.2.2 (RBG-based)** IVs. Over `n` random 96-bit IVs the
collision probability is about `n²/2^97`, and §8 caps it at 2^-32 per key.

The parent epic (DSPX-4502) targets 50 TiB payloads. At the 16 KiB minimum
segment size that is 2^31.6 segments and `P ≈ 2^-33.7`, essentially on NIST's
ceiling. #4203 (DSPX-4492) added a hard stop, `ErrAESGCMExhausted` after
2^32-1 encryptions per DEK, but with random IVs uniqueness is still a
probability.

An IV collision under one key exposes the XOR of the two plaintexts **and** the
GHASH subkey, which forges tags for everything else under that key.

Two decisions follow: **how to construct the IV**, and **what to do where Go
will not let us construct it that way** (FIPS 140-3).

## Decision Drivers

* The wire format must not change, and TDFs written before this change must
  keep decrypting.
* `chunkedWriter.WriteSegment(ctx, index, data)` accepts sparse, out-of-order
  and concurrent indices, and a failed write may be retried.
* Readers must not be able to tell the SDKs' constructions apart; web-sdk
  (DSPX-4496) has already merged a counter.
* Enabling FIPS 140-3 should need no change outside `lib/ocrypto`.
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
* Detect policy, fall back to random IVs, keep the 2^32-1 cap
* Detect policy, fall back to random IVs, reduce the cap to 2^26
* Probe `cipher.NewGCM` only
* `fips140.WithoutEnforcement`
* Require Go 1.26 and branch on `fips140.Enforced()`

## Decision Outcome

Chosen: **§8.2.1 deterministic, stateful**:
`IV = 64-bit per-sealer random fixed field ‖ 32-bit big-endian counter`. An
`ocrypto.AesGcmSealer` owns one key, its fixed field and an atomic counter;
every `Seal` takes the next value. The writer holds one sealer for the DEK, and
each sealing of key access metadata uses a throwaway sealer of its own.

Chosen: **detect policy, fall back to random IVs, keep the 2^32-1 cap**.
`ocrypto` checks `fips140.Enabled()`, then probes `cipher.NewGCM`, once per
process. The fallback is internal and total: same API, same wire bytes, same
`MaxSeals()`. On that path the counter no longer builds the IV but is still the
key's encryption budget, so there is one counter and one error
(`ocrypto.ErrSealerExhausted`, reported as `ErrAESGCMExhausted`).

The cross-SDK rules are in virtru-corp/adr#368, which asks for a 2^26 cap in
FIPS mode. The Go supplement, virtru-corp/adr#373, records why Go keeps 2^32-1.

### Consequences

* 🟩 **Good**, because uniqueness under one sealer is a property of the
  counter, not a probability, so the birthday bound no longer limits payload
  size.
* 🟩 **Good**, because the wire format is untouched and readers are unchanged.
* 🟩 **Good**, because callers hold no ordinal: every write, including a retry,
  takes a fresh IV, whatever `WriteSegment`'s error handling does.
* 🟩 **Good**, because the state lives with the key and nowhere else: no message
  ID, no key→sealer registry, no reserved metadata slot, no metadata pin.
* 🟩 **Good**, because FIPS mode changes nothing an application can see: the
  cap, the default segment size and the error are the same in every mode.
* 🟥 **Bad**, because in a single-split TDF the metadata key *is* the DEK, and
  the two sealers are kept apart only by their random fixed fields: about
  2^-64 per metadata seal.
* 🟥 **Bad**, because a retried or discarded seal spends a counter value, and
  the IV no longer says which segment it encrypts.
* 🟥 **Bad**, because under FIPS a writer at the cap sits at `P ≈ 2^-33`, a 2×
  margin under NIST's ceiling. (At the 2 MiB default, 50 TiB is `P ≈ 2^-47.7`.)
* 🟥 **Bad**, because in non-FIPS builds Go's service indicator records segment
  encryption as non-approved. Nobody reads it outside FIPS mode, and in FIPS
  mode the fallback keeps it approved.

## Validation

* `lib/ocrypto/message_sealer_test.go` pins the IV byte layout with
  known-answer tests against fixtures, by seeding the fixed field and counter.
  These recover the auditability an opaque API gives up, so they are not
  optional. It also covers exhaustion without wrap, concurrent counters and
  distinct fixed fields per sealer.
* `sdk/chunked_iv_test.go` covers out-of-order, concurrent and retried writes,
  metadata on its own sealer, and metadata changing between manifest builds.
  `sdk/chunked_test.go` and `sdk/tdf_test.go` cover `ErrAESGCMExhausted`.
* The SDK suite passes under `GODEBUG=fips140=on`, which is the claim that the
  fallback is invisible above `ocrypto`.

## Pros and Cons of the Options

### IV construction

#### Keep RBG-based IVs (§8.2.2)

What #4203 ships, with its hard stop.

* 🟩 **Good**, because it needs no change and is approved everywhere.
* 🟥 **Bad**, because uniqueness stays probabilistic, at NIST's ceiling for
  50 TiB at small segment sizes.

#### §8.2.1 deterministic, stateless

`IV = per-message ID ‖ part number`, part 0 for metadata and segment `i` at
part `i + 1`. The first implementation (#4118).

* 🟩 **Good**, because it needs no shared state, and an IV identifies its
  segment.
* 🟥 **Bad**, because a retry re-derives the same IV, so retry safety depends
  on `WriteSegment` never emitting bytes on a path that later fails.
* 🟥 **Bad**, because the single reserved metadata part needed a key→sealer
  registry, a message ID threaded through key access resolution, and a pin
  refusing changed metadata (`ErrChunkedMetadataChanged`).

#### §8.2.1 deterministic, stateful (chosen)

Also web-sdk's `GcmIvCounter.next()`.

* 🟩 **Good**, because the caller cannot repeat an IV, and the hot path is one
  atomic add.
* 🟥 **Bad**, because retries spend budget, and out-of-order writes lose the
  index↔IV correspondence.

#### Per-segment key derivation

* 🟩 **Good**, because IV reuse across segments stops mattering.
* 🟥 **Bad**, because it changes the format for all three SDKs, for a problem
  the writer can solve alone.

### FIPS strategy

#### Hard error where a caller-supplied IV is unavailable

* 🟥 **Bad**, because enabling FIPS would break every writer.

#### Detect policy, fall back, keep the 2^32-1 cap (chosen)

* 🟩 **Good**, because the policy check catches `fips140=on`, where
  `cipher.NewGCM` works but its `Seal` is non-approved, and the probe catches
  `fips140=only` and anything unforeseen.
* 🟩 **Good**, because it needs only Go 1.24 (`fips140.Enabled()`).
* 🟩 **Good**, because applications cannot tell the modes apart.
* 🟥 **Bad**, because `Seal` keeps two code paths, and the fallback's worst case
  is at NIST's ceiling rather than well under it.

#### Detect policy, fall back, reduce the cap to 2^26

The first version of both #4118 and #4121, written before #4203.

* 🟩 **Good**, because `P ≈ 2^-45` at the cap, a 4096× margin.
* 🟥 **Bad**, because it needs a FIPS-only default segment size (4 MiB) to keep
  large payloads reachable, making FIPS visible to applications.
* 🟥 **Bad**, because it shrinks what FIPS builds can write after #4203: from
  about 8 PiB to 128 TiB at 2 MiB segments.

#### Probe `cipher.NewGCM` only

* 🟥 **Bad**, because it silently keeps deterministic IVs under `fips140=on` —
  a production FIPS deployment — making every segment encryption
  non-approved.

#### `fips140.WithoutEnforcement`

* 🟥 **Bad**, because it is Go 1.26, and it silently disables an enforcement the
  operator asked for.

#### Require Go 1.26 and branch on `fips140.Enforced()`

* 🟥 **Bad**, because it puts a Go 1.26 floor on a published module for a
  distinction `fips140.Enabled()` plus a probe already covers.

## More Information

* NIST SP 800-38D §8.2.1 (deterministic), §8.2.2 (RBG-based), §8.3 (limits).
* A caller that wants more margin under FIPS can use larger segments; halving
  the segment count quarters `P`.
* Go's own approved deterministic GCM, `NewGCMWithCounterNonce` (FIPS 140-3
  IG C.H Scenario 3), is unexported and uses a 32-bit prefix with a 64-bit
  counter, which does not match this 8‖4 layout.
* API precedent: libsodium `crypto_secretstream`, Tink `StreamingAEAD`, Rust
  `aead::stream` and the AWS Encryption SDK expose keyed objects with no raw
  nonces.
* Tickets: DSPX-4493 (this work), DSPX-4495 (java-sdk), DSPX-4496 (web-sdk).
  The FIPS fallback is **Go-specific and should not be mirrored**. DSPX-4492
  owns risk quantification and `ErrAESGCMExhausted` (#4203); DSPX-4905 owns the
  rest of the unmeasurable-stream work.
