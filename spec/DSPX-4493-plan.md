---
ticket: DSPX-4493
title: Implementation plan — deterministic AES-GCM IVs for the Go SDK's ZTDF writer
status: draft
authors:
    - dmihalcik@virtru.com
branches:
    - opentdf/platform:DSPX-4493-stateful-iv
prs:
    - opentdf/platform#4121
created: 2026-09-28T00:00:00Z
updated: 2026-10-15T00:00:00Z
spec: ./DSPX-4493.md
---

# DSPX-4493 — Implementation plan

The design is in [DSPX-4493.md](./DSPX-4493.md) and the decision in
`adr/decisions/2026-09-28-deterministic-gcm-iv-construction.md`. This file
records how it was built and how to verify it.

## History

1. **Stateless (#4118).** `IV = per-message ID ‖ part number`, with part 0
   reserved for metadata and segment `i` at part `i + 1`. Making that safe
   needed a message ID threaded through key access resolution, a key→sealer
   registry, and a pin refusing changed metadata. Rejected.
2. **Stateful (#4121).** A per-key counter inside `ocrypto.AesGcmSealer`,
   removing all of the above.
3. **Rebased onto #4203**, which had added `ErrAESGCMExhausted` and a 2^32-1
   cap on random IVs. The FIPS fallback's 2^26 cap and derived 4 MiB default
   segment size were dropped in favour of #4203's cap in every mode
   (option 2b, virtru-corp/adr#373).

## Implementation

### `lib/ocrypto`

- `AesGcmSealer`: key, random 64-bit fixed field, `atomic.Uint64` counter.
  `Seal` takes `next.Add(1) - 1` and refuses at `maxSeals` (2^32-1) before
  encrypting.
- `deterministicIVs`: `sync.OnceValue` that returns false if
  `fips140.Enabled()`, or if `cipher.NewGCM` fails. The sealer then uses
  `cipher.NewGCMWithRandomNonce` and splits the IV back off the output.
- `newAESGcmSealer` is the injectable form: tests pin the fixed field, choose
  the path, and lower the limit.

### `sdk`

- The chunked writer builds one sealer for the DEK through
  `segmentSealerFactory` and calls it from `WriteSegment`.
  `ocrypto.ErrSealerExhausted` is wrapped as `ErrAESGCMExhausted`. There is no
  second counter in the writer.
- `encryptMetadata` builds a throwaway sealer per seal.
- `maxPayloadSegments` is `MaxInt32` (archive addressing). `WriteSegment`
  rejects a larger index with `ErrChunkedSegmentIndexExhausted` before
  reserving it.
- Segment sizes are the same in every FIPS mode: 2 MiB default, 4 MiB max, 16 KiB min.
- Test seams: `withChunkedSealerFactory` and `withSegmentSealerFactory`. The
  exhaustion tests inject a sealer that enforces a small limit.

### Tests

- `lib/ocrypto/message_sealer_test.go`: layout and known answers, exhaustion
  without wrap, concurrent counters, distinct fixed fields per sealer, the
  random fallback.
- `sdk/chunked_iv_test.go`: segment IV layout, out-of-order and concurrent
  writes, fresh IV on retry, metadata on its own sealer (chunked writer and
  `CreateTDF`), metadata changing between builds, the index ceiling.
- `sdk/chunked_test.go`, `sdk/tdf_test.go`: `ErrAESGCMExhausted` from the
  writer and from `CreateTDF`, refusal before encrypting, attempts counted.

## Verification

```bash
make fmt
make lint                                     # 0 new issues
make test                                     # -race, all modules
(cd sdk && go test -run TestREADMECodeBlocks)
```

FIPS: the same suites must pass with the fallback selected. Tests that assert
header bytes skip or relax to a uniqueness check; everything else runs.

```bash
(cd lib/ocrypto && GODEBUG=fips140=on go test ./...)
(cd sdk && GODEBUG=fips140=on go test ./...)
GOFIPS140=certified go test ./...             # how a FIPS build is made
```

Cross-SDK (the backward-compatibility check):

```bash
gh workflow run xtest.yml --repo opentdf/tests --ref main \
  -f platform-ref=DSPX-4493-stateful-iv -f otdfctl-ref=DSPX-4493-stateful-iv \
  -f java-ref=main -f js-ref=main
```

Confirm the Go client resolved to this branch's SHA, and that the ZTDF
round-trips ran rather than `SKIPPED`.

Spot check with FIPS off: across a file's segments, the first 8 bytes are
constant and the last 4 count 0, 1, 2, …
