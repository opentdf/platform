# BaseTDF 5.0 — Scale and Detached Storage

| | |
|---|---|
| **Status** | Draft / Design Goals |
| **Target** | BaseTDF suite v5.0.0 |
| **Baseline** | TDF 4.x, as specified by the BaseTDF suite v4.4.0 in [`spec/basetdf/`](../basetdf/) |
| **Audience** | Spec editors, SDK implementers, and agents tasked with executing the work below |

> **On version numbering:** every gap identified here is present throughout the 4.x
> line — the integrity model is explicitly unchanged since 4.3.0
> ([`basetdf-int.md:56-60`](../basetdf/basetdf-int.md)) — so "current spec" means
> all of 4.x unless a specific minor version is named. Section 3 argues for why this
> work must ship as a major version rather than 4.5.0.

---

## 1. Purpose

BaseTDF today assumes a TDF is produced by one process, from a source of known
length, into one file, and consumed by one process reading it end to end. That
assumption is nowhere stated but is baked into the container format, the integrity
model, and the reference SDK.

This document defines five goals that break that assumption, analyzes precisely
where the current format fails each, and specifies the format changes and
reference-implementation work needed to close the gap.

It is written to be executable: Section 6 contains normative-draft text and wire
formats concrete enough to amend the spec from, Section 7 maps the change onto
suite documents, Section 8 maps it onto specific files and symbols in the Go SDK,
and Section 9 sequences the work.

---

## 2. Summary of the change

Two independent problems, one release:

**Scale.** The manifest carries one JSON record per payload segment. At the 2 MiB
default segment size that fixes the manifest at ~1/23,000 of payload size — a 1 TiB
object needs a ~47 MB manifest — and the root signature is a flat MAC over all N
segment hashes that must be verified before *any* segment is decrypted. Streaming,
distributed writes, and random access all break on this.

**Coupling.** The manifest and payload are welded into a single ZIP. That forces
every party who touches the object to touch all of it: whoever stores the payload
also stores the policy, the attribute FQNs, and the KAS URLs. Detaching them lets
a manifest host and a payload host each hold half, with neither able to reconstruct
the object alone.

The two are related. Detached manifests are only useful if a manifest is small
enough to serve as an API-scale object, which is exactly what the scale work
delivers. And a detached manifest makes a manifest-level signature necessary, which
is a requirement that does not exist today.

---

## 3. Why 5.0

### 3.1 The existing version rules make 4.5 worse than 5.0

[`basetdf-core.md:366-367`](../basetdf/basetdf-core.md) requires readers to reject a
manifest whose major version is not `4`. But
[`basetdf-core.md:544`](../basetdf/basetdf-core.md) instructs readers to treat an
unknown *minor* version within major 4 as "the closest known version."

So an incompatible 4.5.0 object handed to a 4.4 reader is silently coerced into a
4.4 interpretation and then fails somewhere confusing — a missing `segments` array,
a `payload.url` that isn't `0.payload`. Whereas a 5.0.0 object is rejected cleanly
by a rule that is already written and already implemented.

The version rules already give correct negotiation behavior for a major bump. Use it.

### 3.2 The changes are breaking by any reading

- `payload.url` MUST be `"0.payload"`, `payload.protocol` MUST be `"zip"`,
  `payload.type` MUST be `"reference"` ([`basetdf-core.md:230-232`](../basetdf/basetdf-core.md)).
- The archive MUST contain exactly two entries and writers MUST NOT add extras
  ([`basetdf-core.md:125-127`](../basetdf/basetdf-core.md)).
- `integrityInformation.segments` is REQUIRED ([`basetdf-int.md:156`](../basetdf/basetdf-int.md)).
- Design Principle 1 is self-containment ([`basetdf-core.md:69-72`](../basetdf/basetdf-core.md)),
  and [`basetdf-sec.md:118-122`](../basetdf/basetdf-sec.md) grounds NIST SP 800-207
  Tenet 1 in it specifically.

Each of these has to move. That last one in particular means the security model
document changes, not just the container document — reviewers will notice, so the
rewrite should land in the same change (see §6.10).

### 3.3 The suite's own framing points here

[`README.md:4-7`](../basetdf/README.md) states the suite is factored after JOSE.
The right precedent is JWS: **one object, multiple serializations** (compact and
JSON). BaseTDF 5.0 should say exactly that — one manifest, several *packagings*:
attached, detached, sharded.

This framing matters practically. It keeps the self-contained ZIP as a first-class
5.0 profile rather than a deprecated legacy mode, so the majority of users who never
need detachment get a mechanical 4.4→5.0 migration.

### 3.4 Charter — what 5.0 does NOT touch

A major version is an invitation to reopen everything. It should be refused
explicitly. In scope: **packaging, integrity, and key derivation.**

| Document | 5.0 status |
|---|---|
| BaseTDF-CORE | Refactored — abstract manifest; packaging moves out |
| BaseTDF-INT | Extended — Merkle, uniform layout, partial verification |
| BaseTDF-SEC | Extended — compartmentalization model, Tenet 1 rewrite |
| BaseTDF-ALG | Extended — new registry entries only |
| BaseTDF-ASN | Extended — `scope: "manifest"` |
| BaseTDF-PKG | **New** — packaging profiles |
| BaseTDF-LOC | **New** — resource locators |
| BaseTDF-KAO | **Frozen** |
| BaseTDF-POL | **Frozen** |
| BaseTDF-KAS | **Frozen** |

Policy language changes, KAS protocol changes, and new PQC work are explicitly
out of scope and MUST NOT be bundled. They can ship as 5.1.

---

## 4. Goals

### G1 — Large-scale streaming writes

A writer MUST be able to produce a TDF in a single forward pass over a plaintext
source **of unknown length**, using memory bounded independently of payload size,
without buffering the payload or rewriting any part of the output.

- `encrypt(io.Reader) -> io.Writer`; no `Seek`, no `Stat`, no content-length.
- Resident memory O(log N) in segment count for integrity state, plus one segment
  buffer. O(N) state MAY spill to temporary storage but MUST NOT be resident.
- A 100 TiB TDF is representable and readable by a conformant reader.
- Valid output on the first pass; no finalize-time seek-back to patch headers.

### G2 — Distributed (map/reduce) writes

N workers with no shared state beyond a job description MUST each be able to
encrypt a disjoint plaintext range, and a reducer MUST assemble a valid TDF from
their outputs without reading ciphertext.

- Worker for range `[a, b)` needs no communication with other workers.
- Reduce input is O(1) metadata per worker plus fixed-size hashes — never ciphertext.
- Assembly is expressible as an S3 multipart upload using `UploadPartCopy`
  (server-side, no egress through the reducer).
- **No worker holds a key capable of decrypting a range it was not assigned.**
- Result is a single TDF, not N TDFs.

### G3 — Constant-overhead random access reads

Reading `k` bytes at an arbitrary offset in an `L`-byte payload MUST cost
`O(k) + O(polylog(L/S))` bytes of I/O and compute, for segment size `S`.

- Cold single-byte read at offset `L/2` of a 1 TiB TDF: ≤ 64 KiB of I/O beyond the
  KAS rewrap round trip and the segment itself.
- Plaintext-offset → payload-offset is closed-form arithmetic, not a scan.
- Integrity for returned bytes is equivalent to a full sequential read: the segment
  is provably the one the writer placed at that index, in an object whose total
  segment count is authenticated.

### G4 — Detached manifest and payload

A manifest MUST be publishable and servable as a standalone document, referencing a
payload stored and served independently, such that:

- The **payload host** observes opaque ciphertext and nothing else — no policy, no
  attribute FQNs, no KAS URLs, no assertions, no MIME type.
- The **manifest host** observes metadata and never observes ciphertext.
- Neither party alone can reconstruct the protected object.
- Manifest→payload binding is cryptographic and survives detachment: substituting
  the payload MUST fail verification.
- A reader MUST be able to validate a manifest's integrity and provenance
  **before** dereferencing any locator it contains.

> **Scoping note.** G4 delivers *compartmentalization between hosts*. It does **not**
> make metadata confidential from the manifest host — policy, attribute FQNs, and
> KAS URLs remain cleartext to whoever serves the manifest
> ([`basetdf-core.md:585-600`](../basetdf/basetdf-core.md)). Confidential policy is
> a distinct problem requiring encrypted policy objects, and is **out of scope for
> 5.0**. This distinction must be stated plainly in BaseTDF-SEC so the property is
> not oversold.

### G5 — Multiple manifests over one payload

It MUST be possible to publish additional manifests against an existing payload,
each with its own policy and KAO set, without re-encrypting the payload.

- Re-sharing a 1 PiB dataset to a new audience costs a rewrap and a small manifest.
- The security semantics of doing so must be specified, not left implicit (see
  §6.10.2 — the effective access set is the *union* across manifests).

---

## 5. Gap analysis

### 5.1 Summary

| Goal | Verdict | Root cause |
|---|---|---|
| G1 Streaming writes | Partially met | Manifest grows O(N); ZIP streaming unspecified |
| G2 Distributed writes | Partially met | Every worker needs the full DEK; single-blob container |
| G3 Random access | **Not met** | Flat root signature over all N hashes, verified before any decrypt |
| G4 Detached storage | **Not possible** | Container rules forbid it; manifest is unauthenticated as a whole |
| G5 Multi-manifest | **Not possible** | Manifest is welded into the payload's container |

### 5.2 Manifest size scales with payload size

Segment size is capped at 4 MiB, default 2 MiB
([`basetdf-int.md:352-358`](../basetdf/basetdf-int.md)). A `segments[i]` entry
serializes to ~89 bytes with GMAC, ~109 with HS256 — a manifest-to-payload ratio of
roughly **1:23,000**:

| Payload | Segments @ 2 MiB | Manifest (GMAC) | Aggregate hash to MAC |
|---|---|---|---|
| 1 GiB | 512 | ~46 KB | 8 KiB |
| 100 GiB | 51,200 | ~4.6 MB | 800 KiB |
| 1 TiB | 524,288 | **~47 MB** | 8 MiB |
| 100 TiB | 52,428,800 | **~4.7 GB** | 800 MiB |
| 1 PiB | 536,870,912 | **~48 GB** | 8 GiB |

Raising to the 4 MiB maximum buys exactly 2×.

This contradicts [`basetdf-core.md:615`](../basetdf/basetdf-core.md), which tells
implementations to "enforce a maximum manifest size to prevent memory exhaustion."
The spec offers no reconciliation.

**The reference SDK has already hit this.** `sdk/internal/zipstream/tdf3_reader.go:15`
sets `manifestMaxSize = 10 MB`. At ~89 bytes/segment and 2 MiB segments that is a
hard ceiling of roughly **230 GiB per TDF** (~190 GiB with HS256 segment hashes)
before `LoadTDF` refuses the object. A real, shipped limit that no part of the
specification acknowledges.

It is also what makes G4 non-viable today: a 47 MB manifest cannot be served as an
API-scale document.

### 5.3 Random access requires full metadata ingestion

Both verification procedures — non-streaming
([`basetdf-int.md:378-388`](../basetdf/basetdf-int.md)) and streaming
([`basetdf-int.md:416-422`](../basetdf/basetdf-int.md)) — require root signature
verification *before any segment is decrypted*, and the root signature needs all N
segment hashes. There is no sanctioned mode for verifying one segment in isolation.

A cold one-byte read from a 1 TiB TDF therefore costs a 47 MB range GET, a 47 MB
JSON parse, 524,288 base64 decodes, and an HMAC over 8 MiB — before touching the
payload. Payload I/O is O(1); metadata is not.

Secondary:

- [`basetdf-int.md:340-342`](../basetdf/basetdf-int.md) uses **SHOULD**, not MUST,
  for interior segments matching `segmentSizeDefault`, so a strictly conformant
  reader cannot use closed-form offset arithmetic.
- [`basetdf-int.md:390`](../basetdf/basetdf-int.md) says "for each segment `i` **in
  order**." Reading segment 40,000 alone is neither described nor blessed.

The reference SDK shows the cost: `Reader.ReadAt` (`sdk/tdf.go:994`) loops
`for index, seg := range r.manifest.Segments` from index 0 on **every call** — an
O(N) scan per read. It also mixes models, computing `start`/`startIndex` from
`DefaultSegmentSize` arithmetic while deriving physical offsets from the per-segment
`EncryptedSize` scan. Those disagree the moment an interior segment is short, which
the spec currently permits.

### 5.4 Streaming writes: ZIP mechanics unspecified

A ZIP local file header carries CRC-32 and both sizes *before* the entry data.
Unknown-length entries require general-purpose bit 3 and a trailing data descriptor.
The spec never mentions this. It cites "local file headers precede file data,
enabling progressive reading" ([`basetdf-core.md:112`](../basetdf/basetdf-core.md))
while mandating ZIP64 above 4 GiB
([`basetdf-core.md:128-130`](../basetdf/basetdf-core.md)) — a threshold a streaming
writer cannot evaluate in advance.

The reference SDK does not attempt it: `CreateTDFContext` takes an `io.ReadSeeker`
and immediately does `reader.Seek(0, io.SeekEnd)` (`sdk/tdf.go:164-176`).

### 5.5 Distributed writes: the DEK is not divisible

Every segment is encrypted directly under the DEK
([`basetdf-int.md:96`](../basetdf/basetdf-int.md)). No per-segment or per-range
derivation exists. A 1,000-worker fan-out distributes a key that decrypts the
*entire* object to 1,000 processes. The XOR split model splits trust across KAS
instances, not writers, and does not help. For a format premised on zero trust this
is the sharpest mismatch.

### 5.6 What already works — preserve these

- **The reduce is cheap and correct.** `root_sig = HMAC(DEK, h₀‖…‖h_{N-1})` needs
  only ordered fixed-size hashes; the reducer never touches ciphertext.
- **The payload is a pure concatenation**, so assembly maps onto S3 multipart upload
  with server-side `UploadPartCopy`.
- **IV derivation is already partition-friendly** — `basetdf-sec.md:622-624`
  RECOMMENDS `base IV + segment index`.
- **GMAC segment hashing is free** ([`basetdf-int.md:215-219`](../basetdf/basetdf-int.md)).
- **Manifest→payload binding already survives detachment.** This is the most
  under-appreciated fact in the current design: the root signature is an HMAC over
  hashes of the actual ciphertext, keyed with the DEK. That binding never depended
  on the ZIP. Substitute the payload and verification fails. **The format is already
  cryptographically detachable; only the container rules forbid it.**

### 5.7 Detachment: the manifest is unauthenticated as a whole

Policy binding covers the policy per-KAO
([`basetdf-kao.md`](../basetdf/basetdf-kao.md)); the root signature covers the
payload. **Nothing covers** `payload.url`, the KAS URL list, `segmentSizeDefault`,
`mimeType`, or the assertion array's membership.

Inside a ZIP this is tolerable — an attacker who can rewrite the manifest can
usually replace the whole file, and the outcome is a failed verification either way.
Detached, the manifest becomes an independently-fetched, independently-tamperable
document, and `payload.url` becomes a **redirect primitive**: an SSRF gadget and a
DoS vector. It is not a confidentiality break — the DEK-keyed root signature still
catches a substituted payload — but it is a new attack surface that detachment
creates and that 5.0 must answer (P8).

### 5.8 Container rigidity

`payload.type` MUST be `"reference"`, `url` MUST be `"0.payload"`, `protocol` MUST
be `"zip"` ([`basetdf-core.md:230-232`](../basetdf/basetdf-core.md)); exactly two
entries, no extras ([`basetdf-core.md:125-127`](../basetdf/basetdf-core.md)). There
is no representation for a manifest without a payload, a payload without a manifest,
or a payload in more than one piece. G4 and G5 are simply unexpressible.

---

## 6. Proposals

Eleven proposals in three families. Family A is the integrity substrate everything
else builds on; B delivers distribution; C delivers detachment.

| ID | Proposal | Goals | Family |
|---|---|---|---|
| P1 | Merkle root signature | G1, G3 | A |
| P2 | Uniform layout: implicit segment index | G1, G3, G4 | A |
| P3 | Externalized hash tree | G1, G3 | A |
| P4 | Partition key derivation | G2 | B |
| P5 | Normative deterministic IV | G2 | B |
| P6 | ZIP streaming-write profile | G1 | B |
| P7 | Packaging profiles | G4, G5 | C |
| P8 | Manifest signature | G4 | C |
| P9 | Resource locators and fetch policy | G4 | C |
| P10 | Multi-manifest semantics | G5 | C |
| P11 | Consistency proofs / append-only payloads | G4 | C |

### Design constraints

1. **Existing TDFs remain readable.** No change may invalidate a 4.3.0 or 4.4.0
   object. Legacy hex-encoding handling
   ([`basetdf-int.md:457-509`](../basetdf/basetdf-int.md)) stays.
2. **The DEK remains the root of trust for payload integrity.** New constructions
   are keyed from the DEK, not a new independent secret. P8 is the deliberate
   exception and is scoped to *manifest* integrity, not payload integrity.
3. **No new pre-decryption trust surface.** Anything consumed before verification
   must be authenticated under the DEK, or size-bounded and structurally validated,
   or covered by P8.
4. **Small TDFs must not get worse.** The common case is a payload under 100 MB.
   New machinery is opt-in and adds no round trips, entries, or manifest bytes to
   small attached objects.
5. **GMAC-free-hashing is preserved.** No new leaf construction may force a second
   pass over ciphertext at write time.

---

### Family A — Integrity substrate

#### P1 — Merkle root signature

**Problem:** the flat concat root signature forces O(N) work to authenticate any
single segment.

New `rootSignature.alg` value: `MERKLE-HS256`.

Leaves preserve the existing segment hash (so GMAC stays free) and add index binding:

```
L_i = HMAC-SHA256(DEK, 0x00 || u32be(i) || segment_hash_i)
```

`segment_hash_i` is exactly the value from
[`basetdf-int.md §4`](../basetdf/basetdf-int.md) — GMAC tag or HMAC — unchanged.
Index binding prevents transplanting a valid segment to a different position.

Internal nodes:

```
N = HMAC-SHA256(DEK, 0x01 || left || right)
```

All nodes 32 bytes. On an odd level the last node is **promoted** unchanged (not
duplicated). Promotion is safe only because the leaf count is bound into the root:

```
root_signature = HMAC-SHA256(DEK, 0x02 || u64be(segmentCount) || tree_root)
```

Base64-encoded into `rootSignature.sig` as today. Domain separators
`0x00`/`0x01`/`0x02` prevent leaf/internal/root confusion.

**Inclusion proof:** `ceil(log2(N))` sibling nodes — 20 nodes (640 bytes) for 1 TiB
at 2 MiB segments.

**Streaming build:** a stack of at most `ceil(log2(N))` partial internal nodes; fold
each leaf as produced. Root available at finalize with O(log N) resident state.

**Verification** (replaces [`basetdf-int.md §7`](../basetdf/basetdf-int.md) step 2
when `alg` is `MERKLE-HS256`):

- *Full read:* recompute leaves, rebuild tree, compare. Same cost as today.
- *Partial read:* fetch the inclusion proof for segment `i`, recompute `L_i` from
  fetched ciphertext, fold the proof, bind `segmentCount`, compare. Readers MUST
  reject if proof length disagrees with the length implied by `segmentCount`
  accounting for promotions.

#### P2 — Uniform layout: implicit segment index

**Problem:** the inline `segments` array is the entire manifest-size problem, and
under uniform segmentation it is fully derivable.

Add `integrityInformation.layout`: `"explicit"` (default, current behavior) or
`"uniform"`. When `"uniform"`:

- Segments `0 … N-2` MUST be exactly `segmentSizeDefault` bytes — upgrade the SHOULD
  at [`basetdf-int.md:340-342`](../basetdf/basetdf-int.md) to MUST for this layout.
- `segmentCount` and `lastSegmentSize` become REQUIRED.
- `segments` becomes OPTIONAL and SHOULD be omitted.
- Segment hashes come from the hash tree (P3).

The manifest becomes **constant size** regardless of payload:

```json
"integrityInformation": {
  "rootSignature": { "alg": "MERKLE-HS256", "sig": "<base64>" },
  "segmentHashAlg": "GMAC",
  "segmentSizeDefault": 2097152,
  "encryptedSegmentSizeDefault": 2097180,
  "layout": "uniform",
  "segmentCount": 524288,
  "lastSegmentSize": 1048576,
  "hashTree": { "nodeSize": 32, "levels": 20, "locator": { "...": "see P9" } }
}
```

**Offset arithmetic (normative for `uniform`).** For plaintext offset `B`:

```
i           = floor(B / segmentSizeDefault)
intraOffset = B mod segmentSizeDefault
physOffset  = payloadStart + i * encryptedSegmentSizeDefault
```

Closed form, O(1). Stating this normatively is what lets a reader skip the segments
array entirely — the property G3 depends on.

**Writer guidance:** select `explicit` below a configurable threshold (RECOMMENDED
4,096 segments ≈ 8 GiB), `uniform` above.

#### P3 — Externalized hash tree

**Problem:** the tree must live somewhere range-readable so a partial reader fetches
~640 bytes instead of the whole structure.

The tree is a distinct artifact addressed by a locator (P9). In the attached
packaging it is a third ZIP entry, `0.integrity`; in detached packaging it is a
separate object, or MAY be inlined into the manifest as base64 when small
(RECOMMENDED threshold: 64 KiB, i.e. ~1,000 segments).

Attached entry order MUST be `0.payload`, `0.integrity`, `0.manifest.json` — payload
first so streaming readers are unaffected; the tree is written at finalize when the
leaf set is complete.

**Binary format** (little-endian; nodes are opaque 32-byte values):

```
offset  size  field
0       8     magic       "BTDFMT\x01\x00"
8       4     version     u32 = 1
12      1     nodeSize    u8 = 32
13      1     levels      u8 = ceil(log2(leafCount)) + 1
14      2     reserved    MUST be zero
16      8     leafCount   u64
24      8     nodeCount   u64
32      ...   nodes       level-order: level 0 (leaves), then level 1, ...
```

Level `l` has `ceil(leafCount / 2^l)` nodes; its byte offset is
`32 + 32 * Σ_{j<l} ceil(leafCount / 2^j)`. Both closed-form, so a reader computes
any proof node's byte range arithmetically with no index.

**Sizing.** ~`2N` nodes = 64 bytes/segment stored — comparable to today's 89-byte
JSON entry — but the reader **fetches** only `O(log N)`:

| Payload | Tree stored | Fetched per random read |
|---|---|---|
| 1 GiB | 33 KB | 320 B (10 nodes) |
| 1 TiB | 34 MB | 640 B (20 nodes) |
| 1 PiB | 34 GB | 960 B (30 nodes) |

**Trust.** The tree is unauthenticated on its own — fine, because every node
consumed folds into a computation checked against `rootSignature.sig`, HMAC'd under
the DEK. A tampered tree yields a root mismatch. Readers MUST bound reads by the
header's `nodeCount` and MUST validate `nodeCount` against `leafCount` before
allocating.

**Streaming write.** Buffer leaf hashes (32 B/segment — 16 MB per TiB) and emit the
tree at finalize. Per G1 this MAY spill to temporary storage; only the O(log N)
folding stack must be resident.

---

### Family B — Distribution

#### P4 — Partition key derivation

**Problem:** distributed writers each need the whole DEK.

Add OPTIONAL `encryptionInformation.keyDerivation`. Absent → segments encrypted
directly under the DEK (current behavior). Present:

```json
"keyDerivation": { "alg": "HKDF-SHA256", "partitionSegments": 512 }
```

```
p   = floor(i / partitionSegments)
K_p = HKDF-Expand(PRK = DEK, info = "BaseTDF-part-v1" || u64be(p), L = 32)
```

Segment `i` is encrypted with `K_p`. With `segmentHashAlg: GMAC` the hash is the tag
under `K_p` — still free. With `HS256` the segment HMAC is keyed with `K_p`.

Merkle leaves, internal nodes, and the root signature stay keyed under the **DEK**,
so integrity remains a whole-object property and no worker can forge a root. A
worker computes its segments' *hashes* but not their leaves; the reducer, holding
the DEK, applies `L_i = HMAC-SHA256(DEK, 0x00 || u32be(i) || segment_hash_i)` — one
HMAC over 20 bytes per segment, ~500k HMACs for 1 TiB, well under a second.

**Security property delivered:** a worker assigned partition `p` receives only
`K_p`, decrypting exactly `partitionSegments × segmentSizeDefault` bytes — its
assigned range and nothing more. This is what G2 requires. At 512 × 2 MiB = 1 GiB
per partition, a 1 TiB job is 1,024 workers each holding a 1 GiB-scoped key.

Not forward-secret; no protection against a worker that separately obtains the DEK.
It scopes *distribution*, which is the actual operational risk.

#### P5 — Normative deterministic IV

**Problem:** `basetdf-sec.md:622-624` only RECOMMENDS counter IVs, so distributed
writers cannot rely on stateless IV assignment interoperating, and readers cannot
detect nonce reuse.

Upgrade to MUST for `layout: "uniform"`, using NIST SP 800-38D §8.2.1:

```
IV_i = noncePrefix (4 bytes) || u64be(i)
```

`noncePrefix` is 4 CSPRNG bytes per TDF, recorded in
`encryptionInformation.method.noncePrefix`. The IV remains prepended to each
segment, so the wire format is unchanged — but a 5.0 reader MUST verify the
prepended IV matches the derived value and MUST reject on mismatch. That converts a
silent catastrophic failure (nonce reuse) into a detected one. Uniqueness holds for
`i < 2^64`; with P4, `i` is globally unique so uniqueness holds per-`K_p` too.

#### P6 — ZIP streaming-write profile

**Problem:** unspecified ZIP mechanics for unknown-length input.

Normative, in BaseTDF-PKG:

- A writer without advance knowledge of payload length MUST set general-purpose bit
  3 on the `0.payload` local file header, write zeros for CRC-32 and both sizes, and
  emit a ZIP64 data descriptor (8-byte sizes) immediately after the entry data.
- Such a writer MUST use ZIP64 unconditionally — ZIP64 extra field on the local
  header, ZIP64 EOCD record and locator. It MUST NOT decide based on final size.
- CRC-32 computed incrementally over encrypted payload bytes.
- `0.integrity` and `0.manifest.json` have known sizes and MUST NOT use data
  descriptors.
- Readers MUST support data descriptors on `0.payload` and MUST prefer central
  directory values when the two disagree — the central directory is authoritative.

Non-normative: a writer with known length SHOULD use the non-streaming form, which
is readable by strictly size-prefix-dependent parsers.

---

### Family C — Packaging and detachment

#### P7 — Packaging profiles

Split "what a TDF *is*" from "how it is *stored*", as JWS splits object from
serialization. New top-level manifest field `packaging`:

| Value | Description |
|---|---|
| `"attached"` | Single ZIP: `0.payload` [`0.integrity`] `0.manifest.json`. The 4.x shape. |
| `"detached"` | Manifest is a standalone JSON document; payload is one independently-addressed object. |
| `"sharded"` | Detached, with payload split across N independently-addressed parts. |

**Attached** (default; unchanged from 4.4 apart from the optional third entry):

```json
"packaging": "attached",
"payload": {
  "type": "reference", "url": "0.payload", "protocol": "zip",
  "mimeType": "text/plain", "isEncrypted": true
}
```

**Detached:**

```json
"packaging": "detached",
"payload": {
  "type": "detached",
  "mimeType": "text/plain",
  "isEncrypted": true,
  "size": 1099511627776,
  "locators": [
    { "uri": "https://vfs.customer.example/objects/9f2a", "priority": 0 },
    { "uri": "s3://customer-bucket/tdf/9f2a", "priority": 1 }
  ]
}
```

Multiple priority-ordered locators give mirroring and let the customer host the
payload wherever they choose while a third party serves manifests.

**Sharded** adds `parts`, each covering a segment range:

```json
"packaging": "sharded",
"payload": {
  "type": "detached", "mimeType": "application/octet-stream", "isEncrypted": true,
  "size": 1099511627776,
  "parts": [
    { "index": 0, "segmentRange": [0, 512], "size": 1073756160, "locators": [ ... ] },
    { "index": 1, "segmentRange": [512, 1024], "size": 1073756160, "locators": [ ... ] }
  ]
}
```

Parts MUST be ordered, contiguous, non-overlapping, and segment-aligned; readers
MUST reject a `parts` array violating any of these. Part boundaries need not align
with P4 partition boundaries, but SHOULD, and writers SHOULD emit them equal.

**Payload-side identification.** A bare payload object carries no pointer to its
manifest — by design, since that pointer would leak the metadata location to the
payload host. Manifest discovery is an application concern (a catalog, a naming
convention, an out-of-band reference). This MUST be stated explicitly rather than
left as an apparent oversight.

**Content binding.** The authoritative manifest→payload binding is always the
DEK-keyed root signature. An OPTIONAL `payload.contentBinding` (`{alg, hash}`,
unkeyed SHA-256 over the ciphertext) MAY be included for deduplication and
content-addressing. It is a **privacy trade-off**: an unkeyed digest is a stable
public identifier for the ciphertext, letting a manifest host or network observer
correlate copies across tenants. RECOMMENDED default is to omit it. See §11 Q3.

#### P8 — Manifest signature

**Problem:** §5.7 — detachment makes the manifest independently tamperable, and
`payload.locators` becomes a redirect primitive that a reader must evaluate
*before* it has a DEK.

Add a signature over the whole manifest, verifiable without the DEK.

**Reuse the assertion mechanism rather than inventing a parallel one.** BaseTDF-ASN
already defines JWS bindings, key resolution, and verification
([`basetdf-asn.md §5`](../basetdf/basetdf-asn.md)). Add `scope: "manifest"` to the
scope enum (currently `"tdo"` | `"payload"`,
[`basetdf-asn.md:115`](../basetdf/basetdf-asn.md)) with these constraints:

- A `scope: "manifest"` assertion MUST use an **asymmetric** binding (`ES256`
  RECOMMENDED, `RS256` permitted). The ASN default of HS256-with-DEK is
  **PROHIBITED** for this scope — a DEK-keyed signature is unverifiable until after
  rewrap, which defeats the purpose of validating locators before fetching them.
- The signed content is the RFC 8785 (JCS) canonicalization of the manifest with the
  signing assertion itself removed. JCS avoids depending on byte-exact
  re-serialization while keeping the manifest a self-contained document.
- Coverage is the entire manifest: `payload`, `encryptionInformation`, `packaging`,
  and all other assertions.

**Requirement levels:** REQUIRED for `detached` and `sharded`; OPTIONAL for
`attached` (where the ZIP provides adequate practical binding).

**Cost:** this introduces a publisher-key PKI dependency that BaseTDF does not have
today — signer key distribution, `kid` resolution, rotation, revocation. That is a
real operational burden and the main argument against G4. See §11 Q4.

#### P9 — Resource locators and fetch policy

Detachment turns readers into HTTP clients acting on attacker-influenced URLs. This
needs its own document (BaseTDF-LOC), not a paragraph.

Locator object:

```json
{ "uri": "https://vfs.customer.example/objects/9f2a", "priority": 0, "size": 1073756160 }
```

Normative reader requirements:

- Readers MUST NOT dereference a locator unless its origin matches a configured
  allowlist. Prior art in the SDK: `allowListFromKASRegistry` (`sdk/tdf.go:784`)
  and the existing `kasAllowList` config — the same pattern, applied to payload
  origins.
- Readers MUST reject schemes outside a configured set (default: `https`, plus
  explicitly enabled object-store schemes).
- Readers MUST NOT follow redirects to origins outside the allowlist.
- Readers MUST verify a P8 manifest signature **before** dereferencing any locator.
- Readers MUST enforce a declared-size bound on fetched bytes and MUST reject a
  response exceeding it.
- Implementations MUST document their default posture. Fetching arbitrary URLs from
  an unauthenticated manifest is an SSRF vulnerability, and the default MUST be
  deny.

#### P10 — Multi-manifest semantics

G5 falls out of P7 mechanically: once manifests are standalone documents, publishing
a second one over the same payload requires only a new KAO set wrapping the same DEK.

**The security semantics must be specified, because they are counterintuitive.**
Every manifest over a given payload wraps the *same DEK*. Therefore:

> The effective access policy for a payload is the **union** of the policies of all
> manifests that reference it. A second manifest with a laxer policy does not
> coexist with a stricter first manifest — it supersedes it for any entity that can
> obtain the second. Publishing an additional manifest is equivalent to widening the
> policy on the original.

Writers MUST NOT treat multi-manifest publication as a way to enforce differentiated
access to the same ciphertext. Genuine separation requires distinct DEKs, i.e.
re-encryption. This belongs in BaseTDF-SEC as a numbered security consideration, not
a footnote — it is exactly the mistake a reasonable implementer will make.

#### P11 — Consistency proofs and append-only payloads

With P1's Merkle tree, RFC 6962 §2.2 consistency proofs let a reader verify that
manifest v2's payload is a strict **extension** of manifest v1's. Combined with
detachment, that makes live-appended payloads tractable: append segments, publish a
new manifest with a larger `segmentCount`, and prior manifests still verify against
the prefix.

```json
"extends": {
  "segmentCount": 262144,
  "rootSignature": "<base64 of prior root signature>",
  "consistencyProof": ["<base64 node>", "..."]
}
```

Verification requires the DEK (nodes are DEK-keyed), so this proves extension to a
key holder, not to the public. Sufficient for the intended use — a reader confirming
the object it read yesterday was not rewritten.

Lowest-priority proposal; include the manifest field in 5.0 so the shape is
reserved, and defer full writer support to 5.1 if schedule pressure demands.

---

### 6.10 Security model changes

These are spec-text obligations, not code, and are easy to drop. They are not
optional.

1. **Rewrite Tenet 1** ([`basetdf-sec.md:118-122`](../basetdf/basetdf-sec.md)).
   Today it grounds NIST SP 800-207 Tenet 1 in self-containment. Reframe around
   **self-description**: the manifest remains the complete authoritative record of
   what is protected and under what conditions; 5.0 changes where those bytes live,
   not what they assert. A detached TDF still requires no external *policy* catalog.
2. **Add the multi-manifest union rule** (P10) as a numbered consideration.
3. **Add the compartmentalization model** — a table of what each party observes
   under each packaging profile, stating plainly that detachment does not confer
   metadata confidentiality against the manifest host (G4 scoping note).
4. **Add a correlation consideration** — detachment means manifest and payload are
   fetched separately, often near in time. Traffic analysis can relink them. Note
   `contentBinding` (P7) as an additional deliberate correlation surface.
5. **Add crypto-shredding as a property** — destroying a detached manifest destroys
   the KAOs and hence the path to the DEK, giving a revocation primitive 4.x lacks.
   State its limits: it is not retroactive against a party who already rewrapped.
6. **Add the SSRF surface** (P9) to the threat model.

### 6.11 Goal coverage

| Goal | Mechanism |
|---|---|
| G1 | P2 caps manifest size; P1 gives O(log N) write state; P3 permits spilling; P6 removes the length requirement |
| G2 | P4 scopes keys per partition; P5 makes IV assignment stateless; P1 trees are per-partition buildable and mergeable |
| G3 | P2 gives closed-form offsets; P1+P3 give O(log N) authenticated single-segment reads |
| G4 | P7 defines the profiles; P8 authenticates the manifest; P9 constrains dereferencing; P2 makes manifests small enough to serve |
| G5 | P7 (standalone manifests) + P10 (semantics) |

**G3 after the change, 1 TiB cold single-byte read:** ~2 KB manifest + 32 B tree
header + 640 B proof + one 2 MiB segment. Meets the ≤ 64 KiB criterion for
everything except the segment, which is inherent to segment size.

---

## 7. Suite document plan

**BaseTDF-CORE** — refactored. Retains the abstract manifest schema, `packaging`
dispatch, and creation/reading flows. ZIP specifics move to PKG. Design Principle 1
becomes "self-description."

**BaseTDF-PKG (new)** — packaging profiles: attached (ZIP layout, entry order,
constraints, hardening from current CORE §10.2), detached, sharded; the streaming
write profile (P6); the `0.integrity` entry.

**BaseTDF-LOC (new)** — locator object, URI schemes, allowlisting, redirect and
size-bound rules, SSRF threat model (P9).

**BaseTDF-INT** — extended: Merkle construction (P1), `layout` and closed-form
offsets (P2), hash tree format (P3), partial-verification conformance profile,
consistency proofs (P11).

**BaseTDF-SEC** — extended per §6.10.

**BaseTDF-ALG** — new registry rows: `MERKLE-HS256` (integrity MAC),
`HKDF-SHA256` (key derivation, new category), `ES256` for manifest signing.

**BaseTDF-ASN** — `scope: "manifest"` plus the asymmetric-binding constraint (P8).

**BaseTDF-KAO / POL / KAS** — frozen. Republished at 5.0.0 with no normative change.

**BaseTDF-EX** — new worked examples per §8.7.

Update the dependency graph and reading order in
[`README.md:23-67`](../basetdf/README.md) for the two new documents.

---

## 8. Reference implementation plan (Go SDK)

Target module `sdk/`. All work must satisfy the repo's mandatory checks — see
[`CLAUDE.md`](../../CLAUDE.md): `golangci-lint run` clean, `go test ./...` passing,
`gofumpt -w` on changed files, and `go test -run TestREADMECodeBlocks` in `sdk/` if
README examples change.

### 8.1 New package `sdk/internal/merkle`

```go
package merkle

// Builder folds leaves in streaming order with O(log N) resident state.
type Builder struct{ /* stack []node; count uint64; dek []byte */ }

func NewBuilder(dek []byte) *Builder
func (b *Builder) Add(index uint64, segmentHash []byte) error
func (b *Builder) Count() uint64
func (b *Builder) Root() ([]byte, error)
func (b *Builder) RootSignature() ([]byte, error) // HMAC(dek, 0x02||u64be(count)||root)

type Tree struct{ /* levels [][]byte; leafCount uint64 */ }

func BuildTree(dek []byte, segmentHashes [][]byte) (*Tree, error)
func (t *Tree) WriteTo(w io.Writer) (int64, error)
func (t *Tree) Proof(index uint64) ([][]byte, error)

// ProofReader fetches only the sibling path via ranged reads.
type ProofReader struct{ /* ra io.ReaderAt; leafCount uint64; levels uint8 */ }

func OpenProofReader(ra io.ReaderAt) (*ProofReader, error)
func (p *ProofReader) Proof(index uint64) ([][]byte, error)

func VerifyInclusion(dek []byte, index, leafCount uint64, segmentHash []byte,
    proof [][]byte, wantRootSig []byte) error

func Merge(dek []byte, partitions []*Tree) (*Tree, error)         // reducer
func ConsistencyProof(t *Tree, oldLeafCount uint64) ([][]byte, error) // P11
```

Node offsets must be closed-form so `ProofReader` issues exactly `levels` ranged
reads.

### 8.2 `sdk/manifest.go`

Confirmed existing shape: `IntegrityInformation` (`manifest.go:14`),
`EncryptionInformation` (`manifest.go:54`), `Method` (`manifest.go:39`),
`Payload` (`manifest.go:45`). Add, all `omitempty` so explicit/attached
serialization is byte-identical to today:

```go
type IntegrityInformation struct {
    // ... existing ...
    Layout          string       `json:"layout,omitempty"`
    SegmentCount    int64        `json:"segmentCount,omitempty"`
    LastSegmentSize int64        `json:"lastSegmentSize,omitempty"`
    HashTree        *HashTreeRef `json:"hashTree,omitempty"`
}

type Locator struct {
    URI      string `json:"uri"`
    Priority int    `json:"priority,omitempty"`
    Size     int64  `json:"size,omitempty"`
}

type PayloadPart struct {
    Index        int64     `json:"index"`
    SegmentRange [2]int64  `json:"segmentRange"`
    Size         int64     `json:"size"`
    Locators     []Locator `json:"locators"`
}
```

Plus `Packaging string` on `Manifest`; `Locators []Locator` and `Parts []PayloadPart`
on `Payload`; `KeyDerivation *KeyDerivation` on `EncryptionInformation`;
`NoncePrefix string` on `Method`.

The existing `Segments []Segment` (`manifest.go:19`) has no `omitempty` and must
gain one. Verify this does not change attached/explicit output — `Segments` is never
empty on that path — but **assert it in a golden-fixture test** rather than assuming.

Add accessors that normalize the zero value so call sites never branch on `""`:
`Manifest.Layout()` → `"explicit"`, `Manifest.Packaging()` → `"attached"`.

### 8.3 `sdk/tdf.go` — writer

- `CreateTDFContext` (`tdf.go:164`) keeps its signature and behavior; add layout
  selection above the threshold.
- **New** `CreateTDFStream(ctx, w io.Writer, r io.Reader, opts ...TDFOption)` — no
  seek, always uniform layout, always the P6 ZIP profile. The G1 entry point. Do not
  overload `CreateTDFContext`; the size-known path has different optimal behavior
  and conflating them produces a function nobody can reason about.
- Replace the `strings.Builder` aggregate hash (`tdf.go:233-294`) with
  `merkle.Builder` under uniform layout; keep the existing path for explicit.
- Assertion binding (`tdf.go:362`) concatenates the aggregate hash. Under Merkle,
  substitute the 32-byte tree root. **This changes assertion signatures** — gate on
  layout and cover with a fixture per profile.

### 8.4 `sdk/tdf.go` — reader

- `Reader.ReadAt` (`tdf.go:994`) — rewrite. Uniform layout: closed-form offsets plus
  `merkle.ProofReader`, no segments scan. Explicit layout: keep the scan but build a
  prefix-sum offset table **once** at `LoadTDF` instead of rescanning per call. That
  fix is independently valuable and lands first (Phase 0).
- Root validation (`tdf.go:1317-1327`) — under uniform layout there is no segments
  array to fold; verify lazily per segment via inclusion proof rather than eagerly
  materializing the tree.
- Add `Reader.VerifyWhole(ctx) error` for callers wanting today's all-or-nothing
  guarantee explicitly, since partial reads no longer imply it.
- Derive `K_p` in `buildKey` (`tdf.go:1249`) when `keyDerivation` is present; cache
  derived keys in a 16-entry LRU on the `Reader`.

### 8.5 `sdk/internal/zipstream`

- Writer: general-purpose bit 3, ZIP64 data descriptors, incremental CRC-32.
- Reader: accept and validate data descriptors; prefer central directory values.
- Third entry `0.integrity` with a ranged `ReadIntegrity(offset, length int64)`
  accessor mirroring `ReadPayload`.
- `manifestMaxSize` stays at 10 MB (`tdf3_reader.go:15`). Under uniform layout it is
  no longer a payload-size ceiling. **Document it** — the current limit is
  undocumented and surprising.

### 8.6 New packages

**`sdk/packaging`** — the P7 abstraction. `Reader`/`Writer` interfaces over
attached/detached/sharded so `sdk.Reader` is agnostic:

```go
type PayloadSource interface {
    ReadAt(p []byte, off int64) (int, error)
    Size() int64
}
type IntegritySource interface {
    ReadAt(p []byte, off int64) (int, error)
}
func Open(m *Manifest, res Resolver) (PayloadSource, IntegritySource, error)
```

**`sdk/locator`** — P9. `Resolver` with allowlist enforcement, scheme restriction,
redirect policy, size bounds. **Default-deny.** Reuse the `allowListFromKASRegistry`
(`tdf.go:784`) pattern for consistency.

**`sdk/distributed`** — the G2 surface; keep out of the root package until the API
settles.

```go
type JobSpec struct {
    TotalSize, SegmentSize, PartitionSegments int64
    NoncePrefix [4]byte
}
type Partition struct {
    Index     int64
    ByteRange [2]int64 // plaintext, segment-aligned
    Key       []byte   // K_p only — never the DEK
}
func Plan(spec JobSpec) ([]Partition, error)

type PartitionResult struct {
    Index         int64
    SegmentHashes [][]byte
    CiphertextLen int64
}
func EncryptPartition(p Partition, spec JobSpec, r io.Reader, w io.Writer) (*PartitionResult, error)

type Assembler struct{ /* dek, spec */ }
func (a *Assembler) Add(res *PartitionResult) error
func (a *Assembler) Finalize(w io.Writer, payload io.Reader) (*Manifest, error)
```

`Plan` MUST reject a `TotalSize` producing a non-final interior partition whose byte
range is not a multiple of `SegmentSize` — fail loudly at plan time, not corrupt at
reduce time.

**`sdk/manifestsig`** — P8. JCS canonicalization (RFC 8785), ES256 sign/verify,
`kid` resolution. Reuse `sdk/assertion.go` binding machinery where possible.

### 8.7 Schema and test vectors

Update [`spec/schema/BaseTDF/manifest.schema.json`](../schema/BaseTDF/manifest.schema.json):
conditionals on `layout` (uniform requires `segmentCount`/`lastSegmentSize`/
`hashTree`, forbids `segments`) and on `packaging` (detached/sharded require
`payload.locators` or `payload.parts` and a manifest signature; forbid
`payload.url`). Use `if`/`then`/`else`, not `oneOf`, so errors name the actual
missing field.

Vectors in [`basetdf-ex.md`](../basetdf/basetdf-ex.md) with fixtures under
`sdk/testdata/basetdf-v5/`:

1. Merkle trees, N ∈ {1, 2, 3, 5, 8, 1000}, fixed DEK, all nodes shown. N=3 and N=5
   exercise promotion.
2. Inclusion proofs for N=1000 at i ∈ {0, 1, 499, 998, 999}.
3. **Promotion-attack negative vector** — a forged tree duplicating the last leaf to
   reach N+1, proving count binding rejects it.
4. Uniform manifest for a 16 GiB TDF, demonstrating it is under 2 KB.
5. `0.integrity` fixture, byte-for-byte, with annotated level offsets.
6. Partition key vectors: DEK → `K_0`, `K_1`, `K_1023` at `partitionSegments: 512`.
7. Deterministic IV vectors: `noncePrefix` → `IV_0`, `IV_1`, `IV_{2^32}`.
8. Cross-profile round trip: same plaintext, explicit and uniform, identical output.
9. Streaming-write ZIP fixture, verified against `unzip`, Go `archive/zip`, and
   Python `zipfile`.
10. Detached manifest + separate payload object, with a signature vector.
11. Sharded manifest with 4 parts, including a negative vector for a non-contiguous
    `parts` array.
12. **Locator negative vectors** — off-allowlist origin, non-https scheme,
    redirect-to-unlisted, oversize response.
13. Consistency proof: manifest at N=1000 extending N=512.

---

## 9. Sequencing

Each phase is a separately reviewable change with tests. Phases 1 and 2 are
independent after Phase 0.

**Phase 0 — Non-breaking prerequisites.** No format change; ship against 4.4.
- Fix the O(N)-per-call scan in `Reader.ReadAt` (`tdf.go:994`) with a prefix-sum
  table built at `LoadTDF`.
- Document the `manifestMaxSize` ceiling and its payload-size implication; surface
  an actionable error.
- Benchmarks `BenchmarkReadAtCold` / `BenchmarkReadAtRandom` at 1, 10, 100 GiB — the
  regression baseline for everything below.

**Phase 1 — Merkle core.** `sdk/internal/merkle`, BaseTDF-INT §5.4, ALG rows,
vectors 1–3. Pure library, no format change.

**Phase 2 — ZIP streaming profile (P6).** BaseTDF-PKG, zipstream changes, vector 9.

**Phase 3 — Uniform layout (P2 + P3).** Manifest fields, `0.integrity`, schema,
closed-form offsets, partial verification. Depends on 1, 2. Vectors 4, 5, 8.
**Meets G3.**

**Phase 4 — Streaming writer.** `CreateTDFStream`. Depends on 2, 3. **Meets G1.**
Acceptance: encrypt from a pipe with no length; assert bounded RSS via
`runtime.MemStats` across payload sizes spanning three orders of magnitude.

**Phase 5 — Partition keys and IVs (P4 + P5).** Vectors 6, 7.

**Phase 6 — Distributed writer.** `sdk/distributed`. Depends on 3, 5. **Meets G2.**
Acceptance: plan a job, run partitions in separate goroutines holding only their
`K_p`, assemble, round-trip — plus a negative test asserting a worker with `K_p`
cannot decrypt partition `p+1`.

**Phase 7 — Suite refactor.** Split CORE into CORE + PKG; create LOC; update the
README dependency graph. Spec-only, no code. Can run in parallel with 4–6.

**Phase 8 — Manifest signature (P8).** `sdk/manifestsig`, ASN `scope: "manifest"`,
vector 10's signature. Depends on 7.

**Phase 9 — Detached and sharded packaging (P7 + P9).** `sdk/packaging`,
`sdk/locator`, schema conditionals, vectors 10–12. Depends on 3, 8. **Meets G4.**

**Phase 10 — Multi-manifest (P10).** Largely spec text plus a helper to mint an
additional manifest against an existing payload. **Meets G5.**

**Phase 11 — Consistency proofs (P11).** Vector 13. Deferrable to 5.1.

**Phase 12 — Interop and release.** Cross-implementation vectors, 4.4→5.0 migration
guide, explicit statement of 4.x reader behavior on a 5.0 object, SEC changes from
§6.10 landed and reviewed.

---

## 10. Risks

| Risk | Mitigation |
|---|---|
| **Scope creep** — a major version invites reopening POL, KAS, PQC | The §3.4 charter is normative for the release. Frozen documents republish unchanged. |
| **PKI dependency** (P8) — signer key distribution, rotation, revocation | Required only for detached/sharded. Attached users never encounter it. |
| **SSRF** in detached readers | P9 default-deny plus negative vectors 12. Treat a permissive default as a release blocker. |
| **Multi-manifest misuse** (P10) — implementers assume differentiated access | Numbered SEC consideration, not a footnote. Consider an SDK-level warning when minting a second manifest. |
| **Multi-SDK migration** (Go, JS, Java, Python) | Attached+explicit stays byte-identical, so most of the matrix is a version-string change. Gate 5.0 GA on two independent implementations passing the vectors. |
| **Tenet 1 rewrite** reads as weakening zero trust | Land the SEC rewrite in the same change as the CORE refactor, with the self-description framing argued explicitly. |

---

## 11. Open questions

1. **Merkle arity.** Binary gives 20-node proofs at 1 TiB. Arity 4 gives 10 levels ×
   3 siblings = 30 nodes — worse in bytes, better in round trips if the tree is not
   contiguously fetchable. Since levels are contiguous and range-readable, binary
   looks right. Confirm against real object-store latency before freezing.
2. **Full tree or leaves only in `0.integrity`?** Full tree is 64 B/segment with
   O(log N) fetch; leaves only is 32 B/segment but O(N) to reconstruct any internal
   node. Full tree proposed; revisit if storage cost dominates read latency for a
   known workload.
3. **`contentBinding` default (P7).** Unkeyed digest gives dedup and content
   addressing but is a stable cross-tenant correlation handle. Recommendation: omit
   by default, OPTIONAL for dedup-oriented deployments. **This is a product decision
   as much as a security one and needs an explicit owner.**
4. **Is the P8 PKI dependency acceptable?** It is the largest new operational
   requirement in 5.0. Alternative: DEK-keyed manifest signature, cheaper but
   unverifiable before rewrap — which does not solve the locator-validation problem
   and so does not actually meet G4. If the PKI burden is rejected, G4 should be
   deferred rather than met with a weaker signature.
5. **`partitionSegments` as a metadata leak.** It reveals producer job topology.
   Probably acceptable given the manifest already exposes policy and KAS URLs, but
   it warrants an explicit SEC note.
6. **Assertion binding under Merkle.** Substituting the tree root for the aggregate
   hash is proposed. Confirm no deployed assertion verifier depends on the aggregate
   hash's length or structure.
7. **Does the KAS need to know about partitions?** P4 derives client-side from the
   DEK, so no. A future variant where the KAS releases only partition keys is a KAS
   protocol change — out of charter, 5.1 at the earliest.
8. **Manifest discovery for detached payloads.** Deliberately an application
   concern (P7). Confirm no platform component needs a normative answer, or accept
   that a catalog service becomes a de facto dependency.
9. **Interaction with nano TDF.** Out of scope; confirm nothing here forecloses a
   future shared integrity model.

---

## 12. Appendix: notation

| Symbol | Meaning |
|---|---|
| `L` | Plaintext payload length in bytes |
| `S` | `segmentSizeDefault` |
| `N` | Segment count = `ceil(L / S)` |
| `DEK` | Data Encryption Key, 256 bits |
| `K_p` | Partition key for partition `p` (P4) |
| `h_i` | Segment hash of segment `i` per [`basetdf-int.md §4`](../basetdf/basetdf-int.md) |
| `L_i` | Merkle leaf for segment `i` (P1) |
| `u32be(x)` / `u64be(x)` | Big-endian fixed-width integer encoding |
| `‖` | Byte concatenation |

---

## 13. References

- [BaseTDF-CORE](../basetdf/basetdf-core.md) — container format, manifest
- [BaseTDF-INT](../basetdf/basetdf-int.md) — segment model, integrity
- [BaseTDF-SEC](../basetdf/basetdf-sec.md) — zero trust tenets (§2.2), IV uniqueness (§6.6)
- [BaseTDF-ALG](../basetdf/basetdf-alg.md) — algorithm registry (§3.3)
- [BaseTDF-ASN](../basetdf/basetdf-asn.md) — assertion scopes (§2.2), bindings (§5)
- [BaseTDF-KAO](../basetdf/basetdf-kao.md) — key splitting, policy binding
- [BaseTDF-KAS](../basetdf/basetdf-kas.md) — bulk rewrap (§8)
- NIST SP 800-207 — Zero Trust Architecture
- NIST SP 800-38D §8.2.1 — deterministic IV construction
- RFC 5869 — HKDF
- RFC 6962 §2.1, §2.2 — Certificate Transparency: inclusion and consistency proofs
- RFC 7515 — JWS (serialization-profile precedent)
- RFC 8785 — JSON Canonicalization Scheme
- APPNOTE 6.3.10 §4.3.9, §4.4.4 — ZIP data descriptors, general-purpose bit 3
