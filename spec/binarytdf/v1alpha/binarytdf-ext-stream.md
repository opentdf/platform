# BinaryTDF-STREAM: AES-256-GCM-HKDF Streaming Suites

| | |
|---|---|
| Document | BinaryTDF-STREAM |
| Extension version | 0.3 |
| Source draft | 0.3 |
| Frame version | 2 |
| Registry identifiers | `AES_256_GCM_HKDF_SHA256_STREAM = 2`, `AES_256_GCM_HKDF_SHA256_STREAM_PART = 3` |
| Status | Draft, optional |
| Depends on | BinaryTDF-SEC, BinaryTDF-PAY, BinaryTDF-SCH, BinaryTDF-PKG |

This document registers two suites that protect one large payload as independently
authenticated segments inside the ordinary Ciphertext section. Sections 1 through 8
define suite 2, whose key schedule, nonce construction, and segment encryption derive
from the
[Tink AES-GCM-HKDF Streaming AEAD encryption function](https://developers.google.com/tink/streaming-aead/aes_gcm_hkdf_streaming).
Section 9 defines suite 3, which adds partition-key derivation to that construction so
that one object may exceed the volume a single AES-GCM key may protect. A BinaryTDF
header declares ciphertext segment size.

Both support bounded-memory processing and optional random access without changing the
BinaryTDF-PKG frame, recovery, KAO wrapping, policy binding, or KAS protocol.

## 1. Core relationship

Identifier 2 is reserved for suite 2 and identifier 3 for suite 3. A compatible
revision retains an identifier; an incompatible parameter, encoding, derivation, nonce,
release, or interpretation change requires a new identifier.

Support is optional and the two suites are independent: an implementation MAY claim
core conformance without implementing either, and MAY implement one without the other.
A receiver that does not implement a suite MUST reject it as `UNSUPPORTED_CAPABILITY`
and MUST NOT fall back to another suite. Each suite consumes the 32-byte object key
from any recovery scheme. KEY_EPOCH includes the content-encryption identifier in
object-key derivation, so selecting a suite here produces a different object key than
suite 1 for the same epoch identity.

This adopts Tink's cryptographic construction, not Tink keysets, Protocol Buffers, or
byte-exact header. BinaryTDF's object key is Tink `KeyValue`; `segment_size` is
`CiphertextSegmentSize`; `DerivedKeySize` is 32; hash is SHA-256; and BinaryTDF AAD
plus encoded segment size is Tink `AssociatedData`.

## 2. Applicability

Suite 1 is a single AES-GCM message, so it cannot carry more than 68719476704
plaintext bytes: the NIST SP 800-38D Section 5.2.1.1 per-invocation limit, stated
normatively in BinaryTDF-PAY Section 4. Its release rule also requires buffering or
double-reading large data. Independently authenticated segments remove both
constraints, because each segment is a separate bounded invocation that is verified
and may be released on its own.

Segmentation removes a per-invocation framing limit; it does not remove the cumulative
volume bound. The AES-GCM confidentiality bound counts total plaintext blocks under one
key however those blocks are divided into messages, so splitting a payload into more
segments does not let one key protect more of it. Segmenting is not rekeying.
Section 8.1 therefore caps a suite 2 object at `2^35` plaintext blocks, at most
512 GiB, and Section 9 defines suite 3, which rekeys at partition boundaries and
applies one object-wide block-square budget to carry larger objects. BinaryTDF-SEC
Section 3 gives the analysis behind both.

Each suite protects one logical payload; neither is a collection container. The frame
still places Ciphertext Length before bytes, so the producer MUST know final encoded
length or use seekable output and backpatch it. Open-ended live streams require
multiple bounded objects or a separate transport/container specification.

## 3. Parameters and derivation

| Tink parameter | Value |
|---|---|
| `KeyValue` | 32-byte object key |
| `CiphertextSegmentSize` | stream-header `segment_size` |
| `DerivedKeySize` | 32 bytes |
| `HkdfHashType` | SHA-256 |
| `AssociatedData` | `payload_aad || uint32_be(segment_size)` |

`segment_size` is an unsigned 32-bit byte count. It MUST be greater than 60 and MUST
NOT exceed 2147483647. An implementation MUST validate it and apply configured
resource limits before allocating a segment buffer. A deployment MAY reject otherwise
valid objects whose segment size exceeds its limit.

The producer generates a fresh random 32-byte `stream_salt` and derives:

```text
payload_key = HKDF-SHA256(
  ikm  = object_key,
  salt = stream_salt,
  info = payload_aad || uint32_be(segment_size),
  len  = 32
)
```

The fixed-width suffix binds segment boundaries. The suite identifier is already in
Protected Metadata covered by `payload_aad`.

## 4. Ciphertext layout

```text
header || encrypted_segment[0] || ... || encrypted_segment[n-1]

header = 0x2c || uint32_be(segment_size) || stream_salt || nonce_prefix
         1 byte  4 bytes                    32 bytes       7 bytes
```

- `0x2c` declares the 44-byte header.
- `segment_size` is the maximum wire-segment size, including header in segment 0 and
  the tag in every segment.
- `stream_salt` is used by Section 3.
- `nonce_prefix` is fresh and uniformly random.
- Every encrypted segment ends with a 16-byte AES-GCM tag.

```text
segment 0: [44-byte header | ciphertext | 16-byte tag]
segment i: [ciphertext                 | 16-byte tag]

segment 0 plaintext capacity = segment_size - 60
later plaintext capacity     = segment_size - 16
```

When multiple segments exist, segment 0 and every non-final segment MUST have maximum
length. The final segment MAY be shorter but MUST NOT be empty unless the complete
payload is empty.

The Ciphertext section MUST be at least 60 bytes: the header and one tag for an empty
final segment.

```text
segment_count = ceil(Ciphertext Length / segment_size)
segment_0_encrypted_offset = 44
segment_i_encrypted_offset = i * segment_size, for i > 0
```

A decoder MUST reject header length other than `0x2c`, invalid segment size, truncated
header or tag, non-final short segment, or empty final segment in a multi-segment
object.

## 5. Nonce and associated data

```text
segment_nonce(i) = nonce_prefix
                 || uint32_be(i)
                 || final_byte
```

`final_byte` is `0x01` for the final segment and `0x00` otherwise. Index and final
marker detect reordering, duplication, truncation, and extension. Segment AES-GCM AAD
is empty; BinaryTDF-PAY `payload_aad` and segment size are bound into the payload key
as Tink specifies.

## 6. Encryption

After metadata and recovery are complete, the producer:

1. selects valid `segment_size` and generates `stream_salt` and `nonce_prefix`;
2. derives `payload_key`;
3. splits plaintext using Section 4; and
4. emits `AES-256-GCM(payload_key, segment_nonce(i), empty_aad, segment_plaintext)`.

Indexes MUST strictly increase from zero. Exactly one segment, the last, MUST use the
final byte. Producers MAY encrypt segments in parallel; emitted order remains index
order.

## 7. Decryption and release

- A sequential opener MUST verify in order and MAY release a segment after it authenticates.
  Released data is authentic prefix data. The stream is complete only when the final
  segment authenticates at the position implied by section length and consumes the
  section exactly.
- Any authentication failure or absence of a valid final segment MUST fail the stream.
  An application consuming prefix data MUST be able to discard or abandon partial
  output and MUST NOT treat prefix data as the complete payload.
- A streaming API MUST expose final completion or failure separately from prefix
  delivery. An API returning one complete object MUST stage output until completion.
- A random-access opener MAY verify and release a segment independently. Whole-payload
  completeness still requires authenticating the final segment. Omission-sensitive
  applications MUST NOT act on the payload as complete before then.

Strict BinaryTDF-PKG frame, BinaryTDF-SCH CBOR, policy-binding, and key-recovery
validation precedes segment work.

## 8. Limits

| Quantity | Limit |
|---|---|
| Ciphertext segment | 61 through 2147483647 bytes |
| Segment 0 plaintext | `segment_size - 60` maximum |
| Later plaintext segment | `segment_size - 16` maximum |
| Segment count | at most 2^32 |
| Plaintext blocks | at most 34359738368, that is 2^35 |
| Total plaintext | at most 549755813888 bytes, that is 512 GiB |
| Fixed overhead | 44-byte header and 16-byte tag per segment |
| Working memory | one segment |

Maximum plaintext is constrained by segment count, size, outer Ciphertext Length, and
the confidentiality budget below. Implementations MUST enforce configured total-byte,
size, and count limits before allocation or cryptographic processing. Profiles MAY set
lower limits.

### 8.1 Volume ceiling

One payload key protects every segment of a suite 2 object. For an invocation carrying
`x` plaintext bytes, define `block_count(x) = ceil(x / 16)`. Let `sigma` be the sum of
`block_count` over every segment. A suite 2 object MUST satisfy:

```text
sigma <= 2^35
```

This is the single-key form of the BinaryTDF-SEC Section 3 object-wide
confidentiality budget. It permits at most 549755813888 plaintext bytes (512 GiB),
and per-segment partial-block rounding may make the exact permitted byte count lower.

The complete plaintext length follows from the frame before any decryption:

```text
segment_count   = ceil(Ciphertext Length / segment_size)
total_plaintext = Ciphertext Length - 44 - 16 * segment_count
```

A producer computes each segment plaintext length from Section 4 and MUST NOT emit an
object whose `sigma` exceeds the ceiling. A decoder can make the same computation from
the declared Ciphertext Length, `segment_size`, and fixed layout, and MUST reject an
over-budget object before allocating a segment buffer or authenticating any segment.
All arithmetic MUST be checked for overflow. Choosing a smaller `segment_size` does
not raise the ceiling, because the bound counts plaintext blocks and not messages.

Suite 2 therefore tops out at 512 GiB of plaintext per object. A larger payload MUST
use suite 3, which rekeys per partition, or be divided into several objects with
independent object keys.

## 9. Partitioned suite 3

Identifier 3, `AES_256_GCM_HKDF_SHA256_STREAM_PART`, is suite 2's segment construction
with one addition: the payload key encrypts nothing, and every segment is encrypted
under a partition key expanded from it. Rekeying at partition boundaries distributes
the BinaryTDF-SEC Section 3.1 confidentiality budget across independently derived keys
while the object grows to storage scale.

Sections 3 through 7 apply to suite 3 as written except where this section replaces
them, and Section 1 governs identifier 3 unchanged. Suite 3 adds no CBOR field: its
only appearance in CBOR is `content_encryption_suite = 3` in Protected Metadata,
registered by BinaryTDF-SCH as `aes-256-gcm-hkdf-sha256-stream-part`. Its parameter
travels in the ciphertext header like every other suite 2 parameter.

### 9.1 Header and partition parameter

`partition_segments` is an unsigned 32-bit count of segments per partition. It is
appended to the Section 4 header, which grows from 44 to 48 bytes:

```text
header = 0x30 || uint32_be(segment_size) || stream_salt
      || nonce_prefix || uint32_be(partition_segments)

0x30                1 byte    declared header length, 48 bytes
segment_size        4 bytes
stream_salt        32 bytes
nonce_prefix        7 bytes
partition_segments  4 bytes
```

The parameter is appended rather than inserted, so every field shared with suite 2
keeps its offset and meaning and the first byte still declares total header length. A
decoder MUST reject a declared header length other than `0x30`, which also prevents a
suite 2 reader from consuming a suite 3 header or the reverse.

Capacities and offsets change only by the four added bytes:

```text
segment 0 plaintext capacity = segment_size - 64
later plaintext capacity     = segment_size - 16

segment_0_encrypted_offset   = 48
segment_i_encrypted_offset   = i * segment_size, for i > 0
```

`segment_size` MUST be greater than 64 and MUST NOT exceed 2147483647. The Ciphertext
section MUST be at least 64 bytes: the header and one tag for an empty final segment.
The Section 4 rules on maximum-length non-final segments, the non-empty final segment,
and rejection of truncated or malformed segments apply unchanged.

### 9.2 Derivation

The payload key is derived as in Section 3 with `partition_segments` appended to the
info string:

```text
payload_key = HKDF-SHA256(
  ikm  = object_key,
  salt = stream_salt,
  info = payload_aad || uint32_be(segment_size) || uint32_be(partition_segments),
  len  = 32
)
```

The additional fixed-width suffix binds the partition parameter and separates the two
suites: one object key, salt, AAD, and segment size yield unrelated payload keys under
suite 2 and suite 3. In the Section 3 mapping, Tink `AssociatedData` is
`payload_aad || uint32_be(segment_size) || uint32_be(partition_segments)`; every other
parameter is unchanged.

`partition_segments` MUST be at least 1. Partition `p` covers segment indexes
`p * partition_segments` through `p * partition_segments + partition_segments - 1`, so
segment `i` is encrypted under:

```text
p   = floor(i / partition_segments)

K_p = HKDF-Expand(
  prk  = payload_key,
  info = UTF8("binary-tdf:v2:stream-partition") || uint64_be(p),
  len  = 32
)
```

This is RFC 5869 Expand with the payload key directly as the pseudorandom key and no
Extract step, because the payload key is already a uniform HKDF output. The partition
index is encoded in eight bytes even though a 32-bit segment index cannot produce a
partition index above 2^32 - 1; the label and width match BaseTDF 5 partition
derivation.

The Section 6 producer step 4 emits
`AES-256-GCM(K_p, segment_nonce(i), empty_aad, segment_plaintext)`. The payload key
performs no AES-GCM operation. A producer that distributes segment work MUST hand a
worker only the partition keys it needs and MUST NOT hand it the payload key.

### 9.3 Nonce

Nonce construction is unchanged from Section 5:

```text
segment_nonce(i) = nonce_prefix || uint32_be(i) || final_byte
```

The index is the absolute segment index; it does not restart at a partition boundary.
Restarting would also be sound, because each partition has its own key, but the
absolute index is strictly safer: it keeps every key and nonce pair distinct even if a
partition key were repeated, whether through a repeated payload key or an
implementation error in Section 9.2. It also keeps random access simple, because the
nonce of segment `i` depends only on `i`. Segment AES-GCM AAD remains empty.

### 9.4 Object-wide confidentiality budget

For an invocation carrying `x` plaintext bytes, define
`block_count(x) = ceil(x / 16)`. For each partition `p`, let:

```text
sigma_p = sum(block_count(segment_plaintext_length(i))
              for every segment i in partition p)
```

A suite 3 object MUST satisfy:

```text
sum(sigma_p^2 for every partition p) <= 2^70
```

This is the BinaryTDF-SEC Section 3 object-wide confidentiality budget. It implies
that no individual partition can exceed `2^35` blocks (512 GiB), but independent
per-partition ceilings are not sufficient: every partition contributes to the sum.

The producer MUST compute the sum with checked integer arithmetic before emitting the
object. The decoder derives the exact segment plaintext lengths and partition ranges
from the declared Ciphertext Length, `segment_size`, and `partition_segments`; it MUST
reject an over-budget object before allocating a segment buffer or authenticating any
segment. Arithmetic MUST be checked with sufficient width; unsigned 128-bit
intermediates are sufficient for the registered field ranges, and overflow MUST be
treated as over budget. An implementation MAY compute runs of equal full partitions
algebraically rather than iterating over every segment.

For advance parameter selection, the conservative per-segment value
`c = ceil((segment_size - 16) / 16)` gives an upper bound. With `n` segments and
`m = partition_segments`, a producer may validate:

```text
f = floor(n / m)
r = n mod m
f * (m * c)^2 + (r * c)^2 <= 2^70
```

where the final term is zero when `r` is zero. Exact accounting can admit slightly
more data because segment 0 and the final segment may be short. At a 1048576-byte wire
segment, `partition_segments = 1024` is RECOMMENDED: an ordinary full partition
protects `1024 * 65535 = 67107840` blocks, just under 1 GiB of plaintext.

### 9.5 Limits and object size

| Quantity | Limit |
|---|---|
| Ciphertext segment | 65 through 2147483647 bytes |
| Segment 0 plaintext | `segment_size - 64` maximum |
| Later plaintext segment | `segment_size - 16` maximum |
| Segment count | at most 2^32 |
| `partition_segments` | 1 through 4294967295, further bounded by Section 9.4 |
| Blocks under one partition key | at most 2^35 and normally much less |
| Object confidentiality | `sum(sigma_p^2) <= 2^70` |
| Total plaintext | intersection of the structural fields and Section 9.4 budget |
| Fixed overhead | 48-byte header and 16-byte tag per segment |
| Working memory | one segment |

The structural fields alone would permit:

```text
max object plaintext = (segment_size - 64) + (2^32 - 1) * (segment_size - 16)
                     = 9223371963840331728 bytes at segment_size 2147483647
```

That is about 8 EiB, and its Ciphertext Length of 9223372032559808512 bytes fits the
8-byte frame field. Section 9.4 is an additional, normally tighter cryptographic
constraint; the structural maximum is not a conforming suite 3 object.

A 50 TiB plaintext is conforming with `segment_size = 1048576` and
`partition_segments = 1024`. Exact values are:

| Quantity | Value |
|---|---:|
| Plaintext bytes | 54975581388800 |
| Segment count | 52429601 |
| Partition count | 51201 |
| Ciphertext Length | 54976420262464 |
| GCM header/tag overhead | 838873664 bytes |
| `sum(sigma_p^2)` | 230580012879620085778 |

The block-square sum is less than `2^70 = 1180591620717411303424`; the resulting
dominant confidentiality advantage is approximately `2^-59.36`.

The encrypted representation is larger than its plaintext. Amazon S3 specifies an
exact single-object maximum of 50,000 GiB (approximately 48.83 TiB), and multipart
upload does not change that final-object limit. With the parameters above, an object
of exactly that physical size carries at most 53686271999952 plaintext bytes. A
50 TiB logical plaintext therefore requires either a byte-addressable storage mapping
that concatenates several physical blobs or multiple independent BinaryTDF objects
with fresh object keys. A virtual concatenation preserves one cryptographic object and
its Section 9.4 budget. A logical-file profile using multiple cryptographic objects
MUST apply `sum(sigma_p^2) <= 2^70` across the union of their independently keyed
partitions to retain the same whole-file target. That storage mapping and logical-file
catalog are outside the BinaryTDF frame; S3 multipart part numbers MUST NOT replace
the cryptographic segment index or partition index.

## 10. Security

- Prefix authenticity is not completeness. Pipelines need a failure path that retracts
  or abandons partial output.
- Header randomness MUST be fresh. Reusing object key and salt may repeat the payload
  key; reusing the complete header may repeat AES-GCM key/nonce pairs.
- Segment size is attacker-controlled until authentication. Validate and bound it
  before allocation. Its derivation binding detects changes.
- Segments do not transplant across objects or positions because payload derivation,
  index, and final marker differ.
- Random access may reveal access patterns to storage or transport.
- Suite 2 has no rekeying mechanism, so the Section 8.1 block ceiling is its only
  protection against AES-GCM volume degradation. Producers of large data SHOULD
  prefer suite 3 rather than approaching that ceiling.
- `partition_segments` is attacker-controlled until authentication in the same way
  segment size is. Validate it and the complete Section 9.4 budget before allocation;
  its derivation binding detects later change.
- A disclosed partition key exposes only the segments of its partition. It does not
  yield the payload key, another partition key, or any other object.

## 11. Conformance

Vectors MUST include at least three segment sizes including 65536; empty payloads and
payloads around every boundary; exact headers, keys, offsets, nonces, ciphertext, and
tags; truncation and removal of final segments; reorder, duplication, and trailing
bytes; invalid sizes and bit corruption in every header and segment component;
cross-object transplant; late sequential failure after partial release; and interior
random access with and without final completion.

Vectors MUST additionally include, for the limits of Sections 8.1 and 9.4, a suite 2
object at exactly the block ceiling and the next larger object; a suite 3 object whose
segment indexes cross at least two partition boundaries, with exact `K_p` values and
absolute-index nonces on both sides of each boundary; a suite 3 header whose
block-square sum is exactly `2^70` and one whose sum exceeds it; the 50 TiB case from
Section 9.5; and a suite 3 header presented to a suite 2 reader and the reverse.
BinaryTDF-EX Section 5 gives worked values for the boundary cases.
