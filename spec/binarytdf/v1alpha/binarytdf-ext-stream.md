# BinaryTDF-STREAM: AES-256-GCM-HKDF Streaming Suite

| | |
|---|---|
| Document | BinaryTDF-STREAM |
| Extension version | 0.1 |
| Source draft | 0.2 |
| Frame version | 2 |
| Registry identifier | `AES_256_GCM_HKDF_SHA256_STREAM = 2` |
| Status | Draft, optional |
| Depends on | BinaryTDF-CORE, BinaryTDF-PAY |

This suite protects one large payload as independently authenticated segments inside
the ordinary Ciphertext section. Its key schedule, nonce construction, and segment
encryption derive from the
[Tink AES-GCM-HKDF Streaming AEAD encryption function](https://developers.google.com/tink/streaming-aead/aes_gcm_hkdf_streaming).
A BinaryTDF header declares ciphertext segment size.

It supports bounded-memory processing and optional random access without changing the
frame, recovery, KAO wrapping, policy binding, or KAS protocol.

## 1. Core relationship

Identifier 2 is reserved for this suite. A compatible revision retains it; an
incompatible parameter, encoding, derivation, nonce, release, or interpretation change
requires a new identifier.

Support is optional. An implementation MAY claim core conformance without implementing
this suite. A receiver that does not implement it MUST reject suite 2 as
`UNSUPPORTED_CAPABILITY` and MUST NOT fall back to another suite. The suite consumes
the 32-byte object key from any recovery scheme. KEY_EPOCH includes the
content-encryption identifier in object-key derivation, so selecting this suite
produces a different object key than suite 1 for the same epoch identity.

This adopts Tink's cryptographic construction, not Tink keysets, Protocol Buffers, or
byte-exact header. BinaryTDF's object key is Tink `KeyValue`; `segment_size` is
`CiphertextSegmentSize`; `DerivedKeySize` is 32; hash is SHA-256; and BinaryTDF AAD
plus encoded segment size is Tink `AssociatedData`.

## 2. Applicability

Suite 1 is a single AES-GCM message and is limited to about 64 GiB of plaintext; its
release rule also requires buffering or double-reading large data. This suite removes
those limits with independently authenticated segments.

It protects one logical payload. It is not a collection container. The frame still
places Ciphertext Length before bytes, so the producer MUST know final encoded length
or use seekable output and backpatch it. Open-ended live streams require multiple
bounded objects or a separate transport/container specification.

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
is empty; core `payload_aad` and segment size are bound into the payload key as Tink
specifies.

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

Strict frame, CBOR, policy-binding, and key-recovery validation precedes segment work.

## 8. Limits

| Quantity | Limit |
|---|---|
| Ciphertext segment | 61 through 2147483647 bytes |
| Segment 0 plaintext | `segment_size - 60` maximum |
| Later plaintext segment | `segment_size - 16` maximum |
| Segment count | at most 2^32 |
| Fixed overhead | 44-byte header and 16-byte tag per segment |
| Working memory | one segment |

Maximum plaintext is constrained by segment count, size, and outer Ciphertext Length.
Implementations MUST enforce configured total-byte, size, and count limits before
allocation or cryptographic processing. Profiles MAY set lower limits.

## 9. Security

- Prefix authenticity is not completeness. Pipelines need a failure path that retracts
  or abandons partial output.
- Header randomness MUST be fresh. Reusing object key and salt may repeat the payload
  key; reusing the complete header may repeat AES-GCM key/nonce pairs.
- Segment size is attacker-controlled until authentication. Validate and bound it
  before allocation. Its derivation binding detects changes.
- Segments do not transplant across objects or positions because payload derivation,
  index, and final marker differ.
- Random access may reveal access patterns to storage or transport.

## 10. Conformance

Vectors MUST include at least three segment sizes including 65536; empty payloads and
payloads around every boundary; exact headers, keys, offsets, nonces, ciphertext, and
tags; truncation and removal of final segments; reorder, duplication, and trailing
bytes; invalid sizes and bit corruption in every header and segment component;
cross-object transplant; late sequential failure after partial release; and interior
random access with and without final completion.
