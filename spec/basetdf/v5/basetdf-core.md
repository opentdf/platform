# BaseTDF-CORE: Manifest and End-to-End Processing

| | |
|---|---|
| **Document** | BaseTDF-CORE |
| **Version** | 5.0.0 |
| **Status** | Standards Track |
| **Date** | 2026-08 |
| **Depends on** | BaseTDF-SEC, BaseTDF-ALG, BaseTDF-KAO, BaseTDF-INT, BaseTDF-POL, BaseTDF-ASN, BaseTDF-LOC, BaseTDF-PKG |
| **Referenced by** | BaseTDF-EX |

## 1. Introduction

BaseTDF-CORE defines the logical BaseTDF manifest and end-to-end processing.
Physical serialization is defined by [BaseTDF-PKG](basetdf-pkg.md), allowing the
same protected object to be attached, detached, or sharded.

### 1.1 Design principles

1. **Self-description.** The manifest is authoritative about what is protected,
   policy, key access, integrity, and protected-byte locations. Self-description
   does not require every byte to share one container.
2. **Separation.** Metadata, ciphertext, integrity artifacts, key services, and
   storage transports have distinct validation boundaries.
3. **Bounded processing.** Unknown-length input supports a forward-only write, and a
   selected segment supports verification without O(payload size) metadata.
4. **Fail closed.** Unsupported versions/profiles, invalid combinations, overflow,
   unauthenticated locators, and cryptographic failures stop affected plaintext.

BCP 14 terms are normative when capitalized. All count, size, range, and offset
operations MUST use checked unsigned 64-bit arithmetic.

## 2. Manifest Object

### 2.1 Scalable attached example

```json
{
  "schemaVersion":"5.0.0",
  "payload":{
    "type":"reference", "url":"0.payload", "protocol":"zip",
    "mimeType":"application/octet-stream", "isEncrypted":true
  },
  "encryptionInformation":{
    "type":"split",
    "keyAccess":[{
      "alg":"RSA-OAEP-256", "kas":"https://kas.example.com",
      "kid":"kas-key-2026", "sid":"split-0", "protectedKey":"<base64>",
      "policyBinding":{"alg":"HS256", "hash":"<base64>"}
    }],
    "method":{
      "algorithm":"AES-256-GCM", "iv":"", "isStreamable":true,
      "noncePrefix":"<base64-four-bytes>"
    },
    "keyDerivation":{"alg":"HKDF-SHA256", "partitionSegments":512},
    "integrityInformation":{
      "rootSignature":{"alg":"MERKLE-HS256", "sig":"<base64>"},
      "segmentHashAlg":"GMAC",
      "segmentSizeDefault":2097152,
      "encryptedSegmentSizeDefault":2097180,
      "layout":"uniform",
      "segmentCount":524288,
      "lastSegmentSize":2097152,
      "plaintextSize":1099511627776,
      "encryptedSize":1099526307840,
      "hashTree":{
        "nodeSize":32, "levels":20, "size":33554432,
        "locator":{"uri":"zip:0.integrity", "size":33554432}
      }
    },
    "policy":"<base64-policy-json>"
  },
  "assertions":[]
}
```

`attached` and `explicit` are defaults when their fields are absent. Thus an
explicit attached object retains the version 4 field shape apart from
`schemaVersion`.

### 2.2 Top-level fields

| Field | Type | Required | Description |
|---|---|---|---|
| `schemaVersion` | string | REQUIRED | New objects MUST use `"5.0.0"`. |
| `packaging` | string | OPTIONAL | `attached`, `detached`, or `sharded`; default `attached`. |
| `payload` | object | REQUIRED | Representation selected by packaging. |
| `encryptionInformation` | object | REQUIRED | KAOs, method, integrity, policy, and optional key derivation. |
| `assertions` | array | OPTIONAL | BaseTDF-ASN assertions; detached/sharded require one manifest signature. |
| `extends` | object | OPTIONAL | Append predecessor and consistency proof. |

A 5.0 reader MUST NOT assign security meaning to unknown fields. It MUST reject any
future minor-version feature it cannot validate completely.

## 3. Packaging Dispatch

| Profile | Required payload fields | Forbidden payload fields |
|---|---|---|
| `attached` | `type: reference`, `url: 0.payload`, `protocol: zip`, `isEncrypted: true` | `locators`, `parts`, `size` |
| `detached` | `type: detached`, `isEncrypted: true`, exact encrypted `size`, non-empty `locators` | `url`, `protocol`, `parts` |
| `sharded` | `type: detached`, `isEncrypted: true`, exact encrypted `size`, non-empty `parts` | `url`, `protocol`, top-level `locators` |

`mimeType` is OPTIONAL and defaults to `application/octet-stream`.
`contentBinding` is OPTIONAL and defined by BaseTDF-PKG; it does not replace the
root signature. Detached/sharded readers MUST verify the manifest assertion before
using any BaseTDF-LOC locator.

## 4. Encryption Information

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | REQUIRED | MUST be `split`. |
| `keyAccess` | array | REQUIRED | One or more BaseTDF-KAO objects. |
| `method` | object | REQUIRED | Content-encryption parameters. |
| `keyDerivation` | object | conditional | Partition key derivation; REQUIRED above the Section 4.3 volume limit. |
| `integrityInformation` | object | REQUIRED | BaseTDF-INT profile. |
| `policy` | string | REQUIRED | Base64 of the exact BaseTDF-POL JSON string. |

Policy, KAO, and KAS semantics are unchanged from BaseTDF 4.4.

### 4.1 Method

| Field | Required | Description |
|---|---|---|
| `algorithm` | yes | Registered content-encryption algorithm. |
| `iv` | yes | Legacy method IV; MAY be empty because each segment carries an IV. |
| `isStreamable` | yes | MUST be `true`. |
| `noncePrefix` | scalable layouts only | Base64 encoding of exactly four random bytes. |

For `uniform` and `indexed`, segment `i` MUST carry
`noncePrefix || u64be(i)` and readers MUST reject a mismatch. Explicit layout keeps
the version 4 unique-IV rules.

### 4.2 Partition keys

```json
{"keyDerivation":{"alg":"HKDF-SHA256", "partitionSegments":512}}
```

`partitionSegments` MUST be positive. For `p = floor(i / partitionSegments)`:

```text
K_p = HKDF-Expand(PRK = DEK,
                  info = UTF8("BaseTDF-part-v1") || u64be(p), L = 32)
```

This is RFC 5869 Expand with the DEK directly as PRK and no Extract step. Segment
encryption and HS256 segment hashing use `K_p`; Merkle nodes and roots use the DEK.
Without this object, segments use the DEK as in version 4. Distributed workers MUST
receive only assigned partition keys. Append checkpoints MUST end at a partition
boundary unless `partitionSegments` is one.

### 4.3 Volume limits

No content-encryption key may protect more than `MAXKEYBYTES = 2^40` plaintext
bytes (1099511627776). BaseTDF-SEC Section 6.7 gives the analysis; this section
gives the manifest constraints. Writers MUST satisfy them and readers MUST reject a
manifest that violates them.

Let `T` be the total plaintext protected under one DEK: `plaintextSize` for a
scalable layout, or the checked sum of `segments[].segmentSize` for an explicit
one. For an append chain, `T` is the cumulative total at the current head
(Section 7), not the increment.

1. `keyDerivation` is REQUIRED when `T > MAXKEYBYTES`, because otherwise every
   segment is encrypted under the DEK.
2. When `keyDerivation` is present, no partition may cover more than
   `MAXKEYBYTES` plaintext bytes. With `n = min(partitionSegments, segmentCount)`:

```text
uniform:  n * segmentSizeDefault <= MAXKEYBYTES
indexed:  n * segmentSizeMax     <= MAXKEYBYTES
explicit: for every p,
          sum(segmentSize[i] : floor(i / partitionSegments) = p) <= MAXKEYBYTES
```

The uniform and indexed forms are conservative upper bounds computable from the
manifest header alone, because `segmentSizeDefault` and `segmentSizeMax` bound
every segment in their layouts. The explicit form is exact because every size is
recorded. An indexed writer whose actual partition bytes fall under the ceiling but
whose `segmentSizeMax` product does not MUST still lower `partitionSegments`; the
check is on the manifest, not on the realized sizes.

The DEK itself is unconstrained by `MAXKEYBYTES` when `keyDerivation` is present,
since it then serves only as the HKDF PRK and the Merkle HMAC key.

Each TDF object MUST use a freshly generated DEK; a DEK MUST NOT be reused across
objects (BaseTDF-SEC Section 6.7.5).

## 5. Integrity Dispatch

Common required fields are `rootSignature`, `segmentHashAlg`,
`segmentSizeDefault`, and `encryptedSegmentSizeDefault`.

| Layout | Additional required | MUST be absent |
|---|---|---|
| `explicit` (default) | `segments` | scalable count/total/tree fields |
| `uniform` | `layout`, `segmentCount`, `lastSegmentSize`, `plaintextSize`, `encryptedSize`, `hashTree`, `MERKLE-HS256` root | `segments`, `segmentSizeMax` |
| `indexed` | `layout`, `segmentCount`, `segmentSizeMax`, `plaintextSize`, `encryptedSize`, `hashTree`, `MERKLE-HS256` root | `segments`, `lastSegmentSize` |

Counts, totals, and tree metadata MUST be validated before allocation.

### 5.1 Hash tree

| Field | Required | Description |
|---|---|---|
| `nodeSize` | yes | 32 for uniform, 48 for indexed. |
| `levels` | yes | Stored levels including leaves and root. |
| `size` | yes | Exact artifact bytes. |
| `locator` | conditional | One BaseTDF-LOC locator. |
| `inline` | conditional | Base64 complete artifact. |

Exactly one of `locator` and `inline` is REQUIRED. The decoded/fetched length MUST
equal `size`; its header and authenticated root MUST agree with the manifest.

## 6. Assertions and Manifest Authentication

BaseTDF-ASN defines assertions. Ordinary `tdo`/`payload` assertions bind to the
explicit aggregate hash or scalable Merkle root. Detached and sharded manifests
MUST have exactly one `scope: manifest` assertion with an asymmetric JWS. It signs
the RFC 8785 canonical manifest after removing that assertion. The publisher key
MUST be trusted by local policy before any locator is dereferenced. Attached
manifests MAY include one such assertion.

## 7. Append Extension

```json
{"extends":{
  "sequence":41,
  "manifestDigestAlg":"SHA-256",
  "manifestDigest":"<base64-prior-canonical-manifest-digest>",
  "segmentCount":262144,
  "plaintextSize":549755813888,
  "encryptedSize":549763153920,
  "rootSignature":"<base64-prior-root>",
  "consistencyProof":[
    {"hash":"<base64>", "plaintextTotal":2097152,
     "encryptedTotal":2097180}
  ]
}}
```

`sequence` increments by one, beginning at one. The predecessor digest is SHA-256
over its RFC 8785 canonical manifest. Old counts/totals/root MUST authenticate and
be smaller than the new values. BaseTDF-INT defines proof verification.

The DEK, layout, content algorithm, nonce prefix, segment-size parameters, and KDF
parameters MUST remain identical. Indexed short tails may become interior segments;
a uniform predecessor is extendable only when its tail was full. A consistency
proof proves a prefix, not freshness or the canonical head. Single-history
publishers MUST serialize publication and retain fork evidence.

## 8. Creation Flow

A writer MUST:

1. choose and validate packaging and layout;
2. generate a fresh 256-bit DEK and, for scalable layouts, a four-byte nonce
   prefix, and select `keyDerivation` to satisfy Section 4.3;
3. create policy, splits, and KAOs;
4. encrypt ordered segments with unique/deterministic IVs and compute hashes;
5. create the explicit aggregate root or scalable Merkle tree and root;
6. populate checked sizes, counts, and tree metadata;
7. add the asymmetric manifest assertion after all other detached/sharded content;
   and
8. serialize using BaseTDF-PKG.

A distributed reducer need only receive ordered fixed-size hashes and sizes from
workers; it MUST NOT need ciphertext to construct Merkle commitments or the manifest.

## 9. Reading Flow

A reader MUST:

1. obtain and size-bound the manifest;
2. validate version and profile structure, normalizing default packaging/layout;
3. verify detached/sharded manifest signatures before locators;
4. validate locators and exact resource sizes;
5. complete KAS authorization, verify policy bindings, and reconstruct the DEK;
6. validate algorithms, integrity structure, and the Section 4.3 volume limits;
7. verify requested ciphertext under BaseTDF-INT, including IV, segment hash,
   Merkle path when applicable, sizes, count, root, and AEAD tag; and
8. release only authenticated plaintext and verify applicable assertions.

An API MUST distinguish selected-range verification from whole-object verification.

## 10. Version Compatibility

Writers MUST use `schemaVersion: "5.0.0"`. Readers MUST accept compatible 5.0.x
patch versions, MAY accept a later 5.x minor only when every required feature is
understood, and MUST reject an unsupported major. A 5.0 reader MUST read 4.3.x and
4.4.x under version 4 rules and SHOULD treat an absent version as pre-4.3 legacy
when legacy support is enabled. A 4.x reader is expected to reject major version 5.

For version 4, packaging/layout normalize to attached/explicit. Legacy hash encoding
and KAO aliases remain readable. A 5.0 writer MUST NOT create legacy encoding or
deprecated KAO fields.

## 11. Security Considerations

The manifest is cleartext. Detachment compartmentalizes storage but does not hide
policy, attributes, KAS URLs, assertions, MIME type, sizes, or locators from its
host. The public manifest signature protects provenance and routing fields; the DEK
root remains authoritative for ciphertext. Multiple manifests have union-policy
semantics. Parsers and resolvers MUST bound resources and fail on arithmetic overflow.

## 12. Normative References

- [BaseTDF-SEC](basetdf-sec.md)
- [BaseTDF-ALG](basetdf-alg.md)
- [BaseTDF-POL](basetdf-pol.md)
- [BaseTDF-KAO](basetdf-kao.md)
- [BaseTDF-KAS](basetdf-kas.md)
- [BaseTDF-INT](basetdf-int.md)
- [BaseTDF-ASN](basetdf-asn.md)
- [BaseTDF-LOC](basetdf-loc.md)
- [BaseTDF-PKG](basetdf-pkg.md)
- RFC 5869; RFC 8785
