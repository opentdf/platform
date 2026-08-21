# BaseTDF-PKG: Packaging Profiles

| | |
|---|---|
| **Document** | BaseTDF-PKG |
| **Version** | 5.0.0 |
| **Status** | Standards Track |
| **Date** | 2026-08 |
| **Depends on** | BaseTDF-INT, BaseTDF-ASN, BaseTDF-LOC |
| **Referenced by** | BaseTDF-CORE, BaseTDF-EX |

## 1. Introduction

Packaging defines where the manifest, ciphertext, and optional integrity tree are
serialized. It does not change policy, KAOs, the DEK, encryption, or integrity.

| `packaging` | Representation |
|---|---|
| `attached` | One ZIP containing payload, optional tree, and manifest. |
| `detached` | Standalone manifest referencing one payload object. |
| `sharded` | Standalone manifest referencing ordered payload parts. |

`packaging` MAY be omitted and defaults to `attached`, preserving the version 4
field shape for small attached objects.

## 2. Attached Profile

### 2.1 Entries

Entries use `STORE`, no ZIP encryption, and this order:

| Order | Entry | Presence |
|---:|---|---|
| 1 | `0.payload` | REQUIRED |
| 2 | `0.integrity` | REQUIRED for `uniform`/`indexed`; absent for `explicit` |
| 3 | `0.manifest.json` | REQUIRED |

Writers MUST NOT add other entries. The explicit profile therefore has exactly two
entries and scalable profiles have exactly three. The attached payload object MUST
be:

```json
{"type":"reference", "url":"0.payload", "protocol":"zip",
 "mimeType":"application/octet-stream", "isEncrypted":true}
```

For scalable layouts, `hashTree.locator.uri` MUST be `zip:0.integrity`.

### 2.2 Hardening

Readers MUST reject duplicate names, paths, `..`, overlapping records, unsupported
compression, ZIP encryption, and sizes above configured bounds. The central
directory is authoritative when it disagrees with a local header. ZIP64 parsing and
range arithmetic MUST use checked unsigned 64-bit operations. Readers MUST NOT
extract entries to filesystem paths derived from entry names.

### 2.3 Unknown-length streaming

A writer without advance payload length MUST:

1. use ZIP64 unconditionally;
2. set general-purpose bit 3 on the `0.payload` local header;
3. put zero in its local CRC-32 and size fields and include a ZIP64 extra field;
4. compute CRC-32 incrementally over encrypted bytes;
5. emit a signed ZIP64 data descriptor with CRC-32 and two 8-byte sizes immediately
   after payload data;
6. write the known-size integrity and manifest entries without descriptors; and
7. write ZIP64 central-directory, EOCD, and locator records.

Readers MUST support this form and prefer authoritative central-directory values.
A known-size writer SHOULD use ordinary size-prefixed entries, adding ZIP64 when
required. Payload-first ordering permits one forward pass; tree leaf records MAY
spill to temporary storage while the O(log N) root stack stays resident.

## 3. Detached Profile

```json
{
  "packaging":"detached",
  "payload":{
    "type":"detached", "mimeType":"application/octet-stream",
    "isEncrypted":true, "size":1099526307840,
    "locators":[{"uri":"https://payload.example/o/9f2a", "priority":0,
                 "size":1099526307840}]
  }
}
```

`payload.type`, `isEncrypted`, exact encrypted `size`, and non-empty `locators` are
REQUIRED. `size` MUST equal `integrityInformation.encryptedSize`. `url`, `protocol`,
and `parts` MUST be absent. Exactly one asymmetric `scope: "manifest"` assertion is
REQUIRED.

A scalable hash tree MUST have its own allowed locator or be base64-encoded in
`hashTree.inline`; those fields are mutually exclusive. Writers SHOULD inline trees
no larger than 64 KiB.

## 4. Sharded Profile

```json
{
  "packaging":"sharded",
  "payload":{
    "type":"detached", "isEncrypted":true, "size":2147512320,
    "parts":[
      {"index":0, "segmentRange":[0,512], "size":1073756160,
       "locators":[{"uri":"https://a.example/p0"}]},
      {"index":1, "segmentRange":[512,1024], "size":1073756160,
       "locators":[{"uri":"https://b.example/p1"}]}
    ]
  }
}
```

Ranges are half-open. Parts MUST have consecutive indices from zero, non-empty
locators, and ordered contiguous non-overlapping ranges covering
`[0, segmentCount)`. Boundaries MUST be segment-aligned. Checked part-size sums
MUST equal payload `size` and authenticated `encryptedSize`; indexed part sizes
MUST equal authenticated subtree sums. Boundaries SHOULD align with key partitions.

The sharded profile is REQUIRED when a logical BaseTDF exceeds any individual
storage resource's object-size limit. A storage limit applies to encrypted bytes,
not plaintext bytes: every AES-GCM segment adds 28 bytes, and attached packaging
also carries integrity and ZIP metadata. Consequently, a maximum-sized plaintext
object generally cannot be encrypted into one resource having the same maximum
size. Writers MUST calculate encrypted sizes before selecting part boundaries and
MUST NOT assume that a provider's advertised plaintext-scale limit includes AEAD
overhead.

Scalable implementations MUST support a logical 50 TiB plaintext using sharded
packaging even when no individual locator can hold the complete encrypted payload.
Shards MAY contain many key partitions; aligning each shard boundary with both a
segment boundary and a key-partition boundary is RECOMMENDED. Multipart-upload part
numbers and retry order are transport details and MUST NOT be used as AES-GCM IVs
or BaseTDF segment indices.

Top-level payload `locators`, `url`, and `protocol` MUST be absent. Exactly one
manifest assertion is REQUIRED.

## 5. Content Binding and Multiple Manifests

The payload MAY contain `"contentBinding":{"alg":"SHA-256","hash":"<base64>"}`,
computed over the complete encrypted byte sequence independent of sharding. It is
useful for deduplication but is a stable cross-tenant correlation handle, so writers
SHOULD omit it by default. The DEK-keyed root is authoritative.

Multiple standalone manifests MAY wrap the same DEK for one payload. Their effective
access policy is the union of all published policies. A less restrictive new
manifest widens access to the original ciphertext. Writers MUST NOT claim this
provides differentiated access; genuine separation requires a distinct DEK and
re-encryption. A payload carries no manifest pointer; discovery is out of scope.

## 6. Processing and Security

Detached/sharded readers MUST verify the manifest signature before resolving an
external locator and use BaseTDF-LOC. In all profiles, ciphertext and tree nodes are
untrusted until verified by BaseTDF-INT.

Attached storage exposes metadata and ciphertext together. Detached storage lets a
payload host see opaque ciphertext while a manifest host sees policy, KAS and
attribute identifiers, assertions, MIME type, sizes, and locators. It does not hide
metadata from the manifest host, and traffic analysis may correlate fetches.

Destroying every detached manifest can remove stored KAOs and the path to the DEK,
but cannot revoke plaintext or DEKs already obtained.

## 7. Normative References

- [BaseTDF-ASN](basetdf-asn.md)
- [BaseTDF-CORE](basetdf-core.md)
- [BaseTDF-INT](basetdf-int.md)
- [BaseTDF-LOC](basetdf-loc.md)
- APPNOTE 6.3.10, ZIP File Format Specification
