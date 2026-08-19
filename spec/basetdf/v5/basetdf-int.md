# BaseTDF-INT: Integrity Verification and Scalable Layouts

| | |
|---|---|
| **Document** | BaseTDF-INT |
| **Version** | 5.0.0 |
| **Status** | Standards Track |
| **Date** | 2026-08 |
| **Depends on** | BaseTDF-SEC, BaseTDF-ALG, BaseTDF-LOC |
| **Referenced by** | BaseTDF-CORE, BaseTDF-ASN, BaseTDF-PKG |

## 1. Introduction

Payloads are independently encrypted segments concatenated in order. BaseTDF 5
defines three layouts:

| Layout | Metadata | Offset lookup | Partial proof |
|---|---|---|---|
| `explicit` | Version 4 JSON record per segment | prefix sum | root validation is O(N) |
| `uniform` | constant manifest + binary Merkle tree | O(1) | O(log N) hashes |
| `indexed` | constant manifest + Merkle sum tree | authenticated O(log N) | O(log N) commitments |

Scalable layouts bind index, sizes, count, totals, and layout into a DEK-keyed root.
`u64be`/`u64le` are unsigned 64-bit encodings; `||` is concatenation. All arithmetic
MUST be checked for overflow.

## 2. Segment Model

Segments are numbered from zero and stored in plaintext order. Every payload has at
least one segment. An empty payload is one zero-plaintext-byte segment; other
zero-length segments are prohibited.

```text
encrypted_segment_i = IV_i || ciphertext_i || tag_i
```

AES-256-GCM uses a 12-byte IV and 16-byte tag, so encrypted size is plaintext size
plus 28. The tag MUST be verified before segment plaintext is released.

With no key derivation, a segment uses the DEK. Otherwise it uses `K_p` from CORE,
where `p = floor(i / partitionSegments)`. Merkle nodes and roots always use the DEK.

For `uniform` and `indexed`:

```text
IV_i = noncePrefix || u64be(i)
```

Writers MUST use this IV and readers MUST compare it with the 12-byte segment prefix.
Explicit layout retains the version 4 unique-IV rule and MAY use this construction.

## 3. Segment Hashes

Let `SK_i` be the DEK or applicable partition key.

```text
HS256: segment_hash_i = HMAC-SHA256(SK_i, encrypted_segment_i)
GMAC:  segment_hash_i = tag_i
```

HS256 produces 32 bytes. GMAC uses the final 16-byte AES-GCM tag and requires no
second ciphertext pass. Manifest values are padded base64; constructions consume
decoded bytes.

## 4. Explicit Layout

Absent `layout` means `explicit`. The version 4 shape is retained:

```json
{
  "rootSignature":{"alg":"HS256", "sig":"<base64>"},
  "segmentHashAlg":"GMAC",
  "segmentSizeDefault":2097152,
  "encryptedSegmentSizeDefault":2097180,
  "segments":[
    {"hash":"<base64>", "segmentSize":2097152,
     "encryptedSegmentSize":2097180}
  ]
}
```

There is exactly one ordered record per segment. Every encrypted size MUST equal
plaintext size plus 28. Interior sizes SHOULD equal the defaults, but arbitrary
recorded sizes remain valid for version 4 compatibility.

```text
aggregate_hash = segment_hash_0 || ... || segment_hash_(N-1)
HS256 root_signature = HMAC-SHA256(DEK, aggregate_hash)
```

The legacy `GMAC` root is the final 16 bytes of `aggregate_hash`. New writers SHOULD
use HS256. Before explicit-layout decryption, a reader MUST validate the root over
all recorded hashes. It then validates requested segment hash, IV, size, and AEAD
tag before release. Readers SHOULD build a checked prefix-sum index once.

## 5. Scalable Layouts

Both require `rootSignature.alg: MERKLE-HS256`, `layout`, `segmentCount`,
`plaintextSize`, `encryptedSize`, and `hashTree`, and MUST omit `segments`.
`segmentCount` is positive and manifest totals MUST equal authenticated root totals.

### 5.1 Uniform

`lastSegmentSize` is REQUIRED and `segmentSizeMax` absent. Segments `0..N-2` MUST
equal `segmentSizeDefault`. The last size is `1..segmentSizeDefault`, except zero for
the single empty segment.

```text
encryptedSegmentSizeDefault = segmentSizeDefault + 28
plaintextSize = (segmentCount - 1) * segmentSizeDefault + lastSegmentSize
encryptedSize = plaintextSize + 28 * segmentCount
```

For plaintext offset `B < plaintextSize`:

```text
i             = floor(B / segmentSizeDefault)
intraOffset   = B mod segmentSizeDefault
payloadOffset = i * encryptedSegmentSizeDefault
```

This closed-form arithmetic is normative. Cross-segment ranges are split.

### 5.2 Indexed

`segmentSizeMax` is REQUIRED and `lastSegmentSize` absent. Any non-empty segment may
be short, including interior segments. Each size MUST not exceed the manifest and
reader limits. `segmentSizeDefault` is a writer target. Writers SHOULD coalesce tiny
segments unless an application requests a checkpoint. Authenticated subtree sums
provide O(log N) lookup (Section 8).

## 6. Merkle Construction

A commitment is `C = (H, P, E)`, with 32-byte `H` and plaintext/encrypted totals.

### 6.1 Leaf

```text
H_i = HMAC-SHA256(DEK,
    0x00 || u64be(i) || u64be(P_i) || u64be(E_i) || segment_hash_i)
C_i = (H_i, P_i, E_i)
```

`E_i` MUST equal `P_i + 28`.

### 6.2 Internal node

```text
P = P_L + P_R
E = E_L + E_R
H = HMAC-SHA256(DEK,
    0x01 || u64be(P_L) || u64be(E_L) || H_L
         || u64be(P_R) || u64be(E_R) || H_R)
C = (H, P, E)
```

At each level, adjacent nodes pair from the left. An odd final commitment is
promoted unchanged, not duplicated or self-hashed. Level 0 is the leaf array and
the last level contains one root.

### 6.3 Root signature

`layoutCode` is byte `0x01` for uniform and `0x02` for indexed.

```text
root_signature = HMAC-SHA256(DEK,
    0x02 || layoutCode || u64be(segmentCount)
         || u64be(P_root) || u64be(E_root) || H_root)
```

The reader MUST compare MACs in constant time and require root totals to equal the
manifest. Domain bytes prevent type confusion; the authenticated count prevents
promotion/duplication ambiguity.

### 6.4 Streaming build and assertion binding

A writer can fold leaves using one stack slot per height, O(log N) resident state.
Leaf records MAY spill to temporary storage. Final folding preserves left/right and
promotion. `H_root` is the scalable payload-binding value used by ordinary ASN
assertions; explicit layout retains `aggregate_hash`.

## 7. Binary Integrity Artifact

The complete tree is level-order. Header integers and indexed totals are
little-endian; hashes are opaque.

```text
offset  size  field
0       8     magic       42 54 44 46 4d 54 01 00 ("BTDFMT\x01\x00")
8       4     version     u32le = 1
12      1     nodeSize    32 uniform; 48 indexed
13      1     levels      ceil(log2(leafCount)) + 1; 1 for one leaf
14      1     layout      1 uniform; 2 indexed
15      1     reserved    zero
16      8     leafCount   u64le
24      8     nodeCount   u64le
32      ...   records     leaves, successive levels, root
```

Uniform record: `H[32]`. Indexed record:

```text
H[32] || u64le(plaintextTotal) || u64le(encryptedTotal)
```

For level `l`:

```text
levelCount(l) = ceil(leafCount / 2^l)
levelOffset(l) = 32 + nodeSize * sum(levelCount(j), 0 <= j < l)
recordOffset(l,j) = levelOffset(l) + nodeSize * j
```

`nodeCount` MUST be the checked sum of all level counts; artifact size MUST be
exactly `32 + nodeSize * nodeCount`, without trailing bytes. Before allocation or
access, readers MUST validate magic, version, reserved, layout, node size, levels,
leaf/node counts, exact size, and manifest agreement. Parsed records remain
untrusted until authenticated to the DEK root.

## 8. Proofs and Indexed Lookup

### 8.1 Inclusion proof shape

For leaf `i` at level `l`:

```text
n_l = ceil(segmentCount / 2^l)
j_l = floor(i / 2^l)
```

If `j_l` is odd, sibling `j_l-1` is left. If even and `j_l+1 < n_l`, sibling
`j_l+1` is right. Otherwise the node is promoted and has no proof item. Direction
and omissions derive from `(i, segmentCount)` and MUST NOT be trusted from an
encoding. A proof contains only existing siblings from leaf to root.

Uniform items contain hashes and derive totals. Indexed items contain `(H,P,E)`.
A verifier MUST reject missing, extra, duplicated, or wrong-sized items, promote
only at implied levels, combine in implied order, and verify the root signature.

### 8.2 Uniform totals

Node `(l,j)` covers:

```text
[j * 2^l, min((j + 1) * 2^l, segmentCount))
```

Its plaintext total is the sum of full default leaves plus the last size if covered;
encrypted total adds 28 per covered leaf. These totals MUST be used in proof folding.

### 8.3 Indexed offset lookup

Require `B < plaintextSize`. Authenticate the root record and manifest totals. Set
`payloadOffset=0`. At each non-leaf level:

1. derive whether the node has one promoted child or two children;
2. fetch the child or adjacent pair in a bounded range;
3. recompute the parent for a pair, or require exact equality for promotion;
4. descend left if `B < P_left`; otherwise subtract `P_left`, add `E_left` to
   `payloadOffset`, and descend right; and
5. reject zero invalid subtrees, limit violations, mismatch, or overflow.

At the leaf, `B` is intra-segment offset and `payloadOffset` the encrypted offset.
The authenticated leaf supplies exact sizes. The reader MUST retain or complete an
equivalent root proof. Before the payload request, the path/root MUST authenticate.
After fetching, recompute the actual segment hash and leaf before decryption/release.

## 9. Verification Profiles

### 9.1 Whole object

A whole-object verifier reconstructs the DEK; validates manifest/tree bounds;
processes every encrypted segment with IV, size, hash, and AEAD checks; rebuilds the
aggregate or tree; and verifies count, totals, and root. Whole-object success MUST
not be reported sooner. A streaming reader MAY release each authenticated segment,
but on later failure releases no more and signals the failure.

### 9.2 Selected range

Partial verification is conformant only for scalable layouts. For every covering
segment, the reader MUST:

1. authenticate the tree leaf and proof, including layout, count, and totals;
2. fetch exactly the authenticated encrypted range;
3. validate deterministic IV;
4. recompute segment hash and the index/size-bound leaf;
5. compare it with the authenticated leaf;
6. verify AES-GCM during decryption; and
7. release only requested bytes from that segment.

This authenticates returned bytes as the writer's bytes at that index in the rooted
object. It does not verify unrequested segments. APIs MUST distinguish selected-
range from whole-object verification.

### 9.3 Failure

Any parse, proof, size, hash, root, IV, tag, or arithmetic failure stops processing
and further release. Non-streaming plaintext MUST be discarded. Implementations
MUST NOT fall back to an unverified profile, locator, algorithm, or boundary.

## 10. Consistency Proofs

The append profile instantiates RFC 6962 Sections 2.1/2.2 tree shape and consistency
algorithm with Section 6's keyed commitments. Proof entries are RFC-ordered hashes
for uniform or full commitments for indexed. Verification MUST authenticate old and
new roots, counts, and totals; establish unchanged strict prefix leaves; and enforce
CORE's immutable chain parameters. Equality, changed leaves, promotion ambiguity,
overflow, and total mismatch MUST fail.

A uniform predecessor is extendable only if its final leaf was full. Indexed short
tails remain unchanged as interior leaves. A KDF checkpoint ends on a partition
boundary unless partition size is one. Consistency proves prefix inclusion to a DEK
holder, not freshness or the latest canonical head.

## 11. Legacy Encoding

Pre-4.3 objects (absent version or semantic version below 4.3.0) base64-encode hex
text rather than raw hash bytes. Legacy-capable readers MUST reproduce that explicit-
layout behavior. Version 4.3+ uses raw-byte base64. New 5.0 writers MUST NOT create
legacy encoding. Version 4 explicit roots, size flexibility, and KAO aliases remain
readable; scalable layouts require major version 5+.

## 12. Security Considerations

The tree may live on untrusted storage and is safe only after nodes fold to the
DEK-keyed root. Headers/reads still require pre-authentication bounds. GMAC segment
hashes have 128-bit output, while every Merkle hash/root is HMAC-SHA256. Partition
keys limit worker scope but are not forward-secret. Deterministic uniqueness still
requires a fresh random nonce prefix for each DEK and no reuse of a
`(segment key, nonce prefix, index)` tuple.

## 13. Normative References

- [BaseTDF-ALG](basetdf-alg.md)
- [BaseTDF-CORE](basetdf-core.md)
- [BaseTDF-LOC](basetdf-loc.md)
- [BaseTDF-SEC](basetdf-sec.md)
- NIST SP 800-38D; RFC 2104; RFC 5869; RFC 6962

