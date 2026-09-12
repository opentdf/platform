# ICTDF-MIG: IC-TDF and BaseTDF Interoperability

| | |
|---|---|
| Document | ICTDF-MIG |
| Guide version | 0.1 |
| Source spec | IC-TDF.XML.V2014-DEC-r2017-JUL |
| TDF version | 201412.201707 |
| Status | Non-normative |
| Depends on | ICTDF-CORE, ICTDF-POL, ICTDF-KAO, ICTDF-PAY |

This guide compares IC-TDF with BaseTDF 5 and describes what conversion between them costs.
It is non-normative: nothing here changes either format.

## 1. The short version

The two formats solve overlapping problems from opposite ends.

| | IC-TDF | BaseTDF 5 |
|---|---|---|
| Serialization | One XML document | ZIP container with a JSON manifest |
| Metadata model | Assertions with scope over a document tree | Assertions and a policy object in a manifest |
| Access control | IC markings (ISM, NTK) evaluated by a decision function | Attribute FQNs evaluated by a KAS |
| Key access | Descriptors only; no protocol | KAOs plus a defined rewrap protocol |
| Payload integrity | Encryption tag, or binding coverage | Segmented Merkle integrity information |
| Collections | Native, recursive, with transitive scope | Not modeled |
| Validation | Multi-pass over foreign-namespace content | Manifest schema plus signature checks |

Neither is a superset of the other. Conversion in either direction loses something, and the
loss is structural rather than a gap in tooling.

## 2. Concept mapping

| IC-TDF | BaseTDF 5 | Fidelity |
|---|---|---|
| `TrustedDataObject` | TDF object with manifest and payload | Close |
| `TrustedDataCollection` | — | No counterpart |
| `HandlingAssertion` `@scope="TDO"` | Policy object plus a handling assertion | Lossy; see §4 |
| `HandlingAssertion` `@scope="PAYL"` | No distinct payload-level marking | Lossy |
| `tdf:Assertion` | BaseTDF-ASN assertion | Close for the statement; scope is lost |
| `@tdf:scope` | — | No counterpart; see §3 |
| `StatementMetadata` | Assertion `statement` metadata | Partial |
| `@tdf:appliesToState` | — | No counterpart; see §5 |
| `Binding` / `SignatureValue` | Assertion binding and manifest signature | Different coverage model |
| `EncryptionInformation` | `encryptionInformation` | Close |
| `KeyAccess` / `RemoteStoredKey` | KAO with `kas`, `kid`, `alg` | Close under ICTDF-OPENTDF |
| `WrappedPDPKey` | KAO plus policy object | Close in intent |
| `@tdf:sequenceNum` layering | — | No counterpart; see §6 |
| `StringPayload` etc. | `payload` entry with `mimeType` | Close |
| `ReferenceValuePayload` | BaseTDF-LOC detached storage | Close in intent |
| — | `integrityInformation` segments | No IC-TDF counterpart |
| — | Key splitting (`sid`) | No IC-TDF counterpart |

## 3. Scope has no counterpart

Scope is the concept that does not survive conversion in either direction, and it is the
one IC-TDF is built around.

An IC-TDF assertion states what it is about — the payload, the object, each member of a
collection, every descendant payload — and a binding over that assertion authenticates
exactly that set (ICTDF-BND §2). BaseTDF assertions attach to the object; there is no
sub-object addressing and no transitive form.

Consequences:

- Converting IC-TDF to BaseTDF collapses `PAYL`, `TDO`, `TDC_MEMBER`, `DESC_TDO`, and
  `DESC_PAYL` into one level. Assertions that meant different things become
  indistinguishable, and their bindings' coverage sets cannot be reconstructed.
- Converting BaseTDF to IC-TDF requires inventing a scope for every assertion. `TDO` is the
  safe choice and is also the most conservative, because it is the widest coverage.
- A round trip does not restore the original. Scope information destroyed in the first
  direction is not recoverable in the second.

## 4. Markings and policy

IC-TDF carries markings; BaseTDF carries attributes. Neither derives from the other
automatically.

Going from IC-TDF to BaseTDF requires the mapping described in ICTDF-OPENTDF §3: a total,
deterministic, deployment-published function from marking values to attribute FQNs. That
mapping is a security boundary — an error in it silently over-releases and no validation
step catches it.

Going from BaseTDF to IC-TDF is harder. An IC-TDF object requires an IC-EDH handling
assertion with an ARH security block bearing `@ism:resourceElement="true"`
(`IC-TDF-ID-00016`), and there is no way to synthesize valid ISM markings from attribute
FQNs. In practice the producer must already know the markings; the BaseTDF object does not
contain them.

Rollup is also unmatched. IC-TDF requires the object-scope marking to dominate everything
inside (ICTDF-POL §4), which lets a guard act on the head of the document alone. BaseTDF's
policy object is authoritative by construction rather than by rollup, so there is nothing to
compute in that direction and nothing to derive in the other.

## 5. Data state

IC-TDF marks an encrypted part twice: once for the ciphertext and once for the plaintext,
with the plaintext marking held externally and excluded from rollup (ICTDF-POL §5).

BaseTDF has one policy. It describes what is required to open the object, which is closest
to IC-TDF's `unencrypted` marking; the `encrypted` marking, describing the ciphertext as it
travels, has no representation at all.

Converting IC-TDF to BaseTDF therefore discards the marking a guard uses to decide whether
the ciphertext may cross a boundary. For deployments where that decision matters, the
converted object is not a substitute for the original.

## 6. Layering versus splitting

Both formats can involve more than one key, and they mean different things by it.

IC-TDF `@sequenceNum` layers encryption: layer 1 innermost, highest number outermost, every
layer removable in turn. Recovery requires all of them.

BaseTDF splits the data encryption key: KAOs sharing an `sid` are alternative routes to one
share, and different `sid` values are shares that must be combined. Recovery requires one
KAO per share.

Neither expresses the other. An `allOf` split is not a set of layers, and a set of layers
is not a split. A converter MUST NOT map one onto the other; where a deployment needs split
semantics, IC-TDF cannot carry them (ICTDF-OPENTDF §2.4).

## 7. Integrity

BaseTDF-INT defines segmented integrity: the payload is chunked, each chunk hashed, and the
hashes are covered by the manifest signature. That allows large payloads, streaming, and
verified partial reads.

IC-TDF has none of this. Payload integrity comes from the encryption method's
`AuthenticationTag`, from a binding whose scope covers the payload, or from both — and the
unit is the whole payload. There is no conforming way to release a verified prefix
(ICTDF-CORE §7).

Converting BaseTDF to IC-TDF discards the segment tree. Converting the other way requires
computing one, which means reading the whole payload.

## 8. Collections

IC-TDF collections are native and recursive, with transitive scope and recursive validation
(ICTDF-VAL §5). BaseTDF has no collection type.

A converter has three options, none of them lossless:

- emit one BaseTDF object per member TDO, losing the collection's own assertions and its
  rolled-up marking;
- emit one BaseTDF object whose payload is the serialized collection, which preserves the
  bytes but makes the members opaque to BaseTDF tooling; or
- refuse.

The first is usually right for dissemination and the third is usually right for archival.

## 9. Converting in practice

If converting IC-TDF to BaseTDF:

1. Validate the source with ICTDF-VAL in full. Do not convert an object you have not
   validated.
2. Verify every binding, and record which assertions were authenticated. Assertions that
   were not stay unauthenticated in the result.
3. Decrypt and re-encrypt. The formats' encryption structures are not interchangeable at
   the byte level, so conversion is a re-protect, and the converter briefly holds plaintext.
4. Apply the marking-to-attribute mapping (§4). Fail on any unmapped marking.
5. Record what was dropped: scope, the `encrypted`-state marking, payload-level markings,
   and collection structure. A converter that drops these silently produces an object that
   looks equivalent and is not.

If converting BaseTDF to IC-TDF, the producer must supply IC markings out of band (§4),
choose a scope for each assertion (§3), and accept that segment integrity is replaced by
whole-payload authentication (§7).

## 10. When not to convert

Conversion is a re-protect performed by a party who sees plaintext and re-asserts markings.
That party becomes part of the trust chain, and the original signer's bindings do not
survive.

Where the original object's provenance is what matters, carry the IC-TDF document as a
BaseTDF payload rather than converting it. The bytes and their bindings stay intact, a
BaseTDF consumer can handle the outer object, and an IC-TDF consumer can extract and verify
the inner one.
