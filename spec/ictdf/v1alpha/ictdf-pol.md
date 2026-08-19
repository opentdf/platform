# ICTDF-POL: Handling Assertions and Access Policy

| | |
|---|---|
| Document | ICTDF-POL |
| Version | 1 Alpha |
| Source spec | IC-TDF.XML.V2014-DEC-r2017-JUL |
| TDF version | 201412.201707 |
| Status | Draft |
| Depends on | ICTDF-SEC, ICTDF-MTD, ICTDF-SCP |
| Referenced by | ICTDF-BND, ICTDF-KAS, ICTDF-VAL, ICTDF-CORE, ICTDF-OPENTDF, ICTDF-MIG |

## 1. Role

A handling assertion carries the dissemination controls that govern the object. It is the
part a guard reads to decide whether the object may cross a boundary, and it is therefore
the one part of a TDF that MUST remain in the clear. Handling assertions are never
encrypted, and no `EncryptionInformation` applies to them.

```text
HandlingAssertion
  HandlingStatement
    edh:Edh | edh:ExternalEdh | rr:RevisionRecall
  Binding | ReferenceList    0..1

  @scope             required
  @id                optional
  @appliesToState    optional, PAYL scope only
```

Unlike `tdf:Assertion`, a handling assertion has no `StatementMetadata` and no
`EncryptionInformation`. Its statement is the marking.

## 2. Handling statement content

| Child | Meaning |
|---|---|
| `edh:Edh` | An IC Enterprise Data Header describing this object |
| `edh:ExternalEdh` | A data header held outside this document, identified by reference |
| `rr:RevisionRecall` | A revision or recall notice for the object |

An `edh:Edh` block carries the identifier, creation time, responsible entity, and — inside
it — the ARH security block that holds the ISM classification markings and any NTK access
information. IC-TDF does not define those markings; it defines where they live and how
they must agree across the object.

Required content by scope:

| Scope | Requirement | Rule |
|---|---|---|
| `TDO` | Exactly one handling assertion, containing an EDH | `IC-TDF-ID-00004` |
| `TDO` | The EDH MUST contain an ARH security block with `@ism:resourceElement="true"` | `IC-TDF-ID-00016` |
| `TDO` | MUST NOT use `edh:ExternalEdh` | `IC-TDF-ID-00018` |
| `TDC` | Exactly one handling assertion, containing an EDH | `IC-TDF-ID-00005` |
| `TDC` | The EDH MUST contain an ARH security block with `@ism:resourceElement="true"` | `IC-TDF-ID-00017` |
| `TDC` | MUST NOT use `edh:ExternalEdh` | `IC-TDF-ID-00019` |
| `TDC` | Handling assertions use no other scope | `IC-TDF-ID-00035` |
| any | The first handling assertion in document order is the `TDO`- or `TDC`-scope one and contains an EDH | `IC-TDF-ID-00042` |

The resource-element requirement is what makes the object's own marking authoritative:
`@ism:resourceElement="true"` designates the marking that applies to the resource as a
whole rather than to a portion of it.

A revision recall handling assertion is optional and additional. It uses the same scope as
the object's primary handling assertion and carries `@revrecall:DESVersion` of at least
`201412` (`IC-TDF-ID-00045`).

## 3. Payload handling assertions

A TDO MUST carry at least one handling assertion with `@scope="PAYL"` (`IC-TDF-ID-00003`).
The payload's marking is separate from the object's because the two differ: an object
whose payload is a reference to remote content is marked differently from the content it
points at.

- An unencrypted payload has at most one `PAYL` handling assertion containing an EDH
  (`IC-TDF-ID-00055`).
- A TDO whose payload is a `ReferenceValuePayload` MUST carry an `edh:ExternalEdh` in its
  `PAYL` handling assertion (`IC-TDF-ID-00033`), because the payload content is not
  present to be marked directly.
- An encrypted payload requires two, as described in §5.

## 4. Rollup

The TDO- or TDC-scope handling assertion states the marking of the object as a whole. That
marking MUST be at least as restrictive as everything the object contains — the producer
rolls up the markings of the payload, the statements, and, for a collection, its members.

Rollup is what makes the outermost marking safe to act on without parsing the interior. A
guard that reads only the first handling assertion must not be able to release something
the interior would have prohibited.

`ntk:Access` is rolled up the same way: need-to-know access information from the interior
MUST be reflected in the `TDO`-scope handling assertion (`IC-TDF-ID-00043`) and, for a
collection, in the `TDC`-scope handling assertion (`IC-TDF-ID-00044`).

Two things are outside rollup:

- the `unencrypted` marking of an encrypted part (§5), which describes plaintext that is
  not disclosed by this object. A producer signals the exclusion with
  `@ism:excludeFromRollup="true"` on the external security block; and
- the classification of a linked resource, which does not raise the classification of the
  TDO that links to it. Embedding that resource instead of linking to it does.

Extraction changes what an object contains, so an extractor MUST recompute rollup for the
result (ICTDF-SCP §4).

## 5. Encrypted payloads and data state

An encrypted payload needs two markings: one for the ciphertext travelling in the clear
and one for the plaintext it protects.

| Requirement | Rule |
|---|---|
| Exactly two `PAYL` handling assertions, one `@appliesToState="encrypted"` and one `"unencrypted"` | `IC-TDF-ID-00026` |
| `@appliesToState` permitted only when the payload has `@tdf:isEncrypted="true"` | `IC-TDF-ID-00025` |
| `@appliesToState` permitted only on `PAYL`-scope handling assertions | `IC-TDF-ID-00039` |
| The `unencrypted` assertion MUST contain `edh:ExternalEdh` | `IC-TDF-ID-00027` |
| If the payload is not itself external, the `encrypted` assertion MUST contain a regular `edh:Edh` | `IC-TDF-ID-00028` |

The external security block in the `unencrypted` assertion carries
`@ism:excludeFromRollup="true"`, which is what keeps the plaintext marking out of the
object's rolled-up classification.

The `unencrypted` marking is external by construction. Carrying the plaintext marking
inline would state the protected content's classification in the clear and would force
rollup to raise the whole object to that level, defeating the purpose of encrypting it.

The equivalent requirements for encrypted statements are in ICTDF-MTD §4.

## 6. Dependent specifications

IC-TDF does not define markings. It composes specifications that do, and constrains their
versions.

| Specification | Prefix | Minimum version | Carried in |
|---|---|---|---|
| IC Enterprise Data Header | `edh` | V4 | `HandlingStatement`, `StatementMetadata` |
| Access Rights and Handling | `arh` | V3 | Inside EDH, and in `StatementMetadata` |
| Information Security Marking | `ism` | V13 | Inside ARH |
| Need-To-Know Metadata | `ntk` | V10 | Inside ARH |
| Revision Recall | `revrecall` | V2014-DEC | `HandlingStatement` |
| US Agency Acronyms | `usagency` | V2016-SEP | Inside EDH |
| IC Identifier | `icid` | — | Inside EDH |

Version floors enforced by rule: `@edh:DESVersion` at least 1 (`IC-TDF-ID-00036`),
`@arh:DESVersion` at least 1 (`IC-TDF-ID-00037`), `@revrecall:DESVersion` at least 201412
(`IC-TDF-ID-00045`). ICTDF-VAL §6 covers the consistency rules that require one version
per dependent specification across a skeleton.

## 7. Policy is not authorization

A handling assertion is a description of the data. It states what controls apply; it does
not decide whether a given requester satisfies them.

- A consumer MUST evaluate markings against the requester's attributes through a policy
  decision function outside this suite. The document has no opinion about who may read it.
- Trust in a marking comes from the binding over it and the trust anchor of its signer,
  not from its presence (ICTDF-SEC §2).
- Mapping IC markings onto an attribute-based policy model is deployment-specific and MUST
  be explicit, total, and deterministic. ICTDF-OPENTDF §3 defines one such mapping;
  ICTDF-MIG §4 discusses the general problem.
