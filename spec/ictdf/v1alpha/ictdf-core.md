# ICTDF-CORE: Object Model and End-to-End Processing

| | |
|---|---|
| Document | ICTDF-CORE |
| Version | 1 Alpha |
| Source spec | IC-TDF.XML.V2014-DEC-r2017-JUL |
| TDF version | 201412.201707 |
| Status | Draft |
| Depends on | ICTDF-SEC, ICTDF-ALG, ICTDF-MTD, ICTDF-SCP, ICTDF-POL, ICTDF-BND, ICTDF-KAO, ICTDF-KAS, ICTDF-PAY, ICTDF-LOC, ICTDF-PKG, ICTDF-SCH, ICTDF-VAL |
| Referenced by | ICTDF-EX, ICTDF-MIG, IC-TDF profiles |

## 1. Scope

This module defines the IC-TDF object model and the end-to-end procedures for producing and
consuming an object. It composes the other modules and adds no wire format of its own.

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are interpreted as
described by BCP 14 when written in all capitals.

## 2. Object model

Two objects exist.

A **Trusted Data Object** is a payload plus the assertions that describe it. It is the unit
of protection.

```text
TrustedDataObject
  HandlingAssertion   @scope="TDO"       object marking, rolled up, never encrypted
  HandlingAssertion   @scope="PAYL"      payload marking; two when the payload is encrypted
  Assertion*                             other metadata, individually scoped and encryptable
  EncryptionInformation*                 payload encryption, layered by @sequenceNum
  Payload                                exactly one, of four forms
```

A **Trusted Data Collection** is a set of TDOs and nested TDCs plus the assertions that
describe them.

```text
TrustedDataCollection
  HandlingAssertion   @scope="TDC"       collection marking, rolled up
  HandlingAssertion   @scope="TDC"       optional revision recall
  Assertion*                             scoped TDC, TDC_MEMBER, DESC_TDO, or DESC_PAYL
  ( TrustedDataObject | TrustedDataCollection )+
```

Four properties define the model:

- **Scope** decides what an assertion is about and, when the assertion carries a binding,
  what that binding authenticates. Scope is the load-bearing concept (ICTDF-SCP).
- **Rollup** makes the outermost marking safe to act on alone, so a guard need not parse
  the interior (ICTDF-POL §4).
- **State** separates the marking of ciphertext from the marking of the plaintext it
  protects, keeping the latter out of rollup (ICTDF-MTD §4).
- **Composition** means IC-TDF defines placement and consistency, not markings, key
  services, or algorithms. Those come from IC-EDH, ARH, ISM, NTK, and deployment choices.

## 3. Producing an object

1. **Select the container.** One protected item is a TDO; a set that must travel and be
   marked together is a TDC.
2. **Place the payload.** Choose the form by content: text as `StringPayload`, octets or
   ciphertext as `Base64BinaryPayload`, foreign XML as `StructuredPayload`, absent content
   as `ReferenceValuePayload` (ICTDF-PAY §3).
3. **Encrypt, if required.** Emit `EncryptionInformation` per layer, number layers from 1
   with the highest outermost, set `@tdf:isEncrypted="true"`, and choose key access
   (ICTDF-KAO).
4. **Mark the payload.** One `PAYL` handling assertion if unencrypted; two, one per data
   state with the `unencrypted` one external, if encrypted (ICTDF-POL §5).
5. **Add other assertions.** Give each a legal scope for its container, mark it with
   `StatementMetadata`, and pair states if its statement is encrypted (ICTDF-MTD).
6. **Roll up.** Compute the object-scope marking as at least as restrictive as everything
   the object contains, including `ntk:Access`. Exclude the `unencrypted` markings of
   encrypted parts and the classifications of linked resources.
7. **Emit the object-scope handling assertion first**, containing an EDH whose ARH security
   block bears `@ism:resourceElement="true"`.
8. **Bind, if required.** For each assertion needing authenticity, compute the coverage set
   from its scope, normalize in document order, sign, and emit
   `Signer → SignatureValue → …` with the algorithm, normalization method, and
   `@includesStatementMetadata` (ICTDF-BND §4).
9. **Serialize.** One XML document, `@tdf:version` on the root, namespaces declared once,
   no gratuitous whitespace in signed regions (ICTDF-PKG).
10. **Validate before release.** Run ICTDF-VAL against the object you are about to emit. A
    producer that emits without validating ships rollup errors.

## 4. Consuming an object

1. **Parse defensively.** Entities off, parser limits on, nothing dereferenced
   (ICTDF-SEC §1).
2. **Validate.** Run the ICTDF-VAL procedure in full, including Step 2 over extension-point
   content. Fail closed.
3. **Read the object marking.** The first handling assertion is the rolled-up marking. It is
   the correct input to a whole-object release decision, and it is available without
   parsing further.
4. **Verify bindings, if authenticity is needed.** Reject unacceptable algorithms and
   normalization methods first, recompute coverage from scope independently of the
   document, verify, then resolve the signer through trusted configuration
   (ICTDF-BND §4).
5. **Treat uncovered content as unauthenticated.** Content outside a verified binding's
   coverage set has no integrity guarantee, even inside the same TDO.
6. **Authorize.** Evaluate markings against the requester through a decision function
   outside this suite. Presence of a marking is not authority; a key access descriptor is
   not authorization (ICTDF-KAS §4).
7. **Recover keys.** Resolve `RemoteStoredKey` through trusted configuration, unwrap layer
   by layer from the highest `@sequenceNum` down, and report every failure as one opaque
   class (ICTDF-KAO §5).
8. **Decrypt and authenticate.** Verify the authentication tag, or a binding covering the
   payload, before treating plaintext as complete. There is no segmentation, so the unit of
   authentication is the whole payload.
9. **Resolve references only if policy allows.** After validation, through a catalog, with
   bounded redirects and size, and with no trust inferred from the URI (ICTDF-LOC §4).

## 5. Extracting from a collection

Extraction produces a new object and is not a copy.

1. Take the TDO or nested TDC out of its collection.
2. Carry transitive assertions with it and rewrite their scope: `DESC_TDO` becomes `TDO`
   and `DESC_PAYL` becomes `PAYL` when the result is a TDO; both are unchanged when the
   result is a TDC. Non-transitive assertions — `TDC` and `TDC_MEMBER` — are not carried
   (ICTDF-SCP §4).
3. Copy in the dependent-specification version declarations the content inherited from the
   enclosing TDF (ICTDF-MTD §5.1).
4. Recompute rollup for the extracted object.
5. Discard bindings whose coverage no longer matches. A rewritten scope changes the
   coverage set, so any signature over it is invalid. Re-sign or emit unsigned.
6. Set `@tdf:version` on the new root and validate the result.

## 6. Conformance

A **conforming producer** emits documents that pass ICTDF-VAL §4 or §5 in full, obeys the
MUST NOT requirements in ICTDF-SEC, and does not emit reserved structures (ICTDF-SCH §5) or
deprecated algorithms (ICTDF-ALG §1).

A **conforming consumer** runs the ICTDF-VAL procedure including Step 2, fails closed on
any step it cannot run, verifies bindings against an explicit allow-list before acting on
covered content, and treats markings as descriptions rather than authorizations.

A **conforming validator** implements ICTDF-VAL §§3–7 and reports its rule set version,
schema catalog, and which steps ran (ICTDF-VAL §9).

An implementation that validates the schema alone is not conforming. The schema cannot
express scope legality, rollup, state pairing, sequence continuity, or version consistency;
those live in the constraint rules and in the multi-pass procedure.

## 7. Deliberate absences

IC-TDF does not define:

| Absent | Consequence |
|---|---|
| Segmentation and per-segment integrity | The whole payload is the unit of authentication; no verified prefix release |
| A key access protocol | `RemoteStoredKey` carries a URI and a protocol name only (ICTDF-KAS §1) |
| A policy language | `EncryptedPolicyObject` is opaque; markings come from ISM and NTK |
| An algorithm registry | `EncryptionMethod/@algorithm` is an unconstrained URI |
| Content hashes for referenced content | A reference is authenticated; its referent is not (ICTDF-LOC §5) |
| Explicit binding coverage | `BoundValueList` and `EXPLICIT` scope are reserved (ICTDF-BND §6) |

These are format boundaries. A deployment needing any of them composes IC-TDF with an
external specification and states the composition explicitly.

## References

- [RFC 2119](https://www.rfc-editor.org/info/rfc2119) — Key words for use in RFCs
- [RFC 8174](https://www.rfc-editor.org/info/rfc8174) — Ambiguity of uppercase vs lowercase
- [RFC 5280](https://www.rfc-editor.org/info/rfc5280) — X.509 certificate and CRL profile
- [RFC 3986](https://www.rfc-editor.org/info/rfc3986) — Uniform Resource Identifier
- [RFC 6838](https://www.rfc-editor.org/info/rfc6838) — Media type specifications
- [XML 1.0](https://www.w3.org/TR/xml/) — Extensible Markup Language
- [XML Namespaces](https://www.w3.org/TR/xml-names/) — Namespaces in XML
- [XML Schema Part 1](https://www.w3.org/TR/xmlschema11-1/) and
  [Part 2](https://www.w3.org/TR/xmlschema11-2/) — Structures and datatypes
- [Canonical XML 1.0](https://www.w3.org/TR/2001/REC-xml-c14n-20010315) and
  [1.1](https://www.w3.org/TR/xml-c14n11/)
- [Exclusive XML Canonicalization 1.0](https://www.w3.org/TR/xml-exc-c14n/)
- [XML Encryption Syntax and Processing](https://www.w3.org/TR/xmlenc-core1/)
- [ISO/IEC 19757-3](https://www.iso.org/standard/55982.html) — Schematron
- [XSLT 2.0](https://www.w3.org/TR/xslt20/) and [XPath 2.0](https://www.w3.org/TR/xpath20/)
