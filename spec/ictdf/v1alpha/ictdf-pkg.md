# ICTDF-PKG: XML Serialization and Document Order

| | |
|---|---|
| Document | ICTDF-PKG |
| Version | 1 Alpha |
| Source spec | IC-TDF.XML.V2014-DEC-r2017-JUL |
| TDF version | 201412.201707 |
| Status | Draft |
| Depends on | ICTDF-SEC, ICTDF-MTD, ICTDF-SCP, ICTDF-POL, ICTDF-BND, ICTDF-KAO, ICTDF-PAY, ICTDF-LOC |
| Referenced by | ICTDF-SCH, ICTDF-VAL, ICTDF-CORE |

## 1. Document form

An IC-TDF instance is a well-formed XML 1.0 document with exactly one root element, either
`tdf:TrustedDataObject` or `tdf:TrustedDataCollection`. There is no DTD, no XML Schema
instance requirement, and no external subset.

| Property | Value |
|---|---|
| Target namespace | `urn:us:gov:ic:tdf` |
| Element form | qualified |
| Attribute form | qualified |
| Media type | `application/dni-tdf+xml` |
| Character encoding | UTF-8 RECOMMENDED; the XML declaration governs |

Attributes are namespace-qualified, so IC-TDF attributes are written `tdf:scope`,
`tdf:version`, `tdf:isEncrypted`, and so on, including on IC-TDF's own elements.

`xsi:schemaLocation`, where present, is a hint only. A validator MUST resolve schemas from
a trusted local catalog and MUST ignore locations named in the instance (ICTDF-SEC §1).

## 2. Namespaces

| Prefix | Namespace |
|---|---|
| `tdf` | `urn:us:gov:ic:tdf` |
| `edh` | IC Enterprise Data Header |
| `arh` | Access Rights and Handling |
| `ism` | Information Security Marking |
| `ntk` | Need-To-Know Metadata |
| `revrecall` | Revision Recall |
| `usagency` | US Agency Acronyms |
| `icid` | IC Identifier |

Namespace URIs carry no version. Every dependent specification states its version through
an attribute, and those attributes must be consistent within a skeleton (ICTDF-VAL §6).
Prefixes are conventional; a document may bind any prefix to any namespace and a consumer
MUST resolve by namespace URI.

Namespace declarations are inherited. A fragment taken out of the document loses the
declarations it did not make itself, which is why extraction copies them in
(ICTDF-MTD §5.1) and why normalization method choice matters to bindings
(ICTDF-BND §5).

## 3. Document structure

```text
TrustedDataObject
  @tdf:version                            required on a root TDO
  @tdf:id                                 optional
  HandlingAssertion             1..*
  Assertion                     0..*
  EncryptionInformation         0..*
  <one payload>                 1

TrustedDataCollection
  @tdf:version                            required
  HandlingAssertion             1..*
  Assertion                     0..*
  ( TrustedDataCollection | TrustedDataObject )   1..*
```

A root `TrustedDataObject` MUST specify `@tdf:version` (`IC-TDF-ID-00002`); a nested one
inherits it. A `TrustedDataCollection` always specifies it. The value matches the pattern in
ICTDF-ALG §4 and SHOULD be `201412.201707` with an optional customization suffix
(`IC-TDF-ID-00054`).

Collections nest to arbitrary depth. A parser MUST bound that depth (ICTDF-SEC §1).

## 4. Document order

Order is not incidental in IC-TDF. Three separate mechanisms depend on it.

### 4.1 Schema-imposed order

Every content model in the schema is a sequence, not an all-group. Within an assertion:

```text
StatementMetadata* → EncryptionInformation* → statement → binding group?
```

Within a `Binding`:

```text
Signer → SignatureValue → BoundValueList?
```

Within a TDO or TDC, handling assertions precede ordinary assertions, and in a TDC the
member objects follow both.

### 4.2 Rule-imposed order

The first handling assertion in document order MUST be the `TDO`- or `TDC`-scope one, and
it MUST contain an EDH (`IC-TDF-ID-00042`). A guard can then read the object's rolled-up
marking from the head of the document without parsing the rest.

The ISM version governing structured content is the first `@ism:DESVersion` in document
order within that content (ICTDF-MTD §5.1).

### 4.3 Signature-imposed order

A `SignatureValue` covers the concatenation of covered elements **in document order**
(ICTDF-BND §2). Reordering elements that a signature covers invalidates it, even where the
schema would permit the new order.

The `Signer → SignatureValue → BoundValueList` order exists so a streaming parser can
verify in one pass. That is a performance property, not a security one: a verifier MUST NOT
act on content before the signature covering it verifies (ICTDF-SEC §3).

## 5. Byte-level stability

Signed content is bytes, not an information set. An implementation that round-trips a
document through a parser and serializer will not in general reproduce the original bytes,
and any binding over the changed region will fail.

- An intermediary MUST NOT re-serialize, reindent, reorder attributes, rewrite prefixes,
  normalize whitespace, strip comments, or change entity forms in a signed document.
- Re-encoding a document to a different character encoding changes the bytes.
- Where a transformation is unavoidable, the object is re-signed by a party authorized to
  do so, and the new signature reflects the new content.
- Normalization for signing is applied to the elements a binding covers, as declared by
  `@normalizationMethod`, and to nothing else. A producer MUST NOT canonicalize the whole
  document as a convenience.

## 6. Whitespace and empty content

Every attribute in the `urn:us:gov:ic:tdf` namespace MUST contain at least one
non-whitespace character (`IC-TDF-ID-00001`). This forecloses the empty-string values that
would otherwise satisfy `xs:string` and `xs:anyURI` attributes.

Whitespace between elements is insignificant to the schema and significant to
normalization. A producer SHOULD emit signed regions without gratuitous formatting
whitespace, because that whitespace becomes part of the signed bytes under an inclusive
canonicalization method.
