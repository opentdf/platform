# ICTDF-MTD: Assertions, Statements, and Statement Metadata

| | |
|---|---|
| Document | ICTDF-MTD |
| Version | 1 Alpha |
| Source spec | IC-TDF.XML.V2014-DEC-r2017-JUL |
| TDF version | 201412.201707 |
| Status | Draft |
| Depends on | ICTDF-SEC, ICTDF-ALG |
| Referenced by | ICTDF-SCP, ICTDF-POL, ICTDF-BND, ICTDF-PKG, ICTDF-VAL, ICTDF-CORE |

## 1. Two kinds of assertion

IC-TDF carries metadata in assertions. There are exactly two kinds, and they are distinct
element types rather than variants of one type.

| Element | Purpose | May be encrypted |
|---|---|---|
| `tdf:HandlingAssertion` | Dissemination controls that govern the object | No |
| `tdf:Assertion` | Any other metadata about the object | Yes |

Both appear in the assertion group at the head of a TDO or TDC:

```text
AssertionGroup
  HandlingAssertion   1..unbounded
  Assertion           0..unbounded
```

Handling assertions precede ordinary assertions in document order. ICTDF-POL governs
handling assertions; this module governs `tdf:Assertion` and the state model shared by
both.

## 2. Assertion structure

```text
Assertion
  StatementMetadata          0..2
  EncryptionInformation      0..unbounded
  <one statement>            1
  Binding | ReferenceList    0..1

  @scope    required
  @type     optional
  @id       optional
```

- `@scope` states which part of the object the assertion describes. Its values and
  semantics are in ICTDF-SCP.
- `@type` is an uncontrolled string naming the assertion's kind. It is producer-defined;
  a consumer MUST NOT derive security decisions from it.
- `@id` is `xs:ID` and is what a `BoundValue/@idRef` or `Reference/@idRef` points at.
- `EncryptionInformation` describes encryption applied to the statement. See ICTDF-KAO.
- The binding group is defined in ICTDF-BND.

Exactly one statement is present. The choice is:

| Element | Content | Extension point |
|---|---|---|
| `tdf:StringStatement` | `xs:string` | Yes |
| `tdf:Base64BinaryStatement` | `xs:base64Binary` | Yes |
| `tdf:StructuredStatement` | `xs:any` from another namespace, `processContents="skip"` | Yes |
| `tdf:ReferenceStatement` | Empty; `@uri` names the content | No |

`StringStatement`, `Base64BinaryStatement`, and `StructuredStatement` carry the same value
types as their payload counterparts; ICTDF-PAY §2 defines the shared attributes
`@filename`, `@mediaType`, and `@isEncrypted`.

## 3. Statement metadata

`StatementMetadata` describes the statement the way a handling assertion describes the
object. It carries exactly one of:

| Child | Use |
|---|---|
| `edh:Edh` | Enterprise data header for the statement |
| `edh:ExternalEdh` | Data header held outside this document |
| `arh:Security` | Access rights and handling security block |
| `arh:ExternalSecurity` | Security block held outside this document |

`StatementMetadata/@appliesToState` is the only place, besides `HandlingAssertion`, where
data state appears.

An assertion has zero, one, or two `StatementMetadata` elements. Two are permitted only in
the encrypted case described in §4.

An assertion whose statement is a `ReferenceStatement` MUST carry an `edh:ExternalEdh` or
`arh:ExternalSecurity` in `StatementMetadata` (`IC-TDF-ID-00034`), because the referenced
content is not present to be marked.

## 4. Data state

Encrypting a part of a TDO creates two things that need separate markings: the ciphertext
that travels in the clear, and the plaintext it protects. `@tdf:appliesToState` names
which of the two a marking describes.

```text
@tdf:appliesToState = "encrypted" | "unencrypted"
```

Rules:

- The attribute MAY appear only where the described part is actually encrypted. On a
  statement it requires `@tdf:isEncrypted="true"` on that statement (`IC-TDF-ID-00032`);
  on a payload handling assertion it requires `@tdf:isEncrypted="true"` on the payload
  (`IC-TDF-ID-00025`).
- On a handling assertion the attribute is permitted only when the scope is `PAYL`
  (`IC-TDF-ID-00039`). A TDO- or TDC-scope handling assertion has no state.
- An encrypted statement MUST have exactly two `StatementMetadata` elements, one
  `encrypted` and one `unencrypted` (`IC-TDF-ID-00031`).
- The `unencrypted` `StatementMetadata` MUST contain `arh:ExternalSecurity`
  (`IC-TDF-ID-00030`). The plaintext marking is deliberately external so that it does not
  raise the visible classification of the object that carries the ciphertext.
- An unencrypted statement carries at most one `StatementMetadata`, and that element MUST
  NOT specify `@appliesToState`.

The parallel requirements for encrypted payloads are in ICTDF-POL §5.

## 5. Extension points

Six elements are extension points — places where content governed by another
specification is embedded:

```text
tdf:StringStatement          tdf:StringPayload
tdf:Base64BinaryStatement    tdf:Base64BinaryPayload
tdf:StructuredStatement      tdf:StructuredPayload
```

`tdf:ReferenceStatement` and `tdf:ReferenceValuePayload` are not extension points; they
carry no content.

Extension point content:

- is not validated by the IC-TDF schema — `StructuredStatement` uses
  `processContents="skip"`;
- is validated in isolation, against its own governing schema and rules, by ICTDF-VAL
  Step 2; and
- MUST be treated as untrusted input until that step completes. See ICTDF-SEC §1.

### 5.1 Version declaration inheritance

Content at an extension point inherits the dependent-specification versions declared by
its enclosing TDF. It does not restate them, and the version-consistency rules
(`IC-TDF-ID-00046` through `IC-TDF-ID-00053`) require a single version per dependent
specification across the enclosing skeleton.

When such content is extracted from the TDF and processed on its own, the inherited
version declarations MUST be copied onto the extracted content. An extractor that omits
them produces a fragment whose marking semantics cannot be resolved.

The ISM version governing structured content is the first `@ism:DESVersion` in document
order within that content; if the content declares none, it inherits the enclosing TDF's.

## 6. Element ordering

Within an assertion, order is fixed by the schema and is significant:

```text
StatementMetadata* → EncryptionInformation* → statement → binding group?
```

Within a `Binding`, the order `Signer → SignatureValue → BoundValueList?` exists so that a
streaming parser can verify a signature in one pass over the document. A producer MUST
emit this order; a consumer MUST NOT act on unverified content merely because the order
permits early verification. See ICTDF-SEC §3.
