# ICTDF-PAY: Payload Carriage

| | |
|---|---|
| Document | ICTDF-PAY |
| Version | 1 Alpha |
| Source spec | IC-TDF.XML.V2014-DEC-r2017-JUL |
| TDF version | 201412.201707 |
| Status | Draft |
| Depends on | ICTDF-SEC, ICTDF-KAO, ICTDF-LOC |
| Referenced by | ICTDF-PKG, ICTDF-VAL, ICTDF-CORE, ICTDF-MIG |

## 1. One payload per object

A `TrustedDataObject` carries exactly one payload, chosen from four forms. A
`TrustedDataCollection` carries none; it carries member objects, each with its own.

| Element | Content | Value type |
|---|---|---|
| `tdf:StringPayload` | `xs:string` | `StringValueType` |
| `tdf:Base64BinaryPayload` | `xs:base64Binary` | `Base64BinaryValueType` |
| `tdf:StructuredPayload` | `xs:any` from another namespace, `processContents="skip"` | `StructuredValueType` |
| `tdf:ReferenceValuePayload` | empty; `@uri` names the content | `ReferenceValueType` |

Each payload element also carries `@tdf:id` of type `xs:ID`. The same four value types back
the statement elements in ICTDF-MTD §2, so the attribute semantics below apply to both.

## 2. Value type attributes

| Attribute | `StringValue` | `Base64BinaryValue` | `StructuredValue` | `ReferenceValue` |
|---|---|---|---|---|
| `@tdf:filename` | yes | yes | yes | — |
| `@tdf:mediaType` | — | yes | — | yes |
| `@tdf:isEncrypted` | yes | yes | yes | yes |
| `@uri` | — | — | — | required |

- `@tdf:filename` is advisory. It is unencrypted even when the payload is not, and a
  consumer MUST NOT use it as a filesystem path without sanitizing it — path traversal and
  device-name attacks apply.
- `@tdf:mediaType` matches the loose pattern `[a-zA-Z]*/[a-zA-Z+-.]*`, which is weaker than
  RFC 6838. It is a hint. A consumer MUST NOT dispatch a parser on it without sniffing or
  validating the content, and MUST NOT treat it as evidence of the content's structure.
- `@tdf:isEncrypted` is `xs:boolean` and defaults to `false` by absence. Its value MUST
  agree with the presence of `EncryptionInformation` (`IC-TDF-ID-00014`,
  `IC-TDF-ID-00015`).

`@filename` and `@mediaType` describe protected content while remaining in the clear. They
are part of the object's disclosure surface (ICTDF-SEC §5) and a producer encrypting a
payload SHOULD omit both unless they are needed and are themselves releasable at the
object's marking.

## 3. Payload forms

### 3.1 String payload

Text, carried as XML character data. XML 1.0 excludes most control characters, so raw
octets MUST NOT be forced into a `StringPayload`.

The schema permits `@tdf:isEncrypted="true"` on a `StringPayload`, and the source examples
use it. That is only well defined when the ciphertext has itself been text-encoded by the
producer. Ciphertext is octets, so a producer SHOULD use `Base64BinaryPayload` for an
encrypted payload and MUST NOT place raw ciphertext in a `StringPayload`.

### 3.2 Base64 binary payload

Arbitrary octets, base64-encoded. This is the form for ciphertext and for any non-text
content. A parser MUST bound the decoded length before allocating (ICTDF-SEC §1); the
encoded form is roughly a third larger than the octets it carries, and the document gives
no length hint.

### 3.3 Structured payload

XML from another namespace, embedded directly. The schema declares
`processContents="skip"`, so the IC-TDF validator checks nothing inside it.

- It is an extension point (ICTDF-MTD §5) and is validated in isolation by ICTDF-VAL
  Step 2 against its own governing schema.
- It inherits the enclosing TDF's dependent-specification version declarations, which MUST
  be copied in on extraction.
- The ISM version governing it is the first `@ism:DESVersion` in document order within it,
  or the enclosing TDF's if it declares none.
- Until Step 2 completes it is untrusted input, and it can declare any namespace, any
  depth, and any size the parser limits allow.

### 3.4 Reference value payload

The payload is not present; `@uri` names where it is.

- `@uri` is REQUIRED.
- The TDO MUST carry an `edh:ExternalEdh` in its `PAYL` handling assertion
  (`IC-TDF-ID-00033`), because content that is absent cannot be marked in place.
- The classification of referenced content does not raise the TDO's classification
  (ICTDF-POL §4). Inlining that content instead of referencing it does.
- Resolution is governed by ICTDF-LOC and never happens during validation.
- No binding can cover content that is not in the document. A `PAYL`-scope binding over a
  `ReferenceValuePayload` authenticates the reference, not the referent.

## 4. Encrypted payloads

An encrypted payload is ciphertext carried as `Base64BinaryPayload`, described by one or
more `EncryptionInformation` elements under the TDO (ICTDF-KAO), and marked twice — once
for the ciphertext and once for the plaintext (ICTDF-POL §5).

The full set of obligations:

| Obligation | Source |
|---|---|
| `@tdf:isEncrypted="true"` on the payload | `IC-TDF-ID-00015` |
| At least one `EncryptionInformation` under the TDO | `IC-TDF-ID-00015` |
| `@sequenceNum` on each when there is more than one, sequential from 1 | `IC-TDF-ID-00040`, `IC-TDF-ID-00041` |
| Exactly two `PAYL` handling assertions, `encrypted` and `unencrypted` | `IC-TDF-ID-00026` |
| The `unencrypted` one contains `edh:ExternalEdh` | `IC-TDF-ID-00027` |
| The `encrypted` one contains a regular `edh:Edh`, unless the payload is external | `IC-TDF-ID-00028` |

Integrity of the ciphertext comes from the encryption method's `AuthenticationTag`, from a
binding whose scope covers the payload, or from both. Where neither is present the payload
has no integrity protection at all, and a consumer SHOULD refuse it.

A consumer MUST authenticate before releasing plaintext. IC-TDF defines no segmentation and
no per-segment integrity, so there is no conforming way to release a verified prefix of a
payload: the unit of authentication is the whole payload.

## 5. Size and streaming

IC-TDF is a single XML document with the payload inline. There is no chunking, no length
prefix, and no external data reference other than `ReferenceValuePayload`.

Consequences a producer must weigh:

- A large payload becomes a large document, and base64 expansion applies.
- Signature verification requires normalizing the covered elements, including the payload,
  so it is not free at any size.
- A payload too large to carry inline is carried by reference (§3.4), which moves integrity
  and marking obligations outside the object.
