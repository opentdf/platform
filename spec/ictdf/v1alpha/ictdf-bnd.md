# ICTDF-BND: Cryptographic Binding

| | |
|---|---|
| Document | ICTDF-BND |
| Version | 1 Alpha |
| Source spec | IC-TDF.XML.V2014-DEC-r2017-JUL |
| TDF version | 201412.201707 |
| Status | Draft |
| Depends on | ICTDF-SEC, ICTDF-ALG, ICTDF-MTD, ICTDF-SCP |
| Referenced by | ICTDF-PKG, ICTDF-VAL, ICTDF-CORE, ICTDF-OPENTDF |

## 1. Structure

A binding attaches a signature to an assertion. Either kind of assertion may carry one.

```text
Binding                                   1..unbounded
  Signer
    @subject    optional, RFC 5280 distinguished name
    @issuer     optional, RFC 5280 distinguished name
    @serial     optional
  SignatureValue                          1
    base64Binary
    @signatureAlgorithm                required, CVEnumTDFSignatureAlgorithm
    @normalizationMethod               required, xs:anyURI
    @includesStatementMetadata         conditional, xs:boolean
  BoundValueList                          0..1
```

The alternative to `Binding` is `ReferenceList`, which is reserved and not permitted in
this version (§6).

Multiple `Binding` elements on one assertion are independent signatures over the same
coverage. Each carries its own signer, algorithm, and normalization method. A verifier MUST
treat them as separate claims and MUST NOT combine them; a deployment requiring more than
one valid signature states that requirement itself.

`Signer` MUST specify `@issuer` and at least one of `@serial` or `@subject`
(`IC-TDF-ID-00038`). It identifies a certificate; it does not contain one. Resolution and
path validation are deployment responsibilities (ICTDF-SEC §2).

## 2. What a signature covers

A `SignatureValue` is computed over the concatenation, **in document order**, of the
normalized form of each element the assertion's scope covers. The scope of the assertion
carrying the binding determines that set; the binding itself does not enumerate it.

```text
signed-bytes = normalize(e₁) ‖ normalize(e₂) ‖ … ‖ normalize(eₙ)
```

where `e₁ … eₙ` are the covered elements in document order and `normalize` is the method
named by `@normalizationMethod` (ICTDF-ALG §2).

Coverage follows the scope semantics of ICTDF-SCP. The tables below restate the shape of
each scope's coverage; the source DES Table 2 and Table 3 give the exact XPath enumeration
and are authoritative where the two differ.

### 2.1 Bindings inside a TDO

| Scope | Covered, in document order |
|---|---|
| `PAYL` | The assertion's own statement; its `StatementMetadata` if and only if `@includesStatementMetadata="true"`; the sibling `Payload` |
| `TDO` | Every `HandlingStatement` in the TDO; every assertion statement; every `StatementMetadata` for which `@includesStatementMetadata="true"`; the `Payload` |

A `TDO`-scope binding covers everything in the TDO except the binding elements themselves.
A `PAYL`-scope binding covers the payload and the assertion that describes it, and nothing
else — in particular it does not cover the object's handling assertion.

### 2.2 Bindings inside a TDC

| Scope | Covered, in document order |
|---|---|
| `TDC` | The collection's own handling and assertion statements and their qualifying `StatementMetadata`, plus, recursively for every descendant `TrustedDataObject`, its handling statements, assertion statements, qualifying `StatementMetadata`, and `Payload`, and for every descendant `TrustedDataCollection`, its handling statements, assertion statements, and qualifying `StatementMetadata` |
| `TDC_MEMBER` | The assertion's own statement and qualifying `StatementMetadata`, plus the same per-member content as `TDC` for each collection member, excluding the collection's peer assertions |
| `DESC_TDO` | The assertion's own statement and qualifying `StatementMetadata`, plus the same per-descendant content as `TDC` for every descendant TDO |
| `DESC_PAYL` | The assertion's own statement; its `StatementMetadata` if and only if `@includesStatementMetadata="true"`; the `Payload` of every descendant TDO |

A `TDC`-scope binding is expensive: it covers the whole collection transitively, so adding
or removing any member invalidates it. `TDC_MEMBER` and `DESC_TDO` bindings survive changes
to the collection's own assertions but not to its membership.

## 3. Statement metadata inclusion

`@includesStatementMetadata` decides whether `StatementMetadata` elements are inside the
signature. It is not optional in practice:

| `BoundValueList` | `SignatureValue/@includesStatementMetadata` | Rule |
|---|---|---|
| absent | MUST be specified | `IC-TDF-ID-00010` |
| present | MUST NOT be specified | `IC-TDF-ID-00009` |

When a `BoundValueList` is present the per-value attribute governs instead, so a
signature-level declaration would be ambiguous. When it is absent, an unspecified value
would leave coverage undefined; a verifier MUST reject such a document rather than
assuming `false`.

The attribute applies uniformly across the coverage set. A signature cannot include the
statement metadata of one covered assertion and exclude another's.

## 4. Producing and verifying

Producing a binding:

1. Determine the coverage set from the assertion's scope and the containing TDO or TDC.
2. Order it by document order.
3. Normalize each covered element with the chosen method, without re-serializing anything
   else.
4. Concatenate the normalized octets.
5. Sign with the chosen algorithm.
6. Emit `Signer`, then `SignatureValue` carrying the base64 signature, the algorithm, the
   normalization method, and `@includesStatementMetadata`.

Verifying:

1. Reject the document if `@signatureAlgorithm` or `@normalizationMethod` is outside the
   verifier's allow-list, before any parsing work that depends on them.
2. Reject `SHA1with…` values.
3. Recompute the coverage set from the scope, independently of any hint in the document.
4. Recompute the concatenation and verify.
5. Resolve `Signer` to a certificate through trusted configuration; validate the path.
6. Treat content outside the coverage set as unauthenticated, even where it is inside the
   same TDO.

A signature that verifies proves only that the covered bytes are as the signer produced
them. It does not prove the marking is correct, that the signer was authorized to make it,
or that content outside the coverage set is intact.

## 5. Normalization and fragment context

Normalization operates on element fragments taken out of their document. Whether ancestor
namespace declarations, `xml:base`, `xml:lang`, and the dependent-specification version
attributes travel with a fragment depends on the method chosen.

- An inclusive method (Canonical XML 1.0 or 1.1) carries inherited namespace declarations
  into each fragment, so the signed bytes include context the fragment did not declare.
- An exclusive method carries only the namespaces the fragment visibly uses. Because
  IC-TDF fragments inherit version declarations from the enclosing TDF (ICTDF-MTD §5.1),
  a deployment choosing an exclusive method MUST state how those declarations enter the
  signed bytes, or accept that they are unauthenticated.

Producer and verifier MUST use the same method and the same fragment boundaries. The
declared URI is the whole of the agreement between them, so an implementation MUST NOT
apply local adjustments — whitespace trimming, attribute reordering, prefix rewriting — on
either side.

## 6. Reserved: bound value lists and reference lists

Two structures are defined in the schema and disallowed in this version.

```text
BoundValueList
  BoundValue                     base64Binary
    @idRef                       required, xs:IDREF
    @hashAlgorithm               required, CVEnumTDFHashAlgorithm
    @normalizationMethod         required, xs:anyURI
    @includesStatementMetadata   optional, xs:boolean

ReferenceList
  Reference
    @idRef                       required, xs:IDREF
    @includesStatementMetadata   optional, xs:boolean
```

`BoundValueList` would let a signature enumerate exactly what it covers: each `BoundValue`
holds the hash of one referenced element, and the `SignatureValue` would then be computed
over the normalized `BoundValueList` rather than over the referenced content directly. That
indirection makes coverage explicit and lets a verifier check a subset without normalizing
the whole object.

`ReferenceList` is the unhashed form, enumerating covered elements without committing to
their content.

Both are reserved (`IC-TDF-ID-00013`), as is the `EXPLICIT` scope that would use them
(`IC-TDF-ID-00008`, `IC-TDF-ID-00012`). Where a `BoundValue` or `Reference` does appear,
its `@idRef` MUST resolve to a descendant of the same TDO (`IC-TDF-ID-00011`); a validator
MUST enforce that itself, because XML ID uniqueness alone permits cross-TDO references
inside a collection.

Producers MUST NOT emit either structure. Consumers MUST reject them.
