# ICTDF-ALG: Algorithms, Vocabularies, and Normalization

| | |
|---|---|
| Document | ICTDF-ALG |
| Version | 1 Alpha |
| Source spec | IC-TDF.XML.V2014-DEC-r2017-JUL |
| TDF version | 201412.201707 |
| Status | Draft |
| Depends on | ICTDF-SEC |
| Referenced by | ICTDF-MTD, ICTDF-BND, ICTDF-KAO, ICTDF-SCH, ICTDF-CORE |

## 1. Controlled vocabularies

IC-TDF defines three controlled vocabulary enumerations. Each is published as an XML CVE
document and as a generated XSD; the XML values are normative and the PDF renderings are
informative. A value outside the governing enumeration is a schema validation failure.

| Vocabulary | Namespace | Used by |
|---|---|---|
| `CVEnumTDFAppliesToState` | `urn:us:gov:ic:cvenum:tdf:state` | `@tdf:appliesToState` |
| `CVEnumTDFHashAlgorithm` | `urn:us:gov:ic:cvenum:tdf:hashalgorithm` | `BoundValue/@hashAlgorithm` |
| `CVEnumTDFSignatureAlgorithm` | `urn:us:gov:ic:cvenum:tdf:signaturealgorithm` | `SignatureValue/@signatureAlgorithm` |

### 1.1 Data state

| Value | Meaning |
|---|---|
| `encrypted` | The marking describes the part in its encrypted state |
| `unencrypted` | The marking describes the part in its decrypted state |

The enumeration is closed. ICTDF-MTD §4 defines when each value is required.

### 1.2 Hash algorithms

| Value | Status in this suite |
|---|---|
| `SHA1` | Permitted by the source CVE; MUST NOT be produced |
| `SHA256` | Recommended |
| `SHA384` | Permitted |
| `SHA512` | Permitted |

### 1.3 Signature algorithms

The signature CVE is pattern-based rather than an explicit value list. Four patterns are
defined:

```text
SHA(1|256|384|512)withRSA
SHA(1|256|384|512)withRSAand[A-Z]+[0-9]*
SHA(1|256|384|512)withECDSA
SHA(1|256|384|512)withECDSAand[A-Z]+[0-9]*
```

The `and…` variants name a mask generation or padding qualifier, for example
`SHA256withRSAandMGF1`. A verifier MUST match the declared value against its configured
allow-list rather than parsing the pattern to derive parameters, and MUST reject any
`SHA1with…` value.

Because the CVE is pattern-based, syntactically valid values naming algorithms the
verifier does not implement will occur. That is a rejection, not a fallback.

## 2. Normalization methods

`SignatureValue/@normalizationMethod` and `BoundValue/@normalizationMethod` are `xs:anyURI`
and are unconstrained by the schema. They identify the canonicalization applied before
hashing or signing. The source specification lists the following as sample values.

| URI | Method |
|---|---|
| `http://www.w3.org/TR/2001/REC-xml-c14n-20010315` | Canonical XML 1.0 |
| `http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments` | Canonical XML 1.0 with comments |
| `http://www.w3.org/2001/10/xml-exc-c14n#` | Exclusive XML Canonicalization 1.0 |
| `http://www.w3.org/2001/10/xml-exc-c14n#WithComments` | Exclusive XML Canonicalization 1.0 with comments |
| `http://www.w3.org/2006/12/xml-c14n11` | Canonical XML 1.1 |
| `http://www.w3.org/2006/12/xml-c14n11#WithComments` | Canonical XML 1.1 with comments |

Rules:

- The attribute is REQUIRED on every `SignatureValue` and every `BoundValue`. There is no
  default and none may be inferred.
- A producer MUST apply exactly the method it declares to every fragment covered by that
  signature or bound value.
- A verifier MUST reject a URI outside its allow-list before canonicalizing anything.
- Exclusive canonicalization does not carry inherited namespace declarations into the
  fragment. Because IC-TDF fragments rely on ancestor namespace and version declarations,
  a deployment choosing an exclusive method MUST state how those declarations are
  supplied. See ICTDF-BND §5.
- Comment handling changes the signed byte sequence. Producer and verifier MUST agree,
  and the declared URI is what they agree on.

## 3. Encryption algorithms

`EncryptionMethod/@algorithm` is `xs:anyURI` and is not drawn from an IC-TDF controlled
vocabulary. IC-TDF carries the identifier and its parameters; it does not register
algorithms. Deployments draw identifiers from XML Encryption or an equivalent registry
and MUST publish the set they accept.

The parameter children an algorithm requires are algorithm-specific. ICTDF-KAO §4
enumerates the available parameter elements and the consistency requirements over them.

## 4. Version identifiers

`@tdf:version` is a string matching:

```text
[0-9]{6}(\.[0-9]{6})?(\-.{1,23})?
```

which corresponds to `Year Month [ "." Revision ] [ "-" CustomizationSuffix ]`. The base
value for this suite is `201412.201707`: a December 2014 specification with a July 2017
revision. `IC-TDF-ID-00054` raises a warning when `@tdf:version` is not `201412.201707`
with an optional customization suffix.

Namespaces do not carry versions. Every dependent specification declares its version
through an attribute — `@ism:DESVersion`, `@ntk:DESVersion`, `@arh:DESVersion`,
`@edh:DESVersion`, `@icid:DESVersion`, `@revrecall:DESVersion`, `@usagency:CESVersion`,
and `@ism:ISMCATCESVersion`. ICTDF-VAL §6 defines the consistency rules over these.

## 5. Identifiers and references

| Attribute | Type | Notes |
|---|---|---|
| `@tdf:id` | `xs:ID` | Unique within the XML document, not merely within the TDO |
| `@tdf:idRef` | `xs:IDREF` | Must resolve to a descendant of the same TDO (`IC-TDF-ID-00011`) |
| `@tdf:filename` | `xs:string` | Advisory; unencrypted metadata |
| `@tdf:mediaType` | pattern `[a-zA-Z]*/[a-zA-Z+-.]*` | Weaker than RFC 6838; do not rely on it for validation |
| `@tdf:normalizationMethod` | `xs:anyURI` | See §2 |
| `@tdf:isEncrypted` | `xs:boolean` | Absence means `false` |
| `@tdf:includesStatementMetadata` | `xs:boolean` | See ICTDF-BND §3 |

Every attribute in the `urn:us:gov:ic:tdf` namespace MUST contain at least one
non-whitespace character (`IC-TDF-ID-00001`).

## 6. Media type

An IC-TDF document is labeled `application/dni-tdf+xml`. The type is not registered with
IANA. Deployments crossing an interface that requires a registered type MUST map it
explicitly rather than substituting `application/xml`, which discards the signal that the
document is a TDF.
