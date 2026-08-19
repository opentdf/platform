# ICTDF-SCH: Schema, Vocabularies, and Constraint Rules

| | |
|---|---|
| Document | ICTDF-SCH |
| Version | 1 Alpha |
| Source spec | IC-TDF.XML.V2014-DEC-r2017-JUL |
| TDF version | 201412.201707 |
| Status | Draft |
| Depends on | ICTDF-ALG, ICTDF-PKG |
| Referenced by | ICTDF-VAL, ICTDF-CORE |

## 1. Normative artifacts

| Artifact | Form | Normative |
|---|---|---|
| `IC-TDF.xsd` | W3C XML Schema | Yes |
| `CVEnumTDFAppliesToState`, `CVEnumTDFHashAlgorithm`, `CVEnumTDFSignatureAlgorithm` | CVE XML values | Yes |
| Generated CVE schemas | W3C XML Schema | Yes |
| `IC-TDF_XML.sch` | Schematron | Yes |
| `Lib/CompareVersionsInSkeleton.sch` | Schematron abstract patterns | Yes |
| Data encoding specification prose | PDF, Markdown | Informative |
| Schema guide | HTML | Informative |
| CVE renderings | PDF | Informative |

Where prose and artifact disagree, the artifact governs. Where this suite and the source
package disagree, the source package governs.

## 2. Schema

The schema declares two global elements, `TrustedDataObject` and `TrustedDataCollection`,
and the global attributes listed in ICTDF-ALG §5. It imports IC-EDH, ARH, Revision Recall,
and the three generated CVE schemas.

What the schema does check:

- element and attribute names, cardinality, and sequence order;
- simple types, including the `@tdf:version` and `@tdf:mediaType` patterns; and
- CVE membership for `@appliesToState`, `@hashAlgorithm`, and `@signatureAlgorithm`.

What the schema cannot check, and Schematron therefore must:

- scope legality by container and the required handling assertions;
- agreement between `@isEncrypted` and `EncryptionInformation`;
- data-state pairing for encrypted parts;
- `@sequenceNum` continuity;
- `@idRef` targets within the correct TDO;
- version floors and version consistency across a skeleton; and
- rollup of `ntk:Access`.

What nothing checks in this suite: the content of `StructuredPayload` and
`StructuredStatement`, which are `processContents="skip"`. ICTDF-VAL Step 2 validates that
content against its own governing schema.

## 3. Constraint rules

Rules are Schematron, using the XSLT 2.0 query language binding. The Jelliffe reference
implementation defines the normative behavior where an implementation's interpretation of
the rule set could differ.

Identifiers are `IC-TDF-ID-` followed by five digits, allocated by classification of the
rule's own text:

| Range | Classification of the rule |
|---|---|
| 00001–09999 | Unclassified |
| 10001–19999 | FOUO |
| 20001–20999 | S//REL FVEY |
| 21001–21999 | S//NF |
| 22001–29999 | S//TBD |
| 30001 and above | Other |

Every rule in this version is in the unclassified range. Severity is Error or Warning;
`IC-TDF-ID-00054` is the only Warning.

Rules are living: a rule may be added, changed, or removed in a revision without a
namespace change. A validator MUST NOT validate a document against a rule set from an older
integer version of the specification, and MAY validate against a newer one.

Constraint rules are of two types. Data validation rules constrain instance content and are
what this module catalogs. Data rendering rules would constrain presentation; there are
none in this version.

## 4. Rule catalog

Forty-nine rules are active. Identifiers 00020 through 00024 were removed in a prior
revision and 00029 is unallocated; the gaps are permanent.

### 4.1 General

| ID | Requirement |
|---|---|
| 00001 | Every attribute in the TDF namespace contains at least one non-whitespace character |
| 00002 | A root `TrustedDataObject` specifies `@tdf:version` |
| 00054 | `@tdf:version` SHOULD be `201412.201707`, optionally with a customization suffix — Warning |

### 4.2 Required handling assertions

| ID | Requirement |
|---|---|
| 00003 | A TDO has at least one handling assertion with `@scope="PAYL"` |
| 00004 | A TDO has exactly one handling assertion with `@scope="TDO"` containing an EDH |
| 00005 | A TDC has exactly one handling assertion with `@scope="TDC"` containing an EDH |
| 00016 | The `TDO`-scope EDH handling assertion contains an ARH security block with `@ism:resourceElement="true"` |
| 00017 | The same for the `TDC`-scope handling assertion |
| 00018 | A `TDO`-scope handling assertion does not use `edh:ExternalEdh` |
| 00019 | A `TDC`-scope handling assertion does not use `edh:ExternalEdh` |
| 00035 | Handling assertions in a TDC use only `@scope="TDC"` |
| 00042 | The first handling assertion in document order has `@scope="TDO"` or `"TDC"` and contains an EDH |
| 00055 | A non-encrypted payload has at most one `PAYL` handling assertion containing an EDH |
| 00043 | `ntk:Access` is rolled up into the `TDO`-scope handling assertion |
| 00044 | `ntk:Access` is rolled up into the `TDC`-scope handling assertion |

### 4.3 Scope

| ID | Requirement |
|---|---|
| 00006 | Assertions in a TDO use only `PAYL`, `TDO`, or `EXPLICIT` scope |
| 00007 | Assertions in a TDC use only `TDC`, `DESC_PAYL`, `DESC_TDO`, `TDC_MEMBER`, or `EXPLICIT` scope |
| 00008 | `EXPLICIT` scope is not permitted in this version |
| 00012 | An `EXPLICIT`-scope assertion requires a `BoundValueList` or a `ReferenceList` |

### 4.4 Binding

| ID | Requirement |
|---|---|
| 00009 | When a `BoundValueList` is present, `SignatureValue` does not specify `@includesStatementMetadata` |
| 00010 | When a `BoundValueList` is absent, `SignatureValue` specifies `@includesStatementMetadata` |
| 00011 | A `BoundValue` or `Reference` `@idRef` resolves to a descendant of the same TDO |
| 00013 | `ReferenceList` and `BoundValueList` are not permitted in this version |
| 00038 | Every `Signer` specifies `@issuer` and at least one of `@serial` or `@subject` |

### 4.5 Encryption

| ID | Requirement |
|---|---|
| 00014 | `EncryptionInformation` requires the described data to be labeled encrypted |
| 00015 | Data labeled encrypted requires `EncryptionInformation` |
| 00040 | More than one `EncryptionInformation` on a part requires `@tdf:sequenceNum` on each |
| 00041 | Sequence numbers start at 1, increment by 1, and contain no duplicates |

### 4.6 Data state

| ID | Requirement |
|---|---|
| 00025 | `@appliesToState` appears only where the payload has `@tdf:isEncrypted="true"` |
| 00026 | An encrypted payload has two `PAYL` handling assertions, one `encrypted` and one `unencrypted` |
| 00027 | The `unencrypted` `PAYL` handling assertion contains `edh:ExternalEdh` |
| 00028 | Where the payload is encrypted and not external, the `encrypted` handling assertion contains a regular `edh:Edh` |
| 00030 | The `unencrypted` `StatementMetadata` of an encrypted statement contains `arh:ExternalSecurity` |
| 00031 | An encrypted statement has two `StatementMetadata` elements, one `encrypted` and one `unencrypted` |
| 00032 | `@appliesToState` on `StatementMetadata` appears only where the statement has `@tdf:isEncrypted="true"` |
| 00039 | `@appliesToState` on a handling assertion appears only at `PAYL` scope |

### 4.7 External content

| ID | Requirement |
|---|---|
| 00033 | A TDO with a `ReferenceValuePayload` carries `edh:ExternalEdh` in its `PAYL` handling assertion |
| 00034 | An assertion with a `ReferenceStatement` carries `edh:ExternalEdh` or `arh:ExternalSecurity` in `StatementMetadata` |

### 4.8 Versions

| ID | Requirement |
|---|---|
| 00036 | `@edh:DESVersion` is at least 1 |
| 00037 | `@arh:DESVersion` is at least 1 |
| 00045 | `@revrecall:DESVersion` is at least 201412 |
| 00046 | A single `ism` version across the TDF skeleton |
| 00047 | A single `ntk` version across the TDF skeleton |
| 00048 | A single `arh` version across the TDF skeleton |
| 00049 | A single `edh` version across the TDF skeleton |
| 00050 | A single `icid` version across the TDF skeleton |
| 00051 | A single `usagency` `@CESVersion` across the TDF skeleton |
| 00052 | A single `tdf` `@version` across the TDF skeleton |
| 00053 | A single `@ism:ISMCATCESVersion` across the TDF skeleton |

Rules 00046 through 00053 are expressed through the shared abstract pattern in
`Lib/CompareVersionsInSkeleton.sch`. "Skeleton" is defined in ICTDF-VAL §2: it is the TDF
with extension-point content removed, so a version declared inside embedded foreign content
does not participate.

## 5. Reserved rules

Four rules forbid structures the schema admits: 00008 and 00012 for `EXPLICIT` scope, and
00013 for `BoundValueList` and `ReferenceList`. They exist so that a future revision can
enable those features by changing rules rather than the schema, which would require a new
namespace.

A producer MUST NOT emit the reserved structures, and a consumer MUST reject them rather
than treating them as forward-compatible extensions (ICTDF-SCP §6, ICTDF-BND §6).

## 6. Running the rules

Validation is not a single Schematron pass over the document. ISM and NTK rules are not
TDO-aware and produce both false positives and false negatives when run across a whole TDF;
extension-point content must be validated in isolation. ICTDF-VAL defines the ordered
procedure, the fragments each rule set runs against, and the assembly of results.
