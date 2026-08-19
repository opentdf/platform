# ICTDF-VAL: Conformance Validation

| | |
|---|---|
| Document | ICTDF-VAL |
| Version | 1 Alpha |
| Source spec | IC-TDF.XML.V2014-DEC-r2017-JUL |
| TDF version | 201412.201707 |
| Status | Draft |
| Depends on | ICTDF-SEC, ICTDF-MTD, ICTDF-SCP, ICTDF-POL, ICTDF-BND, ICTDF-PKG, ICTDF-SCH |
| Referenced by | ICTDF-CORE, ICTDF-EX |

## 1. Why validation is multi-pass

A TDF carries content governed by other specifications. Those specifications' rule sets
were written for documents of their own kind and are not TDO-aware: run across a whole TDF
they compare markings that belong to different assertions, miss markings that belong
together, and reach into extension-point content that is not theirs to judge.

Validation therefore decomposes the document into fragments, runs each rule set against the
fragments it was written for, and assembles the results. Skipping the decomposition
produces both false positives and false negatives, and skipping the extension-point pass
accepts arbitrary foreign XML inside a conforming-looking object.

## 2. Fragments

| Term | Definition |
|---|---|
| **TDO structure** | The elements of a TDO in the TDF namespace, with their attributes |
| **Placeholder element** | An element with local name `PlaceHolderContent` in namespace `urn:placeholder`, substituted for removed content |
| **TDF skeleton** | The TDF with the content of every extension point replaced by a placeholder element |
| **TDO skeleton** | The skeleton of a single TDO |
| **TDC skeleton** | The skeleton of a collection, including its members' skeletons |
| **Resource element** | An element bearing `@ism:resourceElement="true"` |
| **TDO handling assertion** | The `TDO`-scope handling assertion |
| **TDC handling assertion** | The `TDC`-scope handling assertion |
| **Payload handling assertion** | A `PAYL`-scope handling assertion |
| **Assertion fragment** | One `tdf:Assertion` with its statement content |
| **Structured assertion fragment** | An assertion fragment whose statement is a `StructuredStatement` |
| **Payload fragment** | The payload with its describing handling assertion |
| **Structured payload fragment** | A payload fragment whose payload is a `StructuredPayload` |

Content kinds at an extension point are **binary**, **string**, or **structured**.
Structured content is XML from another namespace; binary and string content are opaque to
IC-TDF and are interpreted by whatever governs them.

The skeleton is what version-consistency rules operate over (ICTDF-SCH §4.8). Replacing
extension-point content with a placeholder is what keeps a version declared inside embedded
foreign content from participating in the enclosing document's consistency check.

## 3. Preconditions

Before Step 1, a validator MUST:

1. parse with external entity resolution and DTD loading disabled, and with the parser
   limits of ICTDF-SEC §1 in force;
2. resolve every schema from a trusted local catalog, ignoring `xsi:schemaLocation`; and
3. dereference nothing. No URI in the document is resolved during validation
   (ICTDF-LOC §4).

A validator MUST fail closed. An unresolvable schema, an unrunnable rule set, an
unrecognized CVE value, or an unsupported normalization method is a rejection.

## 4. Validating a TDO

**Step 1 — TDF rules over the whole TDO.**
Run the IC-TDF constraint rules. These are the TDO-aware and cross-assertion rules: scope
legality, required handling assertions, encryption agreement, data-state pairing, sequence
continuity, `@idRef` targets, and version floors. ISM and NTK rules MUST NOT be run in this
step.

**Step 2 — extension-point content in isolation.**
For each of the six extension points present, extract its content and validate it against
its own governing schema and rules, outside the TDF. The content inherits the enclosing
TDF's dependent-specification version declarations, which MUST be supplied to the
validation (ICTDF-MTD §5.1). The ISM version governing structured content is the first
`@ism:DESVersion` in document order within it, or the enclosing TDF's if it declares none.

**Step 3 — the TDO skeleton against ISM.**
Build the TDO skeleton and validate it against the ISM rule set. With extension-point
content replaced by placeholders, the ISM rules see only markings that belong to the TDO
itself.

**Step 4 — ISM consistency across the TDO.** Three checks:

- **4a** — assertions carrying resource-level portion markings are consistent with the
  object's markings;
- **4b** — a payload carrying a resource-level portion marking is consistent with its
  payload handling assertion; and
- **4c** — non-resource-level markings are consistent with the resource-level marking that
  governs them.

Step 4 is where rollup is checked: the object-scope marking must be at least as restrictive
as the interior it covers (ICTDF-POL §4).

## 5. Validating a TDC

**Step 1** — run the IC-TDF constraint rules over the collection.

**Step 2** — validate extension-point content in isolation, as in §4 Step 2.

**Step 3** — build the TDC skeleton and validate it against ISM.

**Step 4** — check ISM consistency across the collection, including that the TDC handling
assertion's markings roll up its members'.

**Step 5** — recursively validate each member. A member `TrustedDataObject` is validated by
§4; a member `TrustedDataCollection` by §5. Recursion terminates at the leaf TDOs.

Recursion is where transitive scope is resolved: an assertion at `DESC_TDO` or `DESC_PAYL`
scope applies at every depth, so each level's validation sees the assertions that reach it
(ICTDF-SCP §3).

## 6. Version consistency

Within a skeleton, each dependent specification appears at exactly one version:

| Namespace | Attribute | Rule |
|---|---|---|
| `ism` | `@ism:DESVersion` | `IC-TDF-ID-00046` |
| `ntk` | `@ntk:DESVersion` | `IC-TDF-ID-00047` |
| `arh` | `@arh:DESVersion` | `IC-TDF-ID-00048` |
| `edh` | `@edh:DESVersion` | `IC-TDF-ID-00049` |
| `icid` | `@icid:DESVersion` | `IC-TDF-ID-00050` |
| `usagency` | `@usagency:CESVersion` | `IC-TDF-ID-00051` |
| `tdf` | `@tdf:version` | `IC-TDF-ID-00052` |
| ISM CAT CES | `@ism:ISMCATCESVersion` | `IC-TDF-ID-00053` |

Mixed versions make marking semantics undecidable — two versions of ISM may assign
different meanings to the same marking, and nothing in the document says which applies.
These rules are not stylistic (ICTDF-SEC §6).

## 7. Revision handling

A validator MUST NOT validate a document against a rule set from an older integer version
of the specification than the document declares, and MAY validate against a newer one. An
older rule set does not know the constraints the document was built to satisfy and will
report spurious failures; a newer one is a superset of what the document was checked
against and reports genuine gaps.

Rules are living. A revision may add, change, or remove a rule without a namespace change,
so a validator's rule set version is an operational fact that MUST be recorded with a
validation result.

## 8. Binding verification

Binding verification is not part of schema or Schematron validation and is not implied by
a validation result.

A consumer that needs authenticity performs it separately, following ICTDF-BND §4, after
validation and before acting on any content. A document may be fully valid and carry no
binding at all, or carry a binding that verifies under an algorithm the consumer does not
accept.

## 9. Reporting

- A validation result names the rule set version, the schema catalog, and which steps ran.
- Errors and warnings are distinguished; `IC-TDF-ID-00054` is the only Warning in this
  version.
- A result that omits Step 2 is not a conformance result, because extension-point content
  was never checked. An implementation that cannot run Step 2 for a given content type MUST
  say so rather than report success.
- Validation output describes the document. It MUST NOT include recovered plaintext, key
  material, or the content of an `EncryptedPolicyObject`.
