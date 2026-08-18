# BinaryTDF-NATO: NATO Metadata Interoperability Profile

| | |
|---|---|
| Document | BinaryTDF-NATO |
| Profile version | 0.1 |
| Source draft | 0.2 |
| Frame version | 2 |
| Status | Draft, optional |
| Depends on | BinaryTDF-SEC, BinaryTDF-MTD, BinaryTDF-POL, BinaryTDF-PAY, BinaryTDF-SCH, BinaryTDF-PKG |

This profile carries NATO confidentiality labels and metadata bindings without changing
BinaryTDF-PKG framing, BinaryTDF-SCH validation, or cryptography.

## 1. Purpose

BinaryTDF transports registered tagged metadata and authenticates exact bytes but
defines no label, claim, or signature format. NATO standards already define them:

- ADatP-4774 defines confidentiality labels; ADatP-4774.8 defines CBOR label and
  clearance encodings.
- ADatP-4778 defines metadata binding; ADatP-4778.8 defines the CBOR Binding Data
  Object, optionally protected by COSE signatures or MACs.
- ADatP-5636 defines NATO Core Metadata elements that a binding may carry.

This profile defines socket integration, embedded and detached binding limits, and an
explicit mapping to Canonical Policy. COSE choice, label semantics, signer trust, and
revocation remain governed by NATO standards and deployment profiles.

The referenced SRDs were informative drafts in the source specification.

## 2. Confidentiality labels

A producer embeds the tagged ADatP-4774.8 structure directly in
`metadata_extensions`:

```cddl
$binary-tdf-metadata-extension /= tagged-ncms-extension
$binary-tdf-metadata-extension /= tagged-confidentiality-label
```

Illustrative diagnostic notation using a provisional tag:

```text
42602({
  1: {-1: [43], 1: [1234, 1], 2: 0,
      3: [[2, [26, 1, 4, 2], [1, 2]], [2, [26, 1, 4, 3], [76]]],
      4: 1620210689, 10: 1685631296}
})
```

Carriage rules:

- BinaryTDF-PAY payload AAD and KAO context authenticate label bytes. Alteration,
  replacement, or injection invalidates decryption.
- BinaryTDF-SCH deterministic CBOR rules apply to carried bytes. Semantic validation
  remains governed by ADatP-4774.
- A label required before processing MUST be listed in `critical_extensions`; an
  unsupported receiver then fails before rewrap.
- A label describes data and grants no access by itself.

## 3. Metadata bindings

### 3.1 Embedded binding

A producer MAY embed a complete BDO:

```cddl
$binary-tdf-metadata-extension /= tagged-bdo
```

An embedded BDO may carry a label and ADatP-4778 signature for downstream provenance.
It cannot bind ciphertext or complete object bytes because ciphertext depends on the
metadata through payload AAD. Its `data-reference` therefore either:

- hashes plaintext before encryption; or
- is omitted, leaving the binding to cover metadata while payload AEAD binds carriage.

A plaintext hash may enable confirmation attacks for low-entropy payloads. Deployments
SHOULD omit it or use a salted-digest profile when that matters.

### 3.2 Detached binding

Attestations created after the object exists MUST NOT require rebuilding it. They travel
as detached BDOs:

- the BDO data-reference URI identifies the object in deployment terms; and
- its hash covers complete immutable BinaryTDF bytes from magic through ciphertext.

The hash SHOULD use a COSE-registered algorithm; SHA-256, COSE `-16`, is recommended.

Detached BDOs allow guards to validate required attestations, add their own, and
forward both without modifying the object. A workflow requiring one MUST identify the
claim and trusted signer and MUST fail closed if it is absent or invalid.

## 4. Mapping labels to policy

Labels describe data; Canonical Policy authorizes release. A deployment using labels
for release MUST publish a total deterministic mapping keyed by the governing
`security-policy-identifier`.

| Label element | Illustrative policy entry |
|---|---|
| classification `2` under OID `1.3.26.1.4` | `["example.com", "classification", ["confidential"]]` |
| releasability category `[2, [26,1,4,3], [76]]` | `["example.com", "rel-to", ["bra"]]` |

Deployments replace `example.com` with a controlled namespace.

- The producer applies mapping at creation and writes ordinary Canonical Policy. KAS
  authorizes only against that policy and does not parse labels.
- Mapping MUST be total for emitted labels; an unmapped value is a creation error.
- The label remains the authoritative marking and policy is its enforcement projection.
  A mismatch is a validation failure.

## 5. Tag assignments

Source drafts used provisional tags 42601 for BDO, 42602 for NCMS security metadata,
and 47740 for clearance. This profile does not fix them:

- implementations MUST use final assignments from the
  [IANA CBOR Tags registry](https://www.iana.org/assignments/cbor-tags/) for promulgated
  documents;
- provisional draft tags MUST be treated as Private Use behind deployment
  configuration and MUST NOT be emitted for interchange; and
- `critical_extensions` names the tag actually emitted.

A future compatible profile revision may pin final registrations.

## 6. Security

- Carriage is not clearance. AEAD does not prove label correctness, signer trust, or
  agreement between content and marking.
- Labels do not authorize. Only Canonical Policy and KAS authorization control release.
- Embedded bindings cannot prove a signature covers the exact BinaryTDF; workflows
  requiring that property MUST use detached bindings over the complete object bytes.
- Plaintext hashes are stable payload identifiers and should be treated as sensitive
  metadata.
- A receiver without this profile MUST reject an object whose required label tag is
  listed in `critical_extensions`; making a required label non-critical defeats
  fail-closed marking.
- Detached attestations are removable and MUST be required by relying applications.
