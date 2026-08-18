# BinaryTDF-MTD: Protected Metadata

| | |
|---|---|
| Document | BinaryTDF-MTD |
| Version | 1 Alpha |
| Source draft | 0.2 |
| Frame version | 2 |
| Status | Draft |
| Depends on | BinaryTDF-SEC, BinaryTDF-ALG |
| Referenced by | BinaryTDF-KAO, BinaryTDF-PAY, BinaryTDF-KAS, BinaryTDF-SCH, BinaryTDF-CORE, BinaryTDF-NATO |

## 1. Structure

| Key | Field | Type | Required |
|---:|---|---|---|
| 1 | `content_encryption_suite` | `uint` | yes |
| 2 | `mime_type` | `tstr` | no |
| 3 | `application_data` | `bstr` | no |
| 4 | `metadata_extensions` | `[* metadata-extension]` | no |
| 5 | `critical_extensions` | `[* uint]` | no |

Protected Metadata provides two application-facing carriers:

- `application_data` contains opaque bytes that the core and authority do not
  interpret.
- `metadata_extensions` contains structured data governed by registered extension
  specifications.

Both are authenticated: their exact bytes are payload AAD and are hashed into every
KAO context. Neither becomes authorization policy merely by being present.

## 2. Metadata extensions

Each metadata extension is a CBOR-tagged data item. The globally registered CBOR tag
identifies a separately published, independently versioned extension specification;
the tagged value carries its data. An extension augments the CDDL socket:

```cddl
$binary-tdf-metadata-extension /= #6.12345(example-metadata)
```

A tag MUST appear at most once. Repeated values belong in an array within the tagged
value. For each item, a receiver MUST:

1. read its tag number;
2. validate a recognized tag against its exact schema and semantics;
3. reject an unrecognized tag listed in `critical_extensions` before requesting
   rewrap; and
4. preserve or ignore an unrecognized non-critical tag without treating it as policy.

The CDDL permits an unknown tagged value for forward-compatible transport. That
alternative MUST NOT accept a malformed value for a recognized tag.

`critical_extensions` is sorted and duplicate-free. Every listed tag MUST be present
in `metadata_extensions`. Criticality applies to processing the containing object.

An extension MUST NOT redefine framing, core keys, cryptographic inputs, capability
registries, recovery schemes, or failure behavior. Such changes require a core
mechanism or new frame version. BinaryTDF-ALG defines extension registration rules.

## 3. Signed and detached claims

AEAD proves that carried metadata belongs to the object as produced. It does not prove
that a claim is true or that a signer is trusted.

A signature inside Protected Metadata cannot sign the complete object containing it,
because ciphertext depends on the metadata bytes through payload AAD. Such a signature
binds only the content defined by its extension. An attestation over the complete
object MUST be detached and reference a hash of the exact object bytes.

A detached attestation can be removed without detection. An application requiring one
MUST identify the expected claim and trusted signer and reject the object if the
attestation is absent or invalid.

## 4. CDDL

```cddl
metadata-extension =
  $binary-tdf-metadata-extension /
  unknown-metadata-extension

unknown-metadata-extension = #6(any)

protected-metadata = {
  1 => content-encryption-suite,
  ? 2 => tstr,
  ? 3 => bstr,
  ? 4 => [* metadata-extension],
  ? 5 => [* uint]
}
```

`#6(any)` is any CBOR tag applied to any value. It exists only to transport an
unknown, non-critical tag. A recognized tag is governed by its registered schema.
