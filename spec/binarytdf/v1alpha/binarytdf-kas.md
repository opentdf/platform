# BinaryTDF-KAS: Key Access Service Rewrap Protocol

| | |
|---|---|
| Document | BinaryTDF-KAS |
| Version | 1 Alpha |
| Source draft | 0.2 |
| Frame version | 2 |
| Status | Draft |
| Depends on | BinaryTDF-SEC, BinaryTDF-ALG, BinaryTDF-MTD, BinaryTDF-POL, BinaryTDF-REC, BinaryTDF-KAO |
| Referenced by | BinaryTDF-SCH, BinaryTDF-CORE, BinaryTDF-KEY-EPOCH |

## 1. Request

A request carries:

- `session_suite`, a supported wrap-suite identifier used only for the response;
- `session_recipient_key`, encoded for that suite;
- exact Protected Metadata and Object Key Recovery CBOR bytes;
- the outer frame version; and
- correlation IDs and zero-based KAO paths.

For ECDH, the session recipient key is the opener's ephemeral public key. For ML-KEM,
it is the opener's ML-KEM-768 or ML-KEM-1024 encapsulation key with suite-fixed size.

## 2. Authority processing

For each distinct KAO path, the authority MUST:

1. strictly parse deterministic metadata and recovery bytes;
2. resolve `authority_id` through trusted configuration and reject KAOs not assigned
   to it;
3. reject invalid paths, structures, extensions, suites, keys, and encodings;
4. derive KAO context, recover `kao_value`, and verify policy binding;
5. authorize the authenticated caller against Canonical Policy; and
6. establish a session shared secret and wrap `kao_value` to the opener.

Key material MUST NOT be returned before authorization. Per-item failures MUST NOT
prevent independent items from receiving results.

## 3. Response

The response carries `session_suite`, suite-specific `encapsulation`, and
`wrapped_key_material`.

- For ECDH, encapsulation is the authority's ephemeral public key.
- For ML-KEM, encapsulation is the ciphertext produced for the opener: 1088 bytes for
  ML-KEM-768 or 1568 bytes for ML-KEM-1024.

The session context is:

```text
session_context = encode_deterministic_cbor({
  1: frame_version,
  2: SHA-256(metadata_bytes),
  3: SHA-256(object_key_recovery_bytes),
  4: kao_path,
  5: session_suite,
  6: SHA-256(response_encapsulation)
})
```

The authority derives `session_kek` with HKDF-SHA256 using the session shared secret,
the salt `binary-tdf:v2:hkdf-salt`, and:

```text
UTF8("binary-tdf:v2:rewrap-kek") || session_context
```

It encrypts `kao_value` with AES-256-GCM, a fresh 12-byte nonce, and
`session_context` as AAD.

## 4. Opener processing

The opener validates every response against its requested path.

- DIRECT returns the object key.
- XOR_ALL accepts at most one authenticated share per group, requires every group,
  and XORs shares locally. The authority does not reconstruct the object key.
- A registered recovery extension defines its returned values and reconstruction.

ML-KEM session suites use FIPS 203 implicit rejection and indistinguishable failure.
Invalid response encapsulation fails wrapped-key authentication and is reported as
generic key-recovery failure.

## 5. Failure classes

| Error | Meaning |
|---|---|
| `UNSUPPORTED_FORMAT` | unsupported frame version |
| `UNSUPPORTED_CAPABILITY` | unsupported suite, scheme, or critical extension |
| `MALFORMED_CBOR` | invalid deterministic CBOR, path, recovery structure, or encoding |
| `UNSUPPORTED_FIELD` | unregistered core key |
| `KEY_RECOVERY_FAILED` | ECDH, decapsulation, authentication, context, or policy-binding failure |
| `ENTITLEMENT_DENIED` | authorization denied release |

ECDH, ML-KEM, authentication, context, and policy-binding failures MUST be
indistinguishable through this single error class. Payload authentication failure is
local to the opener after rewrap.

## 6. CDDL

The rewrap protocol's transport schema is implementation-specific, but session context
is byte-exact:

```cddl
session-context = {
  1 => uint,
  2 => bstr .size 32,
  3 => bstr .size 32,
  4 => kao-path,
  5 => wrap-suite,
  6 => bstr .size 32
}
```
