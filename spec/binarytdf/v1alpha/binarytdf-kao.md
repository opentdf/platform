# BinaryTDF-KAO: Key Access Object and Wrapping

| | |
|---|---|
| Document | BinaryTDF-KAO |
| Version | 1 Alpha |
| Source draft | 0.2 |
| Frame version | 2 |
| Status | Draft |
| Depends on | BinaryTDF-CORE, BinaryTDF-ALG, BinaryTDF-POL, BinaryTDF-REC |
| Referenced by | BinaryTDF-KAS, BinaryTDF-CDDL, BinaryTDF-EX |

## 1. Structure

| Key | Field | Type | Required |
|---:|---|---|---|
| 1 | `authority_id` | `tstr` | yes |
| 2 | `kid` | `bstr` | no |
| 3 | `wrap_suite` | `uint` | yes |
| 4 | `encapsulation` | `bstr` | yes |
| 5 | `wrapped_key_material` | `bstr` | yes |
| 6 | `policy_binding` | `policy-binding` | yes |

`wrapped_key_material` encrypts the object key for DIRECT, a group share for XOR_ALL,
or the 32-byte value defined by another registered scheme.

`encapsulation` is suite-specific public material. For ECDH it is the producer's
ephemeral public key; for ML-KEM it is the KEM ciphertext. A new suite may change its
encoding and length but not this core meaning.

There is no generic parameter byte string. Every parameter, encoding, and required
length belongs to `wrap_suite`.

## 2. Authority identity

`authority_id` is a globally unique, stable absolute URI identifying the authority.
It is not a network location and MUST NOT be dereferenced. A consumer resolves it
through trusted local configuration. Producers SHOULD use an organization-controlled
identity URI or `urn:uuid`.

Trusted configuration maps authority identity to service endpoints and key metadata;
`kid` selects a key within the authority. That mapping may change without rewriting
the object.

Identifiers are compared as exact UTF-8 strings. Consumers MUST NOT apply URI
normalization. URI ownership provides uniqueness, not authorization or trust.

## 3. KAO context

The context is derived and not serialized separately:

| Key | Value |
|---:|---|
| 1 | exact `authority_id` |
| 2 | `kid`, if present |
| 3 | `wrap_suite` |
| 4 | outer frame version |
| 5 | SHA-256 of exact Protected Metadata bytes |
| 6 | SHA-256 of `encapsulation` |
| 7 | SHA-256 of deterministic policy bytes, or SHA-256 of empty bytes when absent |
| 8 | `recovery_scheme` |
| 9 | zero-based KAO path |

```text
kao_context_bytes = encode_deterministic_cbor(kao_context)
```

The recovery scheme defines path shape. The path prevents movement to another group or
alternative position. Context bytes are KDF input and AAD for wrapped key material.
Payload encryption separately authenticates the complete serialized recovery section.

Every field closes a substitution path: authority or key redirection, suite downgrade,
cross-version replay, metadata or policy substitution, encapsulation splicing,
recovery-scheme reinterpretation, and KAO relocation all cause unwrap failure.

## 4. Common wrapping

The producer obtains `shared_secret` using the selected suite:

- ECDH generates a fresh ephemeral key pair, performs ECDH with the recipient public
  key, and stores the compressed ephemeral public key in `encapsulation`.
- ML-KEM runs `ML-KEM.Encaps` with the recipient encapsulation key and stores the KEM
  ciphertext in `encapsulation`.

It derives:

```text
wrap_kek = HKDF-SHA256(
  ikm  = shared_secret,
  salt = UTF8("binary-tdf:v2:hkdf-salt"),
  info = UTF8("binary-tdf:v2:kao-kek") || kao_context_bytes,
  len  = 32
)
```

`kao_value` is the 32-byte object key, share, or registered scheme value. Encrypt it
with AES-256-GCM, a fresh 12-byte nonce, and `kao_context_bytes` as AAD:

```text
wrapped_key_material = nonce || encrypted_kao_value || tag
```

Recipient keys are distributed out of band and selected by `authority_id` and `kid`.
Implementations MUST validate suite, recipient key, encapsulation encoding, and exact
lengths before deriving or releasing material. ECDH implementations MUST validate
public points and reject an all-zero shared secret.

ML-KEM suites MUST use FIPS 203 `ML-KEM.Encaps` and `ML-KEM.Decaps`, including implicit
rejection. An invalid correct-length ciphertext produces the specified pseudorandom
shared secret and later fails wrapped-key authentication. Only `KEY_RECOVERY_FAILED`
may be returned; implicit-rejection state MUST NOT appear in errors, outputs, or logs.

## 5. Policy binding

```text
policy_bytes = encode_deterministic_cbor(effective_canonical_policy)
               or empty bytes for public policy

binding_key = HKDF-SHA256(
  ikm  = kao_value,
  salt = UTF8("binary-tdf:v2:hkdf-salt"),
  info = UTF8("binary-tdf:v2:policy-binding"),
  len  = 32
)

binding = HMAC-SHA256(binding_key, policy_bytes)
```

The authority MUST verify binding after unwrap and before authorization or release.
Every alternative KAO in one XOR_ALL group wraps the same share and has the same
binding. The check ensures that the plaintext policy being authorized is the one bound
to the recovered value.

## 6. CDDL

```cddl
authority-id = tstr

policy-binding = {
  1 => binding-algorithm,
  2 => bstr
}

key-access-object = {
  1 => authority-id,
  ? 2 => bstr,
  3 => wrap-suite,
  4 => bstr,
  5 => bstr,
  6 => policy-binding
}

kao-path = [1* uint]

kao-context = {
  1 => authority-id,
  ? 2 => bstr,
  3 => wrap-suite,
  4 => uint,
  5 => bstr .size 32,
  6 => bstr .size 32,
  7 => bstr .size 32,
  8 => recovery-scheme,
  9 => kao-path
}
```
