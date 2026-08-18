# BinaryTDF-SCH: Deterministic CBOR Schema

| | |
|---|---|
| Document | BinaryTDF-SCH |
| Version | 1 Alpha |
| Source draft | 0.2 |
| Frame version | 2 |
| Status | Draft |
| Depends on | BinaryTDF-ALG, BinaryTDF-MTD, BinaryTDF-POL, BinaryTDF-REC, BinaryTDF-KAO, BinaryTDF-KAS |
| Referenced by | BinaryTDF-PKG, BinaryTDF-CORE, BinaryTDF-EX, BinaryTDF extensions |

## 1. Deterministic CBOR

All CBOR MUST use RFC 8949 Core Deterministic Encoding Requirements. Encoders MUST use
preferred serialization, deterministic map-key ordering, and definite-length items.
Optional fields with absent, empty, or zero values are omitted unless specified
otherwise.

Decoders MUST reject duplicate map keys, indefinite-length items, non-deterministic
encodings, invalid types, unregistered core keys, and resource-limit violations.
Implementations MUST impose finite limits on nesting, collection sizes, and section
lengths.

Core maps use unsigned integer keys. Registry identifiers are unsigned integers without
a CBOR tag. `encode_deterministic_cbor(value)` denotes this specification operation; it
is not a separate wire format.

## 2. Consolidated CDDL

Semantic, suite-specific, scheme-specific, and extension-specific requirements apply
in addition to this shape. Component documents repeat relevant fragments near their
semantic requirements; this section is the consolidated schema.

```cddl
content-encryption-suite = &(
  unspecified: 0,
  aes-256-gcm-hkdf-sha256: 1,
  aes-256-gcm-hkdf-sha256-stream-64k: 2
)

recovery-scheme = &(
  unspecified: 0,
  direct: 1,
  xor-all: 2,
  key-epoch: 3
)

wrap-suite = &(
  unspecified: 0,
  ecdh-p256-hkdf-sha256-aes-256-gcm: 1,
  ecdh-p384-hkdf-sha256-aes-256-gcm: 2,
  ecdh-p521-hkdf-sha256-aes-256-gcm: 3,
  ml-kem-768-hkdf-sha256-aes-256-gcm: 4,
  ml-kem-1024-hkdf-sha256-aes-256-gcm: 5
)

binding-algorithm = &(
  unspecified: 0,
  hmac-sha256: 1
)

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

policy-entry = [
  namespace: policy-namespace,
  attribute: tstr,
  values: [+ tstr]
]

policy-namespace = tstr

canonical-policy = [+ policy-entry]

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

recovery-scheme-data = $binary-tdf-recovery-scheme-data

object-key-recovery = {
  1 => recovery-scheme,
  ? 2 => canonical-policy,
  3 => recovery-scheme-data
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

session-context = {
  1 => uint,
  2 => bstr .size 32,
  3 => bstr .size 32,
  4 => kao-path,
  5 => wrap-suite,
  6 => bstr .size 32
}

direct-kao-set = [key-access-object]

xor-all-share-group = [1* key-access-object]

xor-all-kao-groups = [2* xor-all-share-group]

direct-recovery-data = direct-kao-set

xor-all-recovery-data = xor-all-kao-groups

$binary-tdf-recovery-scheme-data /= direct-recovery-data
$binary-tdf-recovery-scheme-data /= xor-all-recovery-data
```

## 3. Extension sockets

Extension specifications augment the two `$binary-tdf-*` sockets with `/=`. The
metadata wildcard permits only unknown non-critical tags; recognized tags use their
registered sub-schema. The selected recovery identifier determines the valid closed
recovery plug.
