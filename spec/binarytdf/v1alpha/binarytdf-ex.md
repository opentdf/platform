# BinaryTDF-EX: Worked Example

| | |
|---|---|
| Document | BinaryTDF-EX |
| Version | 1 Alpha |
| Source draft | 0.2 |
| Frame version | 2 |
| Status | Informational |
| Depends on | BinaryTDF-CORE, BinaryTDF-CDDL |

This example builds a minimal DIRECT object with one authority, one policy attribute,
and a five-byte payload. CBOR structures and lengths are exact. Cryptographic outputs
shown as `h'…'` are placeholders, not interoperability vectors.

## 1. Protected Metadata

```text
{
  1: 1,
  2: "text/plain"
}
```

Deterministic encoding, 15 bytes:

```text
a2
   01 01
   02 6a 74 65 78 74 2f 70 6c 61 69 6e
```

## 2. Object Key Recovery

```text
{
  1: 1,
  2: [
    ["example.com", "classification", ["confidential"]]
  ],
  3: [
    {
      1: "urn:example:authority:1",
      3: 1,
      4: h'02…',
      5: h'…',
      6: { 1: 1, 2: h'…' }
    }
  ]
}
```

The wrapped material is exactly 60 bytes:

```text
12-byte nonce || 32-byte encrypted object key || 16-byte tag
```

Encoded size is 215 bytes:

| Item | Bytes |
|---|---:|
| map header | 1 |
| `1: 1` | 2 |
| `2:` and policy | 1 + 43 |
| `3:` and array header | 1 + 1 |
| KAO map header | 1 |
| `authority_id` | 1 + 24 |
| `3: 1` | 2 |
| 33-byte encapsulation | 1 + 35 |
| 60-byte wrapped material | 1 + 62 |
| policy-binding map | 1 + 38 |

The policy bytes are:

```text
81
   83
      6b 65 78 61 6d 70 6c 65 2e 63 6f 6d
      6e 63 6c 61 73 73 69 66 69 63 61 74 69 6f 6e
      81 6c 63 6f 6e 66 69 64 65 6e 74 69 61 6c
```

## 3. Frame layout

For five plaintext bytes, Ciphertext is `12 + 5 + 16 = 33` bytes. The complete object
is 283 bytes:

| Offset | Field | Bytes |
|---:|---|---:|
| `0x000` | Magic `4c 32 4c` | 3 |
| `0x003` | Version `02` | 1 |
| `0x004` | Metadata Length `00 00 00 0f` | 4 |
| `0x008` | Protected Metadata | 15 |
| `0x017` | Recovery Length `00 00 00 d7` | 4 |
| `0x01b` | Object Key Recovery | 215 |
| `0x0f2` | Ciphertext Length `00 00 00 00 00 00 00 21` | 8 |
| `0x0fa` | nonce, ciphertext, tag | 33 |

## 4. Derived values

Payload AAD is 239 bytes and uses original frame bytes:

```text
payload_aad = 02
           || 00 00 00 0f || <15 metadata bytes>
           || 00 00 00 d7 || <215 recovery bytes>
```

The KAO context uses DIRECT path `[0]`:

```text
{
  1: "urn:example:authority:1",
  3: 1,
  4: 2,
  5: h'SHA-256 of metadata bytes',
  6: h'SHA-256 of encapsulation',
  7: h'SHA-256 of policy bytes',
  8: 1,
  9: [0]
}
```

```text
object_key  = 32 random bytes
payload_key = HKDF(object_key,  info = "binary-tdf:v2:payload-key")
wrap_kek    = HKDF(ecdh_secret, info = "binary-tdf:v2:kao-kek" || context)
binding_key = HKDF(object_key,  info = "binary-tdf:v2:policy-binding")
binding     = HMAC-SHA256(binding_key, policy_bytes)
```

The approximate fixed overhead is 250 bytes.
