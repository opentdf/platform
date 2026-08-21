# BinaryTDF-EX: Worked Example

| | |
|---|---|
| Document | BinaryTDF-EX |
| Version | 1 Alpha |
| Source draft | 0.2 |
| Frame version | 2 |
| Status | Informational |
| Depends on | BinaryTDF-CORE, BinaryTDF-PKG, BinaryTDF-SCH |

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

## 3. BinaryTDF-PKG frame layout

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

## 5. Limit vectors

These items extend the BinaryTDF-CORE Section 4 coverage with the content-encryption
limits of BinaryTDF-SEC Section 3. Lengths are exact; payload bytes are omitted because
only the declared lengths and header fields decide each case. Every rejection happens
before decryption, on frame and header values alone.

1. Suite 1 at the per-invocation limit. A Ciphertext Length of `68719476732` carries
   68719476704 plaintext bytes with a 12-byte nonce and a 16-byte tag, exactly the
   BinaryTDF-PAY Section 4 limit, and MUST open. A Ciphertext Length of `68719476733`
   carries one byte more and MUST be rejected.
2. Suite 2 at the volume ceiling. With `segment_size` 1048576, a Ciphertext Length of
   `1099528405308` spans 1048593 segments and 1099511627776 plaintext bytes, exactly
   the BinaryTDF-STREAM Section 8.1 ceiling, and MUST open. A Ciphertext Length of
   `1099528405309` carries one plaintext byte more and MUST be rejected.
3. Suite 3 at a partition boundary. With `segment_size` 1048576 and
   `partition_segments` 4, segment 3 decrypts under `K_0` and segment 4 under `K_1`,
   where `K_1` is `HKDF-Expand(payload_key,
   UTF8("binary-tdf:v2:stream-partition") || 0000000000000001, 32)`. The partition
   index and the nonce indexes are hexadecimal. Their nonces keep the absolute index:
   `nonce_prefix || 00000003 || 00` and `nonce_prefix || 00000004 || 00`. Swapping the
   two ciphertext segments MUST fail authentication.
4. Suite 3 parameter rejection. With `segment_size` 1048576, `partition_segments`
   1048592 is the largest conforming value, because `1048592 * 1048560` is
   1099511627520. The value 1048593 gives 1099512676080 and MUST be rejected by
   BinaryTDF-STREAM Section 9.4.
