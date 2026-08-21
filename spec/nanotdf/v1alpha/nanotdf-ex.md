# NanoTDF-EX: Worked Examples

| | |
|---|---|
| Document | NanoTDF-EX |
| Version | 1 Alpha |
| Source spec | nanotdf v1 |
| Format version | 12 (`L1L`) |
| Status | Informational |
| Depends on | NanoTDF-CORE, NanoTDF-PKG, NanoTDF-POL, NanoTDF-BND, NanoTDF-PAY |

Two complete objects. Unlike the placeholder values used in some suites, these are real
interoperability vectors: each base64 blob decodes to the exact bytes shown, every field
offset below lands on a real boundary, and the section lengths sum to the stated total.
Private keys are included so that an implementation can reproduce the derivations.

| Example | Header | Payload | Signature | Total | Overhead |
|---|---:|---:|---:|---:|---:|
| §1 signed, remote policy, 64-bit tag | 142 | 19 | 97 | 258 | 253 |
| §2 unsigned, remote policy, 128-bit tag | 151 | 46 | — | 197 | 173 |

Example 2 is the basis of the format's sub-200-byte overhead claim.

## 1. Basic example

### 1.1 Parameters

- KAS URL: `https://kas.virtru.com`
- Policy URL: `https://kas.virtru.com/policy`, a remote policy
- ECC and Binding Mode: `USE_ECDSA_BINDING` is true, curve `0x00` (`secp256r1`)
- Symmetric and Payload Config: `HAS_SIGNATURE` is true, cipher `0x00`
  (AES-256-GCM, 64-bit tag)
- Plaintext payload: `DON'T`

The plaintext is an easter egg: it was the message in the first TDF email sent with the
browser extension on Gmail.

### 1.2 Creator private key

DER encoded, base64. Included so the signature can be verified.

```text
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcal1YrV0QohnYoBBlcBLrRETfJlqFOkG
LSmUOKizW0KhRANCAATVz7l/VSTFkD9ic2IFkzaqcaTC7hbQW3g0A5firgcdLv4sj0OJHZ5zf8U0oUiy
IrwNU28ahFSfjCTYvzw/bvPg
```

### 1.3 Recipient private key

DER encoded, base64. Included so the payload key can be derived.

```text
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgRywXmrI1J07LZni8xaoKhXj8WbdDHdjd
N62+tgxjdhihRANCAARon4RjqRNA40eEdBT172emATq3I2siKccLcXl07nTrbAu4enVDo9T4LfQ4eZ0y
x/KkIX2HylxzkAEoBxzVpBLN
```

### 1.4 Recipient compressed public key

```text
A2ifhGOpE0DjR4R0FPXvZ6YBOrcjayIpxwtxeXTudOts
```

### 1.5 Complete object

Base64:

```text
TDFMAQ5rYXMudmlydHJ1LmNvbYCAAAEVa2FzLnZpcnRydS5jb20vcG9saWN5teQTpgIR5fF7IjSgzT82
/3u6bY/o3yP2LJ0JNW+FgvipzxUSbIqdpGxeTgy8yCaXGawFG4BiXMdUAwNv+4KHHwL3f7rlJgnaxejr
94bhG3rt1w+JgPlIDH5nHLqrjiRQkgAAEJ69CRdSJo4D+f2AFK98ywYC1c+5f1UkxZA/YnNiBZM2qnGk
wu4W0Ft4NAOX4q4HHS6dm4rjMO9wI+pWmbUgS7x9Vo3/+j/6U1fh/NKQ8xrR72LORvDZXfQxa8rzco1P
dc0VlQEL8gQgdKyU3il2ugLz
```

Hex, 258 bytes:

```text
4c 31 4c 01 0e 6b 61 73 2e 76 69 72 74 72 75 2e 63 6f 6d 80
80 00 01 15 6b 61 73 2e 76 69 72 74 72 75 2e 63 6f 6d 2f 70
6f 6c 69 63 79 b5 e4 13 a6 02 11 e5 f1 7b 22 34 a0 cd 3f 36
ff 7b ba 6d 8f e8 df 23 f6 2c 9d 09 35 6f 85 82 f8 a9 cf 15
12 6c 8a 9d a4 6c 5e 4e 0c bc c8 26 97 19 ac 05 1b 80 62 5c
c7 54 03 03 6f fb 82 87 1f 02 f7 7f ba e5 26 09 da c5 e8 eb
f7 86 e1 1b 7a ed d7 0f 89 80 f9 48 0c 7e 67 1c ba ab 8e 24
50 92 00 00 10 9e bd 09 17 52 26 8e 03 f9 fd 80 14 af 7c cb
06 02 d5 cf b9 7f 55 24 c5 90 3f 62 73 62 05 93 36 aa 71 a4
c2 ee 16 d0 5b 78 34 03 97 e2 ae 07 1d 2e 9d 9b 8a e3 30 ef
70 23 ea 56 99 b5 20 4b bc 7d 56 8d ff fa 3f fa 53 57 e1 fc
d2 90 f3 1a d1 ef 62 ce 46 f0 d9 5d f4 31 6b ca f3 72 8d 4f
75 cd 15 95 01 0b f2 04 20 74 ac 94 de 29 76 ba 02 f3
```

### 1.6 Layout

| Offset | Section | Field | Bytes |
|---:|---|---|---:|
| `0x000` | Header | Magic Number and Version | 3 |
| `0x003` | Header | KAS Resource Locator | 16 |
| `0x013` | Header | ECC and Binding Mode | 1 |
| `0x014` | Header | Symmetric and Payload Config | 1 |
| `0x015` | Header | Policy Type Enum | 1 |
| `0x016` | Header | Policy Body | 23 |
| `0x02d` | Header | Policy Binding | 64 |
| `0x06d` | Header | Ephemeral Public Key | 33 |
| `0x08e` | Payload | Length | 3 |
| `0x091` | Payload | IV | 3 |
| `0x094` | Payload | Ciphertext | 5 |
| `0x099` | Payload | MAC | 8 |
| `0x0a1` | Signature | Creator Public Key | 33 |
| `0x0c2` | Signature | Signature (`r \|\| s`) | 64 |

Header 142, Payload 19, Signature 97, total 258.

### 1.7 Fields

#### 1.7.1 Magic Number and Version

```text
4c 31 4c
```

ASCII `L1L`, format version 12.

#### 1.7.2 KAS Resource Locator

```text
01 0e 6b 61 73 2e 76 69 72 74 72 75 2e 63 6f 6d
```

Protocol `0x01` is `https`; body length `0x0e` is 14; the body is `kas.virtru.com`.

#### 1.7.3 ECC and Binding Mode

```text
80
```

`1000 0000`: `USE_ECDSA_BINDING` is 1, the reserved bits are zero, and the Ephemeral ECC
Params Enum is `000` for `secp256r1`. The ephemeral key is therefore 33 bytes and the
ECDSA policy binding 64 bytes.

#### 1.7.4 Symmetric and Payload Config

```text
80
```

`1000 0000`: `HAS_SIGNATURE` is 1, the Signature ECC Mode is `000` for `secp256r1`, and
the Symmetric Cipher Enum is `0000` for AES-256-GCM with a 64-bit tag. The MAC is
therefore 8 bytes and the Signature section 97 bytes.

#### 1.7.5 Policy

Type enum:

```text
00
```

Type `0x00` is a remote policy, so the body is a Resource Locator.

Body:

```text
01 15 6b 61 73 2e 76 69 72 74 72 75 2e 63 6f 6d 2f 70 6f 6c
69 63 79
```

Protocol `0x01` is `https`; body length `0x15` is 21; the body is
`kas.virtru.com/policy`.

Binding:

```text
b5 e4 13 a6 02 11 e5 f1 7b 22 34 a0 cd 3f 36 ff 7b ba 6d 8f
e8 df 23 f6 2c 9d 09 35 6f 85 82 f8 a9 cf 15 12 6c 8a 9d a4
6c 5e 4e 0c bc c8 26 97 19 ac 05 1b 80 62 5c c7 54 03 03 6f
fb 82 87 1f
```

An ECDSA signature over `SHA256` of the 23 policy body bytes, sized by the ephemeral
curve.

#### 1.7.6 Ephemeral Public Key

```text
02 f7 7f ba e5 26 09 da c5 e8 eb f7 86 e1 1b 7a ed d7 0f 89
80 f9 48 0c 7e 67 1c ba ab 8e 24 50 92
```

A compressed point on `secp256r1`; the leading `02` is the y-parity byte.

#### 1.7.7 Payload

Length:

```text
00 00 10
```

16 bytes follow: a 3-byte IV, 5 bytes of ciphertext, and an 8-byte MAC.

IV:

```text
9e bd 09
```

Not `0x000000`, as required.

Ciphertext:

```text
17 52 26 8e 03
```

Five bytes, matching the five-character plaintext.

MAC:

```text
f9 fd 80 14 af 7c cb 06
```

#### 1.7.8 Signature

Creator public key, a compressed point belonging to the producer's persistent key:

```text
02 d5 cf b9 7f 55 24 c5 90 3f 62 73 62 05 93 36 aa 71 a4 c2
ee 16 d0 5b 78 34 03 97 e2 ae 07 1d 2e
```

Signature, `r || s`:

```text
9d 9b 8a e3 30 ef 70 23 ea 56 99 b5 20 4b bc 7d 56 8d ff fa
3f fa 53 57 e1 fc d2 90 f3 1a d1 ef 62 ce 46 f0 d9 5d f4 31
6b ca f3 72 8d 4f 75 cd 15 95 01 0b f2 04 20 74 ac 94 de 29
76 ba 02 f3
```

## 2. No-signature example

### 2.1 Parameters

- KAS URL: `https://kas.example.com`
- Policy URL: `https://kas.example.com/policy/abcdef`, a remote policy
- ECC and Binding Mode: `USE_ECDSA_BINDING` is true, curve `0x00` (`secp256r1`)
- Symmetric and Payload Config: `HAS_SIGNATURE` is false, cipher `0x05`
  (AES-256-GCM, 128-bit tag)
- Plaintext payload: `Keep this message secret`

### 2.2 Creator private key

None. This object carries no signature, so there is no creator key.

### 2.3 Recipient private key

DER encoded, base64.

```text
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWmLjd6gDd2rwU48m2vVsDfVJ6fKCYt4y
ZA8kSu9O3hehRANCAAQwmFsrcVyKJpSQBMVVrIZ0v0XIin+BSdS/ENvcyIc2YKKIK43zkpPR13ibjsy1
UhZJItQFlBChYCFDPUkANqcs
```

### 2.4 Recipient compressed public key

```text
AjCYWytxXIomlJAExVWshnS/RciKf4FJ1L8Q29zIhzZg
```

### 2.5 Complete object

Base64:

```text
TDFMAQ9rYXMuZXhhbXBsZS5jb22ANQABHWthcy5leGFtcGxlLmNvbS9wb2xpY3kvYWJjZGVmYaoGjXbC
DfOlY3YzmGKfUjBy0IbUTUvmbiV04TvDLMcCKkzceqfvy6YDwZg/h3LvHRDoLg1ABvS93ZJ4eTVmcwPo
sz9EmnOSdxPUpKK05elFLi8FNDOdNZEb36Fe4Ys62wAAK1DknPqraRhSJhstY2CDGsvV8gP77xf5Rr7+
x57lEZugkjM7LA7qy54vjcg=
```

Hex, 197 bytes:

```text
4c 31 4c 01 0f 6b 61 73 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d
80 35 00 01 1d 6b 61 73 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d
2f 70 6f 6c 69 63 79 2f 61 62 63 64 65 66 61 aa 06 8d 76 c2
0d f3 a5 63 76 33 98 62 9f 52 30 72 d0 86 d4 4d 4b e6 6e 25
74 e1 3b c3 2c c7 02 2a 4c dc 7a a7 ef cb a6 03 c1 98 3f 87
72 ef 1d 10 e8 2e 0d 40 06 f4 bd dd 92 78 79 35 66 73 03 e8
b3 3f 44 9a 73 92 77 13 d4 a4 a2 b4 e5 e9 45 2e 2f 05 34 33
9d 35 91 1b df a1 5e e1 8b 3a db 00 00 2b 50 e4 9c fa ab 69
18 52 26 1b 2d 63 60 83 1a cb d5 f2 03 fb ef 17 f9 46 be fe
c7 9e e5 11 9b a0 92 33 3b 2c 0e ea cb 9e 2f 8d c8
```

### 2.6 Layout

| Offset | Section | Field | Bytes |
|---:|---|---|---:|
| `0x000` | Header | Magic Number and Version | 3 |
| `0x003` | Header | KAS Resource Locator | 17 |
| `0x014` | Header | ECC and Binding Mode | 1 |
| `0x015` | Header | Symmetric and Payload Config | 1 |
| `0x016` | Header | Policy Type Enum | 1 |
| `0x017` | Header | Policy Body | 31 |
| `0x036` | Header | Policy Binding | 64 |
| `0x076` | Header | Ephemeral Public Key | 33 |
| `0x097` | Payload | Length | 3 |
| `0x09a` | Payload | IV | 3 |
| `0x09d` | Payload | Ciphertext | 24 |
| `0x0b5` | Payload | MAC | 16 |

Header 151, Payload 46, no Signature, total 197.

### 2.7 Fields

#### 2.7.1 Magic Number and Version

```text
4c 31 4c
```

#### 2.7.2 KAS Resource Locator

```text
01 0f 6b 61 73 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d
```

Protocol `0x01` is `https`; body length `0x0f` is 15; the body is `kas.example.com`.

#### 2.7.3 ECC and Binding Mode

```text
80
```

As in §1.7.3: ECDSA binding on `secp256r1`.

#### 2.7.4 Symmetric and Payload Config

```text
35
```

`0011 0101`: `HAS_SIGNATURE` is 0, so no Signature section follows and the object ends
with the payload. The Signature ECC Mode is `011`, which would name `secp256k1` but is
unused and MUST NOT cause rejection. The Symmetric Cipher Enum is `0101`, cipher `0x05`,
AES-256-GCM with a 128-bit tag, so the MAC is 16 bytes.

#### 2.7.5 Policy

Type enum:

```text
00
```

Remote policy.

Body:

```text
01 1d 6b 61 73 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d 2f 70 6f
6c 69 63 79 2f 61 62 63 64 65 66
```

Protocol `0x01` is `https`; body length `0x1d` is 29; the body is
`kas.example.com/policy/abcdef`.

Binding:

```text
61 aa 06 8d 76 c2 0d f3 a5 63 76 33 98 62 9f 52 30 72 d0 86
d4 4d 4b e6 6e 25 74 e1 3b c3 2c c7 02 2a 4c dc 7a a7 ef cb
a6 03 c1 98 3f 87 72 ef 1d 10 e8 2e 0d 40 06 f4 bd dd 92 78
79 35 66 73
```

#### 2.7.6 Ephemeral Public Key

```text
03 e8 b3 3f 44 9a 73 92 77 13 d4 a4 a2 b4 e5 e9 45 2e 2f 05
34 33 9d 35 91 1b df a1 5e e1 8b 3a db
```

Leading `03`, the opposite y-parity to §1.7.6.

#### 2.7.7 Payload

Length:

```text
00 00 2b
```

43 bytes follow: a 3-byte IV, 24 bytes of ciphertext, and a 16-byte MAC.

IV:

```text
50 e4 9c
```

Ciphertext:

```text
fa ab 69 18 52 26 1b 2d 63 60 83 1a cb d5 f2 03 fb ef 17 f9
46 be fe c7
```

Twenty-four bytes, matching the 24-character plaintext.

MAC:

```text
9e e5 11 9b a0 92 33 3b 2c 0e ea cb 9e 2f 8d c8
```

#### 2.7.8 Signature

Absent. `HAS_SIGNATURE` is 0 and no bytes follow the payload.

## 3. Derived values

Both examples use format version 12, so both share the HKDF salt from NanoTDF-ALG §3:

```text
salt = SHA256(4c 31 4c)
     = 3de3ca1e50cf62d8b6aba603a96fca6761387a7ac86c3d3afe85ae2d1812edfc
```

The payload key in each case is:

```text
shared_secret = ECDH(ephemeral_public, recipient_private)
payload_key   = HKDF(shared_secret, salt = salt, info = "", len = 32)
```

The policy binding in each case is:

```text
binding = ECDSA(ephemeral_private, SHA256(policy_body_bytes))
```

where `policy_body_bytes` is the 23 bytes at `0x016` in §1 and the 31 bytes at `0x017` in
§2 — the type enum and the binding itself are excluded (NanoTDF-BND §2.1).

## 4. References

- [RFC 4648: Base16 and Base64 Encodings](https://www.rfc-editor.org/rfc/rfc4648)
- [RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869)
- [RFC 5915: Elliptic Curve Private Key Structure](https://www.rfc-editor.org/rfc/rfc5915)
