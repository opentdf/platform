# BinaryTDF-CORE: Frame and End-to-End Processing

| | |
|---|---|
| Document | BinaryTDF-CORE |
| Version | 1 Alpha |
| Source draft | 0.2 |
| Frame version | 2 |
| Status | Draft |
| Depends on | BinaryTDF-MTD, BinaryTDF-POL, BinaryTDF-REC, BinaryTDF-KAO, BinaryTDF-PAY, BinaryTDF-KAS, BinaryTDF-SEC |
| Referenced by | BinaryTDF-CDDL, BinaryTDF-EX, BinaryTDF-MIG |

## 1. Scope

BinaryTDF is a compact, self-contained format for protecting one payload. Each object
contains deterministic CBOR metadata, information needed to recover its object key,
and encrypted content. Every byte is fixed at creation, and exact wire bytes are used
directly by the cryptographic protocol.

Frame version 2 defines:

- one compact-object frame containing one payload;
- direct and all-shares XOR object-key recovery;
- a baseline AES-256-GCM content-encryption suite;
- classical ECDH and non-hybrid ML-KEM-768 and ML-KEM-1024 KAO wrap suites;
- deterministic policy and object binding;
- an algorithm-neutral KAS rewrap exchange; and
- extension sockets for metadata, recovery schemes, and content-encryption suites.

The core does not define additional payload constructions, signature formats, signed
claims, classification labels, or domain metadata schemas. Those capabilities use
separately versioned specifications and the registries defined by BinaryTDF-ALG.

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are interpreted as
described by BCP 14 when written in all capitals.

### 1.1 Terminology

- A producer creates a BinaryTDF. An opener decrypts one.
- An authority controls a KAO recipient key and decides whether to release the value
  it protects. A Key Access Service, or KAS, deploys that role.
- AEAD encrypts data and detects changes to the ciphertext and associated data.
- Associated data, or AAD, is authenticated but not encrypted.
- A nonce is a per-encryption value that must not repeat under one AES-GCM key.
- HKDF derives domain-separated keys from secret material and context.
- A key-encryption key, or KEK, is used only to encrypt another key.
- Wrapping encrypts a key or share for an authority. Rewrap encrypts the recovered
  value to an opener session key.
- Encapsulation is the public material sent by a key-establishment scheme: an
  ephemeral ECDH public key or an ML-KEM ciphertext.

## 2. Object model

A BinaryTDF is immutable. Three sections define what is protected, how the object key
is recovered, and the encrypted content:

```text
+-----------------------+
| Protected Metadata    |
+-----------------------+
| Object Key Recovery   |
+-----------------------+
| Encrypted Payload     |
+-----------------------+
```

All three are cryptographic inputs. Protected Metadata and Object Key Recovery are
payload AAD, and every KAO is bound to its exact context. Changing any byte invalidates
key recovery or payload authentication.

External systems MAY identify an object by a cryptographic hash of its complete bytes.
Detached attestations, audit records, and transfer manifests can use that hash without
cooperation from the format.

Signed claims are not a core mechanism. Unsigned claims belong in application data or
a registered metadata extension. Signed claims use an extension with its own signature
and validation rules or a detached attestation over the complete object hash.

### 2.1 Key hierarchy

- The object key is a unique 32-byte root key generated or derived for one object.
- A key share is a 32-byte value used by a split recovery scheme.
- The payload key is derived from the object key by the content-encryption suite.

A KAO protects an object key, a key share, or another 32-byte value defined by a
registered recovery scheme. The authority releases that value; reconstruction and
payload-key derivation occur locally at the opener.

### 2.2 Capability selection

| Field | Selection |
|---|---|
| `content_encryption_suite` | Payload-key derivation and payload encryption |
| `recovery_scheme` | Object-key recovery procedure |
| `wrap_suite` | Protection of one KAO value |
| Metadata extension tag | Application-specific metadata schema |

The object declares these choices and does not negotiate them. Capability discovery
occurs before creation. A receiver MUST NOT replace an unsupported capability with a
weaker one.

### 2.3 Producer lifecycle

This subsection is non-normative; the referenced component requirements are normative.

1. Create the object key and any shares required by BinaryTDF-REC.
2. Encode Protected Metadata as deterministic CBOR.
3. Encode Canonical Policy and Object Key Recovery as deterministic CBOR.
4. Derive every KAO context, wrap its value, and compute its policy binding.
5. Derive the payload key and encrypt using the exact metadata and recovery bytes as
   AAD.
6. Emit the frame in the order defined below.

Steps 2 and 3 finish before steps 4 and 5 because their exact bytes are inputs to KAO
wrapping and payload encryption.

## 3. Binary frame

All integer lengths are unsigned and big-endian.

```text
+----------------------------+----------------------------------+
| Field                      | Size                             |
+----------------------------+----------------------------------+
| Magic                      | 3 bytes: ASCII "L2L"            |
| Version                    | 1 byte: 0x02                    |
| Metadata Length            | 4 bytes                         |
| Protected Metadata CBOR    | Metadata Length bytes           |
| Object Key Recovery Length | 4 bytes                         |
| Object Key Recovery CBOR   | Recovery Length bytes           |
| Ciphertext Length          | 8 bytes                         |
| Ciphertext                 | Ciphertext Length bytes         |
+----------------------------+----------------------------------+
```

Ciphertext Length includes all suite-specific header, nonce, ciphertext, and tag bytes.
There MUST be no bytes after the declared Ciphertext section.

The 64-bit ciphertext length permits payloads larger than 4 GiB. It is a framing bound,
not an allocation instruction. A decoder MUST reject an object before CBOR processing
when:

- magic or version is unsupported;
- a length field is truncated;
- a declared section exceeds remaining input;
- offset or capacity arithmetic overflows; or
- the Ciphertext section does not consume remaining input exactly.

Changing frame layout, a cryptographic input construction, or the meaning of an
existing security-bearing field requires a new frame version.

## 4. CBOR encoding

All CBOR MUST use RFC 8949 Core Deterministic Encoding Requirements. Encoders MUST use
preferred serialization, deterministic map-key ordering, and definite-length items.
Optional fields with absent, empty, or zero values are omitted unless specified
otherwise.

Decoders MUST reject duplicate map keys, indefinite-length items, non-deterministic
encodings, invalid types, unregistered core keys, and resource-limit violations.
Implementations MUST impose finite limits on nesting, collection sizes, and section
lengths.

Core maps use unsigned integer keys. Registry identifiers are unsigned integers without
a CBOR tag. `encode_deterministic_cbor(value)` denotes this specification operation;
it is not a separate wire format.

## 5. Opening procedure

A conforming opener performs:

1. frame and exact-length validation;
2. deterministic CBOR and registered-core-field validation;
3. suite, scheme, and critical-extension validation;
4. local unwrap or KAS rewrap and policy-binding verification for required KAOs;
5. object-key reconstruction or derivation; and
6. payload authentication before returning plaintext, subject to a registered
   content-encryption suite's explicit incremental release rules.

## 6. Conformance

At minimum, interoperability tests SHOULD cover:

- byte-identical deterministic encoding across SDKs;
- malformed lengths and trailing data;
- duplicate, indefinite-length, non-deterministic, and unknown core fields;
- unknown non-critical and critical extensions;
- one-byte changes to version, metadata, recovery, encapsulation, wrapped material,
  and ciphertext;
- wrong-suite keys, lengths, and encodings;
- ML-KEM failure without distinguishable error leakage;
- DIRECT and XOR_ALL paths, alternatives, missing groups, and reconstruction;
- non-canonical, duplicate, and substituted policies; and
- permit, deny, malformed, unsupported-capability, and partial-success rewrap.

Cross-language vectors SHOULD include the complete object, raw sections, policy bytes,
KAO and session context bytes, payload AAD, derived-key inputs, and expected failure.

## 7. References

- [BCP 14](https://www.rfc-editor.org/info/bcp14)
- [RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869)
- [RFC 8126: Protocol Registries](https://www.rfc-editor.org/rfc/rfc8126)
- [RFC 8610: CDDL](https://www.rfc-editor.org/rfc/rfc8610)
- [RFC 8949: CBOR](https://www.rfc-editor.org/rfc/rfc8949)
- [FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
