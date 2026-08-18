# BinaryTDF-PKG: Binary Packaging Profile

| | |
|---|---|
| Document | BinaryTDF-PKG |
| Version | 1 Alpha |
| Source draft | 0.2 |
| Frame version | 2 |
| Status | Draft |
| Depends on | BinaryTDF-SEC, BinaryTDF-SCH |
| Referenced by | BinaryTDF-CORE, BinaryTDF-EX, BinaryTDF-STREAM, BinaryTDF-MIG |

## 1. Scope

This document defines the physical serialization of one BinaryTDF object. It owns the
frame magic, version byte, section ordering, length fields, and outer parsing rules.
The logical meaning and schema of each section are defined by the component documents
and BinaryTDF-SCH. The internal construction of the Ciphertext section is selected by
BinaryTDF-PAY.

Every serialized byte is fixed at creation. Exact Protected Metadata and Object Key
Recovery bytes are cryptographic inputs and are preserved rather than reconstructed
after parsing. BinaryTDF-PAY defines the normative use of those original bytes.

## 2. Binary frame

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
not an allocation instruction.

## 3. Parsing

A decoder MUST reject an object before CBOR processing when:

- magic or version is unsupported;
- a length field is truncated;
- a declared section exceeds remaining input;
- offset or capacity arithmetic overflows; or
- the Ciphertext section does not consume remaining input exactly.

Parser limits from BinaryTDF-SEC apply before allocation, hashing, or authority contact.
A decoder retains the exact Protected Metadata and Object Key Recovery section bytes
required by the cryptographic components.

## 4. Versioning and conformance

Changing frame layout, section ordering, length encoding, a cryptographic input
construction, or the meaning of an existing security-bearing field requires a new
frame version. BinaryTDF-CORE defines suite-wide conformance coverage.
