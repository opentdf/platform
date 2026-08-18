# BinaryTDF Specification Suite — Version 1 Alpha

BinaryTDF is a compact, immutable format for protecting one payload. Each object
contains deterministic CBOR metadata, object-key recovery information, and encrypted
content. Exact wire bytes are cryptographic inputs and must not be reconstructed after
parsing.

This suite reorganizes BinaryTDF draft 0.2, frame version 2, into parallel components.
It changes presentation, not wire format, intent, algorithms, validation, or security
semantics. The source draft's recovery documents, streaming suite, key-epoch extension,
NATO metadata profile, and Go prototype migration guide are included.

## Documents

| Layer | Document | Title | File |
|---|---|---|---|
| Foundation | BinaryTDF-SEC | Security Considerations | [binarytdf-sec.md](binarytdf-sec.md) |
| Foundation | BinaryTDF-ALG | Algorithm and Extension Registries | [binarytdf-alg.md](binarytdf-alg.md) |
| Model | BinaryTDF-MTD | Protected Metadata | [binarytdf-mtd.md](binarytdf-mtd.md) |
| Model | BinaryTDF-POL | Canonical Policy | [binarytdf-pol.md](binarytdf-pol.md) |
| Recovery | BinaryTDF-REC | Object Key Recovery | [binarytdf-rec.md](binarytdf-rec.md) |
| Recovery | BinaryTDF-KAO | Key Access Object and Wrapping | [binarytdf-kao.md](binarytdf-kao.md) |
| Payload | BinaryTDF-PAY | Payload Protection | [binarytdf-pay.md](binarytdf-pay.md) |
| Protocol | BinaryTDF-KAS | KAS Rewrap Protocol | [binarytdf-kas.md](binarytdf-kas.md) |
| Assembly | BinaryTDF-CORE | Frame and End-to-End Processing | [binarytdf-core.md](binarytdf-core.md) |
| Schema | BinaryTDF-CDDL | Normative CDDL | [binarytdf-cddl.md](binarytdf-cddl.md) |
| Examples | BinaryTDF-EX | Worked Example | [binarytdf-ex.md](binarytdf-ex.md) |
| Extension | BinaryTDF-STREAM | AES-256-GCM-HKDF Streaming Suite | [binarytdf-ext-stream.md](binarytdf-ext-stream.md) |
| Extension | BinaryTDF-KEY-EPOCH | KEY_EPOCH Recovery | [binarytdf-ext-key-epoch.md](binarytdf-ext-key-epoch.md) |
| Profile | BinaryTDF-NATO | NATO Metadata Interoperability | [binarytdf-profile-nato.md](binarytdf-profile-nato.md) |
| Migration | BinaryTDF-MIG | Go Prototype Migration | [binarytdf-migration.md](binarytdf-migration.md) |

## Architecture

```text
SEC ──► ALG ──► MTD, REC, KAO, PAY
 │                 │    │    │
 ├──► POL ─────────┘    │    │
 └──────────────────────► KAS

MTD, POL, REC, KAO, PAY, KAS ──► CORE
All component schemas ──────────► CDDL
CORE, CDDL ─────────────────────► EX

REC ──► KEY-EPOCH
PAY ──► STREAM
MTD, POL ──► NATO
CORE ──► MIG
```

## Conventions

BCP 14 requirement terms are normative only when written in all capitals. Unless
specified otherwise, unsigned integers in the binary frame are big-endian, `||`
means byte concatenation, indexes are zero-based, and CBOR uses the Core Deterministic
Encoding Requirements of RFC 8949 Section 4.2.

## Status and source

The suite is an alpha draft. Its normative source is BinaryTDF draft 0.2, frame
version 2, in the `pr-2-codex-binary-tdf-draft-0-2` branch of the BinaryTDF
specification project. Prototype frame version 1 is incompatible with frame version 2.

## License

This specification is licensed under the repository's license terms.
