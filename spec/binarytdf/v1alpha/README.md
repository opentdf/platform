# BinaryTDF Specification Suite — Version 1 Alpha

BinaryTDF is a compact, immutable format for protecting one payload. Each object
contains deterministic CBOR metadata, object-key recovery information, and encrypted
content. Exact serialized bytes are cryptographic inputs and must not be reconstructed
after parsing.

This suite reorganizes BinaryTDF draft 0.2, frame version 2, into components aligned
with the BaseTDF 5 architecture. The refactoring changes document ownership, not wire
format, algorithms, validation, or security semantics.

## Core modules

| Layer | Document | Responsibility | File |
|---|---|---|---|
| Foundation | BinaryTDF-SEC | Security considerations and parser limits | [binarytdf-sec.md](binarytdf-sec.md) |
| Foundation | BinaryTDF-ALG | Algorithm and extension registries | [binarytdf-alg.md](binarytdf-alg.md) |
| Model | BinaryTDF-MTD | Protected metadata and extension carriage | [binarytdf-mtd.md](binarytdf-mtd.md) |
| Policy | BinaryTDF-POL | Canonical authorization policy | [binarytdf-pol.md](binarytdf-pol.md) |
| Operations | BinaryTDF-REC | Object-key recovery topology | [binarytdf-rec.md](binarytdf-rec.md) |
| Operations | BinaryTDF-KAO | Protection of one recovery value | [binarytdf-kao.md](binarytdf-kao.md) |
| Operations | BinaryTDF-PAY | Payload-key derivation and encryption | [binarytdf-pay.md](binarytdf-pay.md) |
| Policy | BinaryTDF-KAS | KAS rewrap protocol | [binarytdf-kas.md](binarytdf-kas.md) |
| Storage | BinaryTDF-PKG | Physical binary frame | [binarytdf-pkg.md](binarytdf-pkg.md) |
| Schema | BinaryTDF-SCH | Deterministic CBOR and consolidated CDDL | [binarytdf-sch.md](binarytdf-sch.md) |
| Assembly | BinaryTDF-CORE | Logical object and end-to-end processing | [binarytdf-core.md](binarytdf-core.md) |
| Examples | BinaryTDF-EX | Worked example | [binarytdf-ex.md](binarytdf-ex.md) |

## Extensions, profiles, and guides

| Kind | Document | Extends | File |
|---|---|---|---|
| Extension | BinaryTDF-STREAM | PAY and PKG | [binarytdf-ext-stream.md](binarytdf-ext-stream.md) |
| Extension | BinaryTDF-KEY-EPOCH | REC | [binarytdf-ext-key-epoch.md](binarytdf-ext-key-epoch.md) |
| Profile | BinaryTDF-NATO | MTD and POL | [binarytdf-profile-nato.md](binarytdf-profile-nato.md) |
| Guide | BinaryTDF-MIG | CORE, PKG, and SCH | [binarytdf-migration.md](binarytdf-migration.md) |

## Architecture

Arrows point from prerequisites to consumers.

```text
SEC ──► ALG, MTD, POL, REC, KAO, PAY, KAS, PKG
ALG, MTD, POL, KAO ──► REC
ALG, MTD, REC ───────► PAY
ALG, MTD, POL, REC, KAO ──► KAS
ALG, MTD, POL, REC, KAO, KAS ──► SCH ──► PKG

SEC, ALG, MTD, POL, REC, KAO, PAY, KAS, SCH, PKG ──► CORE ──► EX

PAY, PKG ──► STREAM
REC, SCH ──► KEY-EPOCH
MTD, POL ──► NATO
CORE, PKG, SCH ──► MIG
```

## Alignment with BaseTDF 5

The suites use the same names for shared responsibilities: SEC, ALG, POL, KAO, KAS,
PKG, CORE, and EX. BinaryTDF-SCH corresponds to the BaseTDF JSON schemas while using
CDDL for deterministic CBOR. BinaryTDF-MTD makes metadata carriage explicit, and
BinaryTDF-REC separates recovery topology from protection of one recovery value.

BinaryTDF-PAY covers the payload-encryption portion of BaseTDF-INT. BinaryTDF has no
separate INT module because its baseline integrity is supplied by the selected AEAD
suite. It has no ASN module because signed claims are not a core capability, and no LOC
module because frame version 2 carries its payload inline. These absences are format
boundaries rather than missing placeholder documents.

## Conventions

BCP 14 requirement terms are normative only when written in all capitals. Unless
specified otherwise, unsigned integers in BinaryTDF-PKG are big-endian, `||` means byte
concatenation, indexes are zero-based, and CBOR follows BinaryTDF-SCH.

## Status and source

The suite is an alpha draft. Its normative source is BinaryTDF draft 0.2, frame
version 2, in the `pr-2-codex-binary-tdf-draft-0-2` branch of the BinaryTDF
specification project. Prototype frame version 1 is incompatible with frame version 2.
The source draft's recovery documents, streaming suite, key-epoch extension, NATO
metadata profile, and Go prototype migration guide are included.

## License

This specification is licensed under the repository's license terms.
