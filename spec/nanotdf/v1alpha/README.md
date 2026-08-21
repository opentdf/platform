# NanoTDF Specification Suite — Version 1 Alpha

NanoTDF is a compact binary format for protecting one payload under one policy. It
carries no wrapped key: the symmetric key is derived on both sides from an ECDH exchange
between an ephemeral key pair and the Key Access Service's key pair, which removes the
largest fixed cost in a conventional TDF. Objects can be produced offline, and fixed
overhead stays under 200 bytes.

This suite reorganizes the nanotdf version 1 specification into components aligned with
the BaseTDF 5 architecture. The refactoring changes document ownership, not wire format,
algorithms, validation, or security semantics. Where the source specification is
internally inconsistent, this suite states the corrected value and records the correction
in NanoTDF-CORE §6.

## Core modules

| Layer | Document | Responsibility | File |
|---|---|---|---|
| Foundation | NanoTDF-SEC | Security considerations, parser limits, trust boundaries | [nanotdf-sec.md](nanotdf-sec.md) |
| Foundation | NanoTDF-ALG | Curve and cipher registries, key derivation, encodings | [nanotdf-alg.md](nanotdf-alg.md) |
| Policy | NanoTDF-POL | Policy object, type enumeration, remote and embedded bodies | [nanotdf-pol.md](nanotdf-pol.md) |
| Operations | NanoTDF-KAO | Ephemeral key agreement, HKDF derivation, Policy Key Access | [nanotdf-kao.md](nanotdf-kao.md) |
| Operations | NanoTDF-BND | Policy binding and the optional creator signature | [nanotdf-bnd.md](nanotdf-bnd.md) |
| Operations | NanoTDF-PAY | Payload framing, IV, ciphertext, and MAC | [nanotdf-pay.md](nanotdf-pay.md) |
| Operations | NanoTDF-KAS | Key Access Service protocol | [nanotdf-kas.md](nanotdf-kas.md) |
| Storage | NanoTDF-LOC | Resource Locators and fetch policy | [nanotdf-loc.md](nanotdf-loc.md) |
| Storage | NanoTDF-PKG | Binary frame, magic number, bitfields, size bounds | [nanotdf-pkg.md](nanotdf-pkg.md) |
| Assembly | NanoTDF-CORE | Object model, end-to-end processing, source deviations | [nanotdf-core.md](nanotdf-core.md) |
| Examples | NanoTDF-EX | Two verified interoperability vectors | [nanotdf-ex.md](nanotdf-ex.md) |

## Architecture

Arrows point from prerequisites to consumers.

```text
SEC ──► ALG, LOC, PKG, KAO, POL, BND, PAY, KAS

ALG ──► PKG, KAO, POL, BND, PAY
LOC ──► PKG, POL, KAS
PKG ──► KAO, POL, BND, PAY
KAO ──► POL, BND, PAY, KAS
POL ──► BND, KAS
BND ──► KAS

SEC, ALG, LOC, PKG, KAO, POL, BND, PAY, KAS ──► CORE ──► EX
```

## Alignment with BaseTDF 5

The suites use the same names for shared responsibilities: SEC, ALG, POL, KAO, KAS, LOC,
PKG, CORE, and EX.

Two modules have no direct BaseTDF counterpart. NanoTDF-BND owns both the policy binding
and the creator signature, because in NanoTDF the binding is a load-bearing wire field
sized by a header bitfield rather than a property of an assertion; BaseTDF covers the
signature half of this in BaseTDF-ASN. NanoTDF-PAY exists because payload carriage has
its own length field, reserved IV, and implied MAC length; BaseTDF folds the equivalent
into BaseTDF-CORE and BaseTDF-INT.

Four BaseTDF modules are deliberately absent:

- **INT.** NanoTDF defines no segmentation, no Merkle layout, and no per-segment
  integrity. One payload is one AEAD operation, and object-wide integrity exists only
  when a creator signature is present.
- **ASN.** There are no assertions. The only signed claim is the creator signature, owned
  by NanoTDF-BND.
- **MTD.** Version 1 carries no metadata. There is no extension socket to carry any.
- **SCH.** NanoTDF ships no external schema artifact. BinaryTDF has CDDL and IC-TDF has an
  XSD; here the byte tables in NanoTDF-PKG are the grammar.

These absences are format boundaries rather than missing placeholder documents.

## Conventions

BCP 14 requirement terms are normative only when written in all capitals. Unless
specified otherwise, all integers are unsigned and big-endian, `||` means byte
concatenation, bit indices within a byte are numbered from 7 down to 0, and elliptic
curve public keys are X9.62 compressed points.

Several field lengths are implied rather than carried: the ephemeral key, an ECDSA policy
binding, the payload MAC, and the signature are all sized by an enumerated value in one of
the two configuration bytes. Parse order is therefore constrained; see NanoTDF-CORE §2.2.

## Status and source

The suite is an alpha draft. Its normative source is the nanotdf version 1
specification, whose magic number and version serialize as `4c 31 4c`, ASCII `L1L`. The
version count starts at 12 as an artifact of the original design, so every version below
12 is invalid by construction.

The two worked examples in NanoTDF-EX are reproduced from the source and have been
verified: each decodes to the stated byte count, and every field offset and section
length reconciles.

There are no extension, profile, or migration documents in this suite. NanoTDF version 1
defines no extension mechanism, so a new capability requires a new format version.

## License

This specification is licensed under the repository's license terms.
