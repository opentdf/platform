# BaseTDF Specification Suite — Version 5.0.0

The BaseTDF suite defines the Trusted Data Format (TDF) for data-centric security.
Version 5 separates the logical TDF manifest from physical packaging and adds
integrity layouts suitable for very large, streamed, distributed, detached, and
randomly accessed payloads.

BaseTDF 5.0 is a breaking wire-format release. Version 4 objects remain readable by
a 5.0 implementation, but a 4.x reader is expected to reject a 5.0 manifest.

## Document Overview

| Layer | Document | Title | File |
|---|---|---|---|
| Foundation | BaseTDF-SEC | Security Model and Zero Trust Architecture | [basetdf-sec.md](basetdf-sec.md) |
| Foundation | BaseTDF-ALG | Algorithm Registry | [basetdf-alg.md](basetdf-alg.md) |
| Policy | BaseTDF-POL | Policy and Attribute-Based Access Control | [basetdf-pol.md](basetdf-pol.md) |
| Policy | BaseTDF-KAS | Key Access Service Protocol | [basetdf-kas.md](basetdf-kas.md) |
| Operations | BaseTDF-KAO | Key Access Object | [basetdf-kao.md](basetdf-kao.md) |
| Operations | BaseTDF-INT | Integrity Verification and Scalable Layouts | [basetdf-int.md](basetdf-int.md) |
| Operations | BaseTDF-ASN | Assertions and Manifest Signatures | [basetdf-asn.md](basetdf-asn.md) |
| Storage | BaseTDF-LOC | Resource Locators and Fetch Policy | [basetdf-loc.md](basetdf-loc.md) |
| Storage | BaseTDF-PKG | Packaging Profiles | [basetdf-pkg.md](basetdf-pkg.md) |
| Assembly | BaseTDF-CORE | Manifest and End-to-End Processing | [basetdf-core.md](basetdf-core.md) |
| Examples | BaseTDF-EX | Examples and Test Vectors | [basetdf-ex.md](basetdf-ex.md) |

## Architecture

SEC defines security invariants and ALG defines identifiers. POL, KAS, and KAO
retain the 4.4 policy and key-access model. INT defines segmentation, explicit and
Merkle layouts, proofs, and key derivation. ASN defines assertions and public-key
manifest signatures. LOC constrains external retrieval. PKG defines attached,
detached, and sharded serializations. CORE binds the suite together.

```text
SEC ──► ALG ──► KAO, INT, ASN
 │              ▲
 ├──► POL ──────┤
 ├──► KAS ◄─────┘
 └──► LOC

KAO, INT, ASN, LOC ──► PKG
SEC, ALG, POL, KAO, KAS, INT, ASN, LOC, PKG ──► CORE ──► EX
```

## Recommended Reading Order

1. [SEC](basetdf-sec.md) and [ALG](basetdf-alg.md)
2. [POL](basetdf-pol.md), [KAO](basetdf-kao.md), and [KAS](basetdf-kas.md)
3. [INT](basetdf-int.md) and [ASN](basetdf-asn.md)
4. [LOC](basetdf-loc.md) and [PKG](basetdf-pkg.md)
5. [CORE](basetdf-core.md) and [EX](basetdf-ex.md)

## Version 5 Scope

Version 5 adds packaging profiles, scalable Merkle layouts, partition-scoped keys,
deterministic segment IVs, manifest signatures, safe locators, multi-manifest
semantics, and append consistency proofs. BaseTDF-KAO, BaseTDF-POL, and BaseTDF-KAS
are frozen at their 4.4 semantics. Policy-language, KAS-protocol, and new
post-quantum work are outside the 5.0 charter.

## Conventions

BCP 14 requirement terms are normative only when written in all capitals. Unless
specified otherwise, cryptographic integers are unsigned 64-bit big-endian values,
`||` means concatenation, and JSON binary values use standard padded base64.

## JSON Schemas

The suite prose is authoritative. Implementations SHOULD also validate against the
version 5 schema when published under [`spec/schema/BaseTDF/`](../../schema/BaseTDF/).

## License

This specification is licensed under the repository's license terms.
