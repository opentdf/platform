# OpenTDF Specification

This directory contains the specifications for the OpenTDF Trusted Data Format
and associated protocols.

## Current Version: 4.4.0

The specification is organized as the **BaseTDF Suite** — a collection of
focused documents inspired by the JOSE RFC factoring.

**[BaseTDF Suite →](basetdf/)**

### Quick Links

| Document | Description |
|----------|-------------|
| [BaseTDF-SEC](basetdf/basetdf-sec.md) | Security model, threat analysis, zero trust alignment |
| [BaseTDF-ALG](basetdf/basetdf-alg.md) | Algorithm registry (AES-GCM, RSA-OAEP, ECDH, ML-KEM, ML-DSA) |
| [BaseTDF-CORE](basetdf/basetdf-core.md) | Container format and manifest schema |
| [BaseTDF-KAO](basetdf/basetdf-kao.md) | Key Access Object — key protection and splitting |
| [BaseTDF-INT](basetdf/basetdf-int.md) | Integrity verification — segments and signatures |
| [BaseTDF-POL](basetdf/basetdf-pol.md) | Policy and attribute-based access control |
| [BaseTDF-KAS](basetdf/basetdf-kas.md) | Key Access Service protocol |
| [BaseTDF-ASN](basetdf/basetdf-asn.md) | Assertions — verifiable statements bound to TDFs |
| [BaseTDF-EX](basetdf/basetdf-ex.md) | Examples and test vectors |

### JSON Schemas

- [`schema/BaseTDF/manifest.schema.json`](schema/BaseTDF/manifest.schema.json)
- [`schema/BaseTDF/kao.schema.json`](schema/BaseTDF/kao.schema.json)
- [`schema/BaseTDF/policy.schema.json`](schema/BaseTDF/policy.schema.json)

## Previous Versions

- [v4.3 (legacy)](legacy/v4.3/) — Previous monolithic specification
