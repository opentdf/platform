# BaseTDF Specification Suite — Version 4.4.0

The BaseTDF suite is a collection of focused specifications that together define
the Trusted Data Format (TDF) for data-centric security. Inspired by the JOSE
RFC factoring (JWA/JWK/JWS/JWE/JWT), the suite separates concerns so that
cryptographic algorithms, key management, access control, integrity, and
container format can each evolve independently.

## Document Overview

| Layer | Document | Title | File |
|-------|----------|-------|------|
| **Foundation** | BaseTDF-SEC | Security Model & Zero Trust | [basetdf-sec.md](basetdf-sec.md) |
| **Foundation** | BaseTDF-ALG | Algorithm Registry | [basetdf-alg.md](basetdf-alg.md) |
| **Policy** | BaseTDF-POL | Policy & Attribute-Based Access Control | [basetdf-pol.md](basetdf-pol.md) |
| **Policy** | BaseTDF-KAS | Key Access Service Protocol | [basetdf-kas.md](basetdf-kas.md) |
| **Operations** | BaseTDF-KAO | Key Access Object | [basetdf-kao.md](basetdf-kao.md) |
| **Operations** | BaseTDF-INT | Integrity Verification | [basetdf-int.md](basetdf-int.md) |
| **Operations** | BaseTDF-ASN | Assertions | [basetdf-asn.md](basetdf-asn.md) |
| **Application** | BaseTDF-CORE | Container Format & Manifest | [basetdf-core.md](basetdf-core.md) |
| **Informational** | BaseTDF-EX | Examples & Test Vectors | [basetdf-ex.md](basetdf-ex.md) |

## Architecture Layers

```
Layer 3: APPLICATION    BaseTDF-CORE    Container format & manifest
Layer 2: OPERATIONS     BaseTDF-KAO     Key access & protection
                        BaseTDF-INT     Integrity verification
                        BaseTDF-ASN     Assertions
Layer 1: POLICY         BaseTDF-POL     Policy & attribute-based access control
                        BaseTDF-KAS     Key Access Service protocol
Layer 0: FOUNDATION     BaseTDF-ALG     Algorithm registry
                        BaseTDF-SEC     Security model & zero trust
         INFORMATIONAL  BaseTDF-EX      Examples & test vectors
```

## Dependency Graph

```
         BaseTDF-CORE
        /    |    \    \
   KAO     INT    ASN   POL
     \      |     /     /
      BaseTDF-ALG      /
        \    |        /
      BaseTDF-KAS    /
          \    \    /
         BaseTDF-SEC
```

**Reading this graph**: An arrow from A to B means "A depends on B." To understand
any document, you should first be familiar with the documents it depends on.

## Recommended Reading Order

1. **BaseTDF-SEC** — Start here. Establishes the threat model, security invariants,
   and zero trust principles that all other documents reference.
2. **BaseTDF-ALG** — Algorithm identifiers and parameters. Required to understand
   the `alg` fields used throughout the suite.
3. **BaseTDF-POL** — Policy structure and ABAC evaluation. Defines what is being
   protected and the access rules.
4. **BaseTDF-KAO** — How encryption keys are protected, split, and bound to policy.
5. **BaseTDF-INT** — Payload integrity verification (segments, hashes, root signature).
6. **BaseTDF-ASN** — Optional verifiable assertions bound to TDFs.
7. **BaseTDF-KAS** — Wire protocol for the Key Access Service.
8. **BaseTDF-CORE** — Container format tying everything together.
9. **BaseTDF-EX** — Worked examples and test vectors for implementers.

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 4.4.0 | 2025-02 | Suite factoring, PQC algorithms, formal security model |
| 4.3.0 | — | Previous monolithic specification |

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in these
documents are to be interpreted as described in [BCP 14][rfc2119] [RFC 8174][rfc8174]
when, and only when, they appear in ALL CAPITALS, as shown here.

[rfc2119]: https://www.rfc-editor.org/rfc/rfc2119
[rfc8174]: https://www.rfc-editor.org/rfc/rfc8174

## JSON Schemas

Machine-readable schemas for validation are available in
[`../schema/BaseTDF/`](../schema/BaseTDF/):

- `manifest.schema.json` — Full v4.4.0 manifest
- `kao.schema.json` — Key Access Object
- `policy.schema.json` — Policy object

## License

This specification is part of the OpenTDF project and is licensed under the
same terms as the parent repository.
