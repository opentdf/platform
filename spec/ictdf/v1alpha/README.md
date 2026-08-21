# IC-TDF Specification Suite — Version 1 Alpha

IC-TDF is the Intelligence Community XML encoding of the Trusted Data Format. An IC-TDF
instance binds handling metadata, discovery and mission metadata, and one payload into a
single XML document whose parts may be cryptographically bound to one another and
individually encrypted.

This suite reorganizes the *XML Data Encoding Specification for Trusted Data Format*,
version 2014-DEC-r2017-JUL, into components aligned with the BaseTDF 5 architecture. The
refactoring changes document ownership, not the XML vocabulary, the schema, the
controlled vocabularies, the Schematron constraint rules, or the validation semantics.
The source DES, its XSD, its CVEs, and its 49 constraint rules remain the authority for
every requirement restated here.

## Core modules

| Layer | Document | Responsibility | File |
|---|---|---|---|
| Foundation | ICTDF-SEC | Security model and validation hazards | [ictdf-sec.md](ictdf-sec.md) |
| Foundation | ICTDF-ALG | Algorithm, vocabulary, and normalization registries | [ictdf-alg.md](ictdf-alg.md) |
| Model | ICTDF-MTD | Assertions, statements, and statement metadata | [ictdf-mtd.md](ictdf-mtd.md) |
| Model | ICTDF-SCP | Assertion scope, transitivity, and extraction | [ictdf-scp.md](ictdf-scp.md) |
| Policy | ICTDF-POL | Handling assertions and access policy | [ictdf-pol.md](ictdf-pol.md) |
| Operations | ICTDF-BND | Cryptographic binding and signature coverage | [ictdf-bnd.md](ictdf-bnd.md) |
| Operations | ICTDF-KAO | Key access and encryption method | [ictdf-kao.md](ictdf-kao.md) |
| Operations | ICTDF-KAS | Key retrieval and policy decision interfaces | [ictdf-kas.md](ictdf-kas.md) |
| Operations | ICTDF-PAY | Payload carriage | [ictdf-pay.md](ictdf-pay.md) |
| Storage | ICTDF-LOC | External references and fetch policy | [ictdf-loc.md](ictdf-loc.md) |
| Storage | ICTDF-PKG | XML serialization and document order | [ictdf-pkg.md](ictdf-pkg.md) |
| Schema | ICTDF-SCH | Schema, controlled vocabularies, and constraint rules | [ictdf-sch.md](ictdf-sch.md) |
| Assembly | ICTDF-VAL | Conformance validation procedure | [ictdf-val.md](ictdf-val.md) |
| Assembly | ICTDF-CORE | Object model and end-to-end processing | [ictdf-core.md](ictdf-core.md) |
| Examples | ICTDF-EX | Worked examples | [ictdf-ex.md](ictdf-ex.md) |

## Profiles and guides

| Kind | Document | Extends | File |
|---|---|---|---|
| Profile | ICTDF-OPENTDF | POL, KAO, KAS, and BND | [ictdf-profile-opentdf.md](ictdf-profile-opentdf.md) |
| Guide | ICTDF-MIG | CORE, POL, KAO, and PAY | [ictdf-migration.md](ictdf-migration.md) |

## Architecture

Arrows point from prerequisites to consumers.

```text
SEC ──► ALG, MTD, SCP, POL, BND, KAO, PAY, LOC, PKG
ALG ──► MTD, BND, KAO
MTD, SCP ──► POL, BND
POL, KAO ──► KAS
KAO ──► PAY
LOC ──► PAY, KAO
MTD, SCP, POL, BND, KAO, PAY, LOC ──► PKG ──► SCH ──► VAL

SEC, ALG, MTD, SCP, POL, BND, KAO, KAS, PAY, LOC, PKG, SCH, VAL ──► CORE ──► EX

POL, KAO, KAS, BND ──► OPENTDF
CORE, POL, KAO, PAY ──► MIG
```

## Alignment with BaseTDF 5

The suites use the same names for shared responsibilities: SEC, ALG, POL, KAO, KAS, LOC,
PKG, CORE, and EX. ICTDF-MTD and ICTDF-SCP split what BaseTDF-ASN calls assertions into the
metadata carrier and the scope algebra, because IC-TDF scope is a first-class processing
instruction rather than a property of one assertion. ICTDF-BND covers the signature half of
BaseTDF-ASN.

Three documents have no BaseTDF counterpart. ICTDF-SCH exists because IC-TDF ships
normative artifacts — an XSD, three controlled vocabularies, and a Schematron rule set —
that BaseTDF states inline in each module. ICTDF-VAL exists because IC-TDF conformance is a
multi-pass procedure over foreign-namespace content rather than a single manifest check.
ICTDF-PAY exists because payload carriage in XML has attributes of its own; BaseTDF folds
the equivalent into CORE.

Going the other way, IC-TDF has no INT module: it defines no segmentation, no Merkle
layout, and no per-segment integrity, so payload integrity comes from the selected
encryption method and from binding coverage. These differences are format boundaries rather
than missing placeholder documents.

## Conventions

BCP 14 requirement terms are normative only when written in all capitals, matching the
source DES convention. Element and attribute names are written as they appear in the
`urn:us:gov:ic:tdf` namespace; the `tdf:` prefix is elided where context is unambiguous.
Constraint rules are cited by their source identifier, for example `IC-TDF-ID-00042`.
Attributes are written `@name`.

## Status and source

The suite is an alpha draft. Its normative source is the *XML Data Encoding Specification
for Trusted Data Format*, `IC-TDF.XML.V2014-DEC-r2017-JUL`, published by the Office of the
Director of National Intelligence, together with the `IC-TDF.xsd` schema, the IC-TDF
controlled vocabulary enumerations, and the `IC-TDF_XML.sch` Schematron rule set from the
same package. Where this suite and the source package disagree, the source package wins.

The source distribution notice reads: "This document has been approved for Public Release
and is available for use without restriction."

## License

This specification is licensed under the repository's license terms.
