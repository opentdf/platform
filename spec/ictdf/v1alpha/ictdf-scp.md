# ICTDF-SCP: Assertion Scope

| | |
|---|---|
| Document | ICTDF-SCP |
| Version | 1 Alpha |
| Source spec | IC-TDF.XML.V2014-DEC-r2017-JUL |
| TDF version | 201412.201707 |
| Status | Draft |
| Depends on | ICTDF-SEC, ICTDF-MTD |
| Referenced by | ICTDF-POL, ICTDF-BND, ICTDF-VAL, ICTDF-CORE |

## 1. Purpose

`@tdf:scope` states what an assertion is about. Scope is the mechanism that lets one
document carry a marking for the payload, a different marking for the whole object, and
further markings for each member of a collection, without ambiguity about which applies to
what. Scope also determines what a binding over that assertion covers, so a scope error is
a security error, not a labeling error.

Scope is required on both `tdf:HandlingAssertion` and `tdf:Assertion`.

## 2. Scope values

| Value | Valid in | Transitive | Covers |
|---|---|---|---|
| `PAYL` | TDO | — | The payload only |
| `TDO` | TDO | — | Every element of the TDO other than the assertion itself |
| `TDC` | TDC | No | Every element of the collection, taken collectively |
| `TDC_MEMBER` | TDC | No | Each member of the collection, but not peer assertions |
| `DESC_TDO` | TDC | Yes | Every descendant TDO |
| `DESC_PAYL` | TDC | Yes | The payload of every descendant TDO |
| `EXPLICIT` | TDO, TDC | — | Only what a `BoundValueList` or `ReferenceList` enumerates |

An assertion inside a TDO MUST use `PAYL`, `TDO`, or `EXPLICIT` (`IC-TDF-ID-00006`). An
assertion inside a TDC MUST use `TDC`, `TDC_MEMBER`, `DESC_TDO`, `DESC_PAYL`, or
`EXPLICIT` (`IC-TDF-ID-00007`). A handling assertion inside a TDC MUST use `TDC`
(`IC-TDF-ID-00035`).

`EXPLICIT` is reserved. It is not permitted in this version (`IC-TDF-ID-00008`), and
neither are the `BoundValueList` and `ReferenceList` structures it would depend on
(`IC-TDF-ID-00013`). See §6.

## 3. Transitivity

A **non-transitive** scope applies to the level at which it is declared and does not
descend into nested collections. A **transitive** scope applies at every depth beneath the
declaring collection.

A **collection member** is a direct `TrustedDataObject` or `TrustedDataCollection` child of
a TDC. A **descendant** is a member, or a member of a member, at any depth.

```text
TDC-A
├── Assertion @scope="TDC"          → all of TDC-A, collectively; stops here
├── Assertion @scope="TDC_MEMBER"   → TDO-1 and TDC-B individually; stops here
├── Assertion @scope="DESC_TDO"     → TDO-1, TDO-2, TDO-3
├── Assertion @scope="DESC_PAYL"    → payloads of TDO-1, TDO-2, TDO-3
├── TDO-1
└── TDC-B
    ├── TDO-2
    └── TDO-3
```

`TDC` and `TDC_MEMBER` differ in what they treat as the unit. `TDC` describes the
collection as a single thing — the aggregate. `TDC_MEMBER` describes each member
separately and deliberately excludes the collection's own peer assertions, so a member's
marking is not contaminated by metadata that belongs to the container.

## 4. Scope under extraction

Extracting a TDO or a nested TDC from its enclosing collection changes the frame of
reference. Transitive assertions travel with the extracted content, and their scope is
rewritten so that they continue to mean the same thing.

| Original scope | Extracted into a TDO | Extracted into a TDC |
|---|---|---|
| `DESC_TDO` | becomes `TDO` | stays `DESC_TDO` |
| `DESC_PAYL` | becomes `PAYL` | stays `DESC_PAYL` |
| `TDC` | not carried | not carried |
| `TDC_MEMBER` | not carried | not carried |

Non-transitive scopes are not carried because they describe the container, which no longer
exists in the extracted result.

An extractor MUST also copy the dependent-specification version declarations that the
extracted content inherited from its enclosing TDF (ICTDF-MTD §5.1), and MUST re-evaluate
rollup for the resulting object (ICTDF-POL §4). A rewritten scope invalidates any binding
that covered the assertion in its original form; the extracted object needs a new binding
or none.

## 5. Required assertions by container

### 5.1 TDO

A conforming TDO has at least two handling assertions:

- exactly one with `@scope="TDO"` containing an IC-EDH (`IC-TDF-ID-00004`); and
- at least one with `@scope="PAYL"` (`IC-TDF-ID-00003`).

The first handling assertion in document order MUST be the `TDO`-scope one and MUST
contain an EDH (`IC-TDF-ID-00042`). An unencrypted payload has at most one `PAYL` handling
assertion containing an EDH (`IC-TDF-ID-00055`); an encrypted payload has exactly two, one
per data state (`IC-TDF-ID-00026`).

### 5.2 TDC

A conforming TDC has exactly one handling assertion with `@scope="TDC"` containing an
IC-EDH (`IC-TDF-ID-00005`), and it MUST be first in document order (`IC-TDF-ID-00042`). A
TDC MAY carry a second handling assertion carrying a revision recall statement, also at
`TDC` scope. It carries no other handling assertions.

Ordinary assertions at `TDC`, `TDC_MEMBER`, `DESC_TDO`, or `DESC_PAYL` scope are optional
and unbounded.

## 6. Reserved: explicit scope

`EXPLICIT` scope is defined so that an assertion can name exactly the elements it
describes, rather than deriving them from position. It depends on one of:

- a `BoundValueList`, whose `BoundValue` children each carry an `@idRef` and a hash of the
  referenced element; or
- a `ReferenceList`, whose `Reference` children each carry an `@idRef` and no hash.

Both structures and the scope itself are disallowed in this version
(`IC-TDF-ID-00008`, `IC-TDF-ID-00012`, `IC-TDF-ID-00013`). An `EXPLICIT`-scope assertion
that reaches a validator is a rejection. The schema admits them so that a future revision
can enable them without a namespace change; ICTDF-BND §6 records the intended signature
semantics.

Producers MUST NOT emit `EXPLICIT` scope, `BoundValueList`, or `ReferenceList`. Consumers
MUST reject them rather than treating them as unrecognized extensions.
