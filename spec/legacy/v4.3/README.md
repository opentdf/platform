# BaseTDF Specification v4.3.0 (Legacy)

> **Note**: This is the **legacy v4.3.0** specification in its original monolithic
> format. It is retained here for historical reference and to support
> implementations that have not yet migrated to the current version.

## Current Specification

The current version of the BaseTDF specification is **v4.4.0**, organized as a
suite of focused documents. See the [BaseTDF Suite](../../basetdf/) for the
current specification.

## v4.3 JSON Schema

The v4.3.0 manifest JSON schema is located at:

- [`sdk/schema/manifest.schema.json`](../../../sdk/schema/manifest.schema.json) — Strict validation schema
- [`sdk/schema/manifest-lax.schema.json`](../../../sdk/schema/manifest-lax.schema.json) — Permissive validation schema

These schemas reflect the monolithic manifest structure used in v4.3.0, where the
entire TDF manifest (payload, key access objects, policy, integrity information,
and assertions) was defined in a single schema file.

## What Changed in v4.4.0

The v4.4.0 specification introduced:

- **Suite factoring** — The monolithic specification was split into 9 focused
  documents (BaseTDF-SEC, BaseTDF-ALG, BaseTDF-CORE, BaseTDF-KAO, BaseTDF-INT,
  BaseTDF-POL, BaseTDF-KAS, BaseTDF-ASN, BaseTDF-EX), inspired by the JOSE RFC
  factoring (JWA/JWK/JWS/JWE/JWT).
- **Post-quantum cryptography** — Addition of ML-KEM and ML-DSA algorithm
  families to the algorithm registry.
- **Formal security model** — A dedicated security document (BaseTDF-SEC) with
  threat analysis and zero trust alignment.
- **Separated JSON schemas** — Individual schemas for the manifest, key access
  object, and policy (located in `spec/schema/BaseTDF/`).

## Migration

Implementations targeting v4.3.0 manifests remain compatible with v4.4.0. The
wire format is backward-compatible; the specification refactoring is primarily
organizational. New features (PQC algorithms, hybrid key wrapping) are additive
and do not break existing v4.3.0 consumers.
