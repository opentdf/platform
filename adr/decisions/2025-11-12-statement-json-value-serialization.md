# ADR: Statement.Value Must Be JSON String When Statement.Format is "json"

- Status: proposed
- Date: 2025-11-12

## Context and Problem Statement

OpenTDF manifests (TDF) include policy statements that carry a `Format` and a `Value`. We observed ambiguity and cross-SDK inconsistencies when `Statement.Format == "json"` and the `Value` field is embedded as structured JSON (object/array) versus a JSON string.

Problems encountered:
- Variation across producers: some SDKs serialized `Value` as an object/array, others as a JSON-encoded string.
- Parsing ambiguity for consumers/validators, especially in streaming or schema-less contexts.
- Interop breaks when signing/binding is performed over different canonical byte representations.

We need a single, cross-SDK rule to serialize `Statement.Value` for the `"json"` format to ensure deterministic manifests and stable cryptographic bindings.

## Decision

When `Statement.Format` is `"json"`, the `Statement.Value` MUST be serialized as a JSON string containing the JSON document.

- Producers MUST JSON-encode the structured value into a string and place that string in `Statement.Value`.
- Consumers MUST treat the `Statement.Value` as a JSON string and, when needed, decode it once to obtain the structured JSON value.
- This rule applies uniformly across SDKs (Go, Java, JavaScript) and any other producer/consumer of TDF manifests.
- Security preference: The string representation is preferred for security because it yields a stable byte sequence for signatures/bindings and avoids parser differential, whitespace, and key-ordering issues that can be exploited or cause verification drift.

### Example

Given this structured value:
```json
{ "roles": ["analyst", "reviewer"], "exp": 1734043200 }
```
Producers must serialize the statement as:
```json
{
  "Format": "json",
  "Value": "{\"roles\":[\"analyst\",\"reviewer\"],\"exp\":1734043200}"
}
```
Consumers can parse with a single JSON-unquote step before processing.

## Rationale

- Determinism: A single representation (string) removes ambiguity and makes cryptographic hashes/bindings stable across SDKs and platforms.
- Backward compatibility: Existing manifests that already embed a JSON string remain valid; manifests embedding raw objects may still be read by tolerant parsers, but new producers standardize on string form.
- Simplicity at boundaries: Treating `Value` as an opaque JSON document avoids partial structural merging or schema drift.
- Safety: Avoids differences from pretty-printing, key ordering, or whitespace introduced when objects are embedded directly; producers are responsible for a single canonical encoding step.

## Considered Options

1. Allow `Statement.Value` to be either a JSON string or a raw JSON object/array when `Format == "json"`.
2. Require `Statement.Value` to be the raw JSON object/array when `Format == "json"`.
3. Require `Statement.Value` to always be a JSON string containing the JSON document (CHOSEN).

### Option 1: Dual representation
- Pros: Flexible; fewer changes for some producers.
- Cons: Ambiguity; non-deterministic bindings; complicates validators; cross-SDK differences persist.

### Option 2: Raw object/array only
- Pros: Natural JSON shape; fewer unescape steps for consumers.
- Cons: Canonicalization and whitespace/ordering issues make bindings brittle; harder to keep byte-identical across languages; increases breakage risk.

### Option 3: JSON string only (CHOSEN)
- Pros: Deterministic; straightforward to sign/bind; consistent across SDKs.
- Cons: Requires an extra encode/decode step at edges; slightly less ergonomic for consumers.

## Implications

- Producers (SDKs, services) must update serialization logic where necessary to ensure JSON-string form when `Format == "json"`.
- Consumers must decode the string when they need structured access; otherwise they may treat the value as opaque text.
- Signing/verification: Bindings and hashes must operate on the exact byte sequence of the JSON string stored in `Value`.
- Documentation: Update examples and developer guides to reflect this rule.

## Compatibility and Migration

- Existing manifests with `Format == "json"` and a string `Value` continue to work unchanged.
- For manifests embedding a raw object/array, consumers SHOULD continue to parse leniently for backward compatibility where feasible, but producers MUST NOT generate new manifests in that form.
- Across SDKs, provide helper utilities for encode/decode to reduce duplication and prevent double-encoding.

## Test and Verification Guidance

- Add tests that:
  - Ensure producers emit a JSON string when `Format == "json"`.
  - Verify consumers perform exactly one decode step to reconstruct the object.
  - Confirm cryptographic binding inputs are computed over the byte content of the stored string.

## References

- OpenTDF Specification (pending note update to add this rule)
- Related ADRs: 2025-10-16-custom-assertion-providers.md (assertion binding/verification and manifest format considerations)
