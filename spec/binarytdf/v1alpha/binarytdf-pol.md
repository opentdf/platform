# BinaryTDF-POL: Canonical Policy

| | |
|---|---|
| Document | BinaryTDF-POL |
| Version | 1 Alpha |
| Source draft | 0.2 |
| Frame version | 2 |
| Status | Draft |
| Depends on | BinaryTDF-CORE |
| Referenced by | BinaryTDF-REC, BinaryTDF-KAO, BinaryTDF-KAS, BinaryTDF-CDDL, BinaryTDF-NATO |

## 1. Data model

Policy is a sorted array. Each entry contains one namespace, one attribute, and one or
more values:

```text
[
  ["example.com", "classification", ["confidential"]],
  ["example.com", "region", ["us", "uk"]]
]
```

A namespace is the lowercase ASCII DNS name controlled by the organization defining
its attributes. It is an identifier, not a URL, and MUST NOT include a scheme, port,
path, query, fragment, or trailing dot.

For OpenTDF interoperability:

```text
["example.com", "classification", ["confidential"]]
```

represents:

```text
https://example.com/attr/classification/value/confidential
```

The `https` scheme and fixed path segments are not serialized.

## 2. Canonicalization

Namespace, attribute, and value strings MUST be non-empty. Each namespace/attribute
pair MUST appear exactly once, and every value in an entry MUST be unique. Entries are
sorted by namespace and attribute; values are sorted within each entry. Comparisons
use lexicographic UTF-8 bytes. No Unicode normalization is performed.

Producers create canonical form before encoding. Receivers MUST reject empty entries,
duplicates, and incorrect ordering; they MUST NOT silently merge or normalize policy.

An absent policy means public access. Producers MUST omit `policy` for public objects;
an explicit empty policy is not another public-policy encoding. A registered recovery
scheme may define different absence semantics for its own objects but MUST NOT create a
second encoding for an existing meaning.

## 3. Metadata mapping

Metadata does not become policy by being carried. A mapping from an external label or
metadata schema to Canonical Policy MUST be explicit, deterministic, and defined by a
separate specification or profile. The producer applies that mapping at creation; KAS
authorizes against Canonical Policy.

## 4. CDDL

```cddl
policy-entry = [
  namespace: policy-namespace,
  attribute: tstr,
  values: [+ tstr]
]

policy-namespace = tstr

canonical-policy = [+ policy-entry]
```
