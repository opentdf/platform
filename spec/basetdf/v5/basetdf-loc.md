# BaseTDF-LOC: Resource Locators and Fetch Policy

| | |
|---|---|
| **Document** | BaseTDF-LOC |
| **Version** | 5.0.0 |
| **Status** | Standards Track |
| **Date** | 2026-08 |
| **Depends on** | BaseTDF-SEC, BaseTDF-ASN |
| **Referenced by** | BaseTDF-PKG, BaseTDF-CORE, BaseTDF-INT |

## 1. Introduction

BaseTDF 5 permits payload and integrity artifacts to be stored separately from a
manifest. A locator is attacker-influenced input to a network client and creates
SSRF, redirect, resource-exhaustion, and confused-deputy risks. This document
defines locator syntax and default-deny resolution. It does not define discovery,
object-store credentials, or a catalog service.

## 2. Locator Object

```json
{"uri": "https://payload.example/objects/9f2a", "priority": 0,
 "size": 1073756160}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `uri` | string | REQUIRED | Absolute resource URI, except the reserved attached URI in Section 3.4. |
| `priority` | non-negative integer | OPTIONAL | Lower values are preferred; default `0`. |
| `size` | non-negative integer | OPTIONAL | Exact resource size in bytes. |

Locator arrays MUST NOT be empty and writers MUST order them by ascending priority.
Equal-priority locators retain array order. A reader MAY try the next allowed
locator after failure but MUST NOT use a disallowed locator as fallback.

Security policy MUST be evaluated against a standards-compliant parsed URI, not a
substring or suffix match on the source text.

## 3. Schemes and Origins

### 3.1 Network schemes

The default enabled network scheme is `https`. Object-store schemes such as `s3`,
`gs`, or `az` MAY be supported only when explicitly enabled. Plain `http`, `file`,
`data`, and process-launching schemes MUST be disabled by default.

For HTTP, an origin is `(scheme, host, effective-port)`. Matching MUST compare the
complete normalized host and port. `example.com` MUST NOT match
`example.com.attacker.invalid`. Wildcards, if supported, MUST match whole DNS labels
and MUST NOT match a public suffix. Object-store resolvers MUST document how account,
bucket, container, region, and endpoint form an origin.

### 3.2 Credentials

Credentials MUST be scoped to the approved origin. Authorization headers, cookies,
signed query parameters, and object-store credentials MUST NOT be forwarded to a
different origin after redirect or failover. URI userinfo MUST be rejected.

### 3.3 Network addresses

Implementations able to enforce address policy SHOULD reject loopback, link-local,
multicast, unspecified, and deployment-denied private addresses after DNS
resolution. They SHOULD repeat the check for every connection to resist DNS
rebinding. Address checks supplement, not replace, origin allowlisting.

### 3.4 Attached URI

`zip:0.integrity` is reserved for the `0.integrity` entry of the currently open
attached package. It is not a network locator. No other `zip:` URI is defined.

## 4. Resolver Policy

Before dereferencing any external locator, a reader MUST:

1. parse and structurally validate the complete manifest;
2. verify the BaseTDF-ASN manifest signature with a publisher key trusted by local
   policy;
3. validate scheme and origin against explicit resolver configuration;
4. validate declared sizes and ranges against safety limits; and
5. bind credentials to the approved origin.

The default MUST be deny. An empty allowlist permits no external fetch. Arbitrary
origins supplied by a manifest MUST NOT be accepted.

### 4.1 Redirects

Redirects MUST be disabled or all scheme, origin, address, credential, and size
checks MUST be reapplied at each hop. A redirect to a non-allowlisted origin MUST be
rejected. Implementations MUST impose a finite hop limit.

### 4.2 Size and range enforcement

Resolvers MUST enforce the locator size, enclosing payload/part/tree size,
authenticated `encryptedSize`, and local request/object limits. A full response
must exactly match an exact declared size. A range response MUST match the requested
range and stay within the resource. If a server ignores a range, the reader MUST
stop at its bound rather than consume an unbounded full object.

Routing metadata may direct only bounded reads. BaseTDF-INT MUST authenticate the
selected leaf, proof, counts, sizes, root, and actual ciphertext before plaintext is
released.

### 4.3 Fail closed

URI parse failures, disallowed origins, redirects, size mismatches, short reads,
proof failures, and payload-integrity failures MUST fail closed. Errors MUST NOT
expose credentials or key material.

## 5. Host Separation

A detached payload intentionally carries no manifest back-pointer. Discovery is an
application concern so the payload host does not learn the metadata location. The
manifest signature authenticates publisher provenance and locator selection. The
DEK-keyed root remains the authoritative binding to ciphertext.

## 6. Conformance and Security

A conformant resolver MUST be deny-by-default, verify the manifest before fetch,
revalidate or disable redirects, enforce exact sizes and bounded ranges, and test
off-allowlist, disabled-scheme, cross-origin redirect, and oversized-response cases.

Signed locators remain subject to local policy because a publisher can be
compromised. Timing and network metadata may correlate separate manifest and
payload fetches. Mirrors improve availability, not integrity.

## 7. Normative References

- [BaseTDF-ASN](basetdf-asn.md)
- [BaseTDF-INT](basetdf-int.md)
- [BaseTDF-SEC](basetdf-sec.md)
- RFC 3986, URI Generic Syntax
- RFC 8785, JSON Canonicalization Scheme
- RFC 9110, HTTP Semantics

