# NanoTDF-LOC: Resource Locators and Fetch Policy

| | |
|---|---|
| Document | NanoTDF-LOC |
| Version | 1 Alpha |
| Source spec | nanotdf v1 |
| Format version | 12 (`L1L`) |
| Status | Draft |
| Depends on | NanoTDF-SEC |
| Referenced by | NanoTDF-PKG, NanoTDF-POL, NanoTDF-KAS, NanoTDF-CORE |

## 1. Structure

The Resource Locator is NanoTDF's single mechanism for naming something that lives
outside the object. It is deliberately smaller than a general URL: the scheme is an
enumerated byte rather than text, and the length is a single byte.

| Field | Minimum (B) | Maximum (B) |
|---|---:|---:|
| Protocol Enum | 1 | 1 |
| Body Length | 1 | 1 |
| Body | 1 | 255 |
| **Total** | **3** | **257** |

A Resource Locator appears in three places: the KAS reference in the header
(NanoTDF-KAS §1), the body of a remote policy (NanoTDF-POL §3), and the key reference
inside Policy Key Access (NanoTDF-KAO §4).

A body length of zero is invalid. A parser MUST reject a locator whose declared body
length exceeds the remaining input.

## 2. Protocol enumeration

| Value | Protocol |
|---|---|
| `0x00` | `http` |
| `0x01` | `https` |
| `0x02` | unreserved |
| `0xff` | Shared Resource Directory |

Any value not listed is unreserved. A client encountering an unreserved value MUST treat
the object as erroneous rather than guessing a scheme.

For `http` and `https`, the Body is everything following `://` in the equivalent URL.
The scheme, and the `://` separator, are not stored. A locator for
`https://kas.example.com/policy` therefore carries protocol `0x01`, body length `0x1d`,
and the 29 bytes `kas.example.com/policy`.

`http` is retained for compatibility with constrained deployments that terminate TLS
elsewhere. It SHOULD NOT be used: it exposes the KAS request, and with it the fact that a
particular party holds a particular object, to any observer.

### 2.1 Shared Resource Directory

Protocol `0xff` indicates that the body names an entry in a directory shared between
producer and consumer, rather than a network location. The intent is to shrink objects
further by replacing a repeated hostname with a short key.

The Shared Resource Directory is experimental. Version 1 defines no directory format, no
resolution procedure, and no failure behaviour, so an implementation cannot interoperate
on it. A client MUST reject protocol `0xff` unless the deployment has explicitly opted
in and supplied the resolution rules out of band.

## 3. Fetch policy

Resolving a locator is a consumer action governed by deployment policy. It is never a
parsing or validation action.

- A parser MUST NOT dereference any locator while decoding or validating an object.
  Doing so turns every malformed or hostile object into an outbound request, leaks the
  fact and timing of validation, and makes validation depend on network reachability.
- A consumer MUST resolve a locator through trusted local configuration — an allow-list,
  a catalog, or a service registry — rather than by dispatching on the literal body.
- A consumer MUST NOT infer trust from a locator. Ownership of a name gives uniqueness,
  not authority; an object may name any locator (NanoTDF-SEC §6).
- A consumer MUST bound redirects, response size, and elapsed time, and MUST apply the
  same parser limits to fetched content as to the object itself (NanoTDF-SEC §1).

## 4. Integrity of referenced content

The object does not authenticate what a locator points at.

For a remote policy, the policy binding covers the locator bytes, not the policy those
bytes name (NanoTDF-BND §2). A party who can control what the locator resolves to can
therefore change the effective policy without invalidating the binding. Remote policy
SHOULD be used only where the resolver is as trusted as the KAS itself.

Referenced content is mutable. Two consumers resolving the same object at different
times may see different policy, and the object provides no way to detect it. Where that
is unacceptable, use an embedded policy (NanoTDF-POL §4), whose bytes are covered by the
binding directly.

## 5. References

- [BCP 14](https://www.rfc-editor.org/info/bcp14)
- [RFC 3986: URI Generic Syntax](https://www.rfc-editor.org/rfc/rfc3986)
- [RFC 9110: HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110)
