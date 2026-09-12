# ICTDF-LOC: External References and Fetch Policy

| | |
|---|---|
| Document | ICTDF-LOC |
| Version | 1 Alpha |
| Source spec | IC-TDF.XML.V2014-DEC-r2017-JUL |
| TDF version | 201412.201707 |
| Status | Draft |
| Depends on | ICTDF-SEC |
| Referenced by | ICTDF-PAY, ICTDF-KAO, ICTDF-KAS, ICTDF-VAL, ICTDF-CORE |

## 1. Where references appear

An IC-TDF document names four kinds of thing that live outside it.

| Reference | Names | Resolved by |
|---|---|---|
| `ReferenceValuePayload/@uri` | Payload content | Consumer, after validation |
| `ReferenceStatement/@uri` | Statement content | Consumer, after validation |
| `RemoteStoredKey/@uri` | A key, via `@protocol` | Key retrieval (ICTDF-KAS §2) |
| `edh:ExternalEdh`, `arh:ExternalSecurity` | A marking held elsewhere | Marking resolution |
| `PreSharedKey/@alias`, `@store` | A key in an out-of-band arrangement | Local keystore |

The last two are not URIs but are references in the same sense: the document names
something it does not contain.

## 2. External markings

An external marking is not a weaker marking. It is a marking that is deliberately not
stated in this document, for one of two reasons:

- the marked content is not here, so there is nothing to mark in place — a
  `ReferenceValuePayload` or `ReferenceStatement`; or
- stating it here would disclose it — the `unencrypted` marking of an encrypted part,
  which would otherwise raise the object's rolled-up classification (ICTDF-POL §5).

Where external markings are required:

| Situation | Required | Rule |
|---|---|---|
| Payload is a `ReferenceValuePayload` | `edh:ExternalEdh` in the `PAYL` handling assertion | `IC-TDF-ID-00033` |
| Statement is a `ReferenceStatement` | `edh:ExternalEdh` or `arh:ExternalSecurity` in `StatementMetadata` | `IC-TDF-ID-00034` |
| Payload is encrypted | `edh:ExternalEdh` in the `unencrypted` `PAYL` handling assertion | `IC-TDF-ID-00027` |
| Statement is encrypted | `arh:ExternalSecurity` in the `unencrypted` `StatementMetadata` | `IC-TDF-ID-00030` |

Object-scope handling assertions are the exception: a `TDO`- or `TDC`-scope handling
assertion MUST NOT use `edh:ExternalEdh` (`IC-TDF-ID-00018`, `IC-TDF-ID-00019`). The
object's own marking is always present in the object, so that a guard can act on the
document alone.

## 3. Linked versus embedded

A linked resource's classification does not raise the linking TDO's classification. An
embedded resource's does.

This distinction is what makes references useful: a low-classification object can point at
higher-classification content without itself becoming high. It also means that resolving a
reference and inlining the result is not a neutral transformation — it changes the object's
marking obligations, requires recomputed rollup (ICTDF-POL §4), and invalidates any binding
that covered the payload.

An intermediary MUST NOT inline a reference on a consumer's behalf.

## 4. Fetch policy

Resolution is a consumer action governed by deployment policy, never a validator action.

- A validator MUST NOT dereference any URI in the document. Doing so turns every malformed
  or hostile document into an outbound request, leaks the fact and timing of validation,
  and makes validation depend on network reachability.
- A consumer MUST resolve URIs through trusted local configuration — a catalog, an
  allow-list of authorities, or a service registry — rather than by scheme dispatch on the
  literal value.
- A consumer MUST NOT infer trust from the URI. Ownership of a name gives uniqueness, not
  authority; a document may name any URI.
- A consumer MUST bound redirects, response size, and time, and MUST apply the same parser
  limits to fetched content as to the document itself (ICTDF-SEC §1).
- Fetching leaks. The request discloses to the resolver, and to anyone observing, that a
  particular consumer holds a particular object. Where that matters, the deployment SHOULD
  proxy or prefetch.

## 5. Integrity of referenced content

The document does not authenticate what a reference points at.

- No binding can cover absent content. A binding whose scope includes a
  `ReferenceValuePayload` authenticates the URI and the surrounding structure, not the
  referent (ICTDF-PAY §3.4).
- There is no hash of referenced content in this version. `BoundValue` would have provided
  one for in-document elements, and it is reserved (ICTDF-BND §6); nothing covers external
  content at all.
- A consumer therefore MUST obtain integrity for fetched content from the transport, from a
  signature the referenced resource carries itself, or from the resolver's own guarantees,
  and MUST state which.
- Referenced content is mutable. Two consumers resolving the same object at different times
  may see different content, and the object gives no way to detect it.
- Where these properties are unacceptable, the content is embedded rather than referenced,
  and the object's markings and bindings are recomputed accordingly.
