# ICTDF-KAS: Key Retrieval and Policy Decision Interfaces

| | |
|---|---|
| Document | ICTDF-KAS |
| Version | 1 Alpha |
| Source spec | IC-TDF.XML.V2014-DEC-r2017-JUL |
| TDF version | 201412.201707 |
| Status | Draft |
| Depends on | ICTDF-SEC, ICTDF-POL, ICTDF-KAO |
| Referenced by | ICTDF-CORE, ICTDF-OPENTDF, ICTDF-MIG |

## 1. What IC-TDF defines and what it does not

IC-TDF defines **carriage** of key retrieval information. It does not define a key access
service, a wire protocol, a request or response format, an authentication mechanism, or a
policy language.

| Concern | Defined by IC-TDF |
|---|---|
| Where a remote key lives | Yes — `RemoteStoredKey/@uri` |
| Which protocol reaches it | Named only — `RemoteStoredKey/@protocol` |
| Request and response messages | No |
| Requester authentication | No |
| Policy language for a PDP | No — `EncryptedPolicyObject` is opaque |
| Audit and denial semantics | No |

Everything in the second column is a deployment or profile responsibility. This module
states the constraints IC-TDF does impose on whatever fills those gaps.
ICTDF-OPENTDF describes one concrete filling; ICTDF-MIG §5 compares it with the BaseTDF
key access service.

## 2. Remote stored keys

```text
RemoteStoredKey
  @protocol   required
  @uri        required
```

`@protocol` is an uncontrolled string. There is no IC-TDF registry of protocol names, so a
consumer MUST match it against a locally configured set and MUST reject an unrecognized
value rather than inferring one from the URI scheme.

`@uri` identifies the key. It is not a capability and not a trust statement:

- A consumer MUST resolve it through trusted local configuration — a catalog, an allow-list
  of authorities, or a service registry — and MUST NOT dereference an arbitrary URI found
  in a document (ICTDF-SEC §2, ICTDF-LOC §4).
- URI ownership gives uniqueness, not authority. A document can name any URI it likes.
- Resolution happens after validation, never during it. A validator that fetches keys turns
  every malformed document into an outbound request.

The retrieval exchange authenticates the requester and authorizes the release. IC-TDF
carries neither the requester's identity nor the decision; both live in the protocol.

## 3. Policy decision points

`WrappedPDPKey` differs from `WrappedKey` in what it wraps: an `EncryptedPolicyObject`
rather than a `KeyValue`.

```text
WrappedPDPKey
  EncryptedPolicyObject     base64Binary
  EncryptionInformation*
  @keyIdentifier            optional
```

The policy object is encrypted to a decision point, which is the only party that can read
it. A requester therefore cannot see the policy it must satisfy, and cannot obtain the key
by holding a certificate alone — the decision point evaluates the policy and releases the
key, or does not.

Requirements on a deployment using `WrappedPDPKey`:

- The policy object's content is opaque to IC-TDF. Its language, versioning, and evaluation
  semantics MUST be specified separately.
- The decision point MUST bind its decision to the object it was asked about. A policy
  object detached from its TDO and replayed against another proves nothing.
- The nested `EncryptionInformation` describes how the policy object was wrapped and
  follows ICTDF-KAO §3.2, including the requirement to bound nesting depth.
- Denials MUST be indistinguishable from key-recovery failures at the consumer
  (ICTDF-KAO §5). A distinguishable denial reveals policy content the encryption was
  meant to hide.

## 4. Relationship to handling assertions

A key access descriptor says how to get a key. A handling assertion says what controls
govern the data. They are separate, and the separation is deliberate.

- A key service MUST NOT treat the presence of a `RemoteStoredKey` pointing at it as
  authorization to release. Release is decided by evaluating the object's markings against
  the requester.
- The markings a decision uses MUST come from a source the decision point trusts. Reading
  them out of the requester's copy of the document is only sound if a binding over them
  verifies and the signer is trusted (ICTDF-BND §4).
- The TDO- or TDC-scope handling assertion is the rolled-up marking (ICTDF-POL §4) and is
  the correct input for a whole-object release decision. A `PAYL`-scope marking is the
  correct input for a payload-only release.
- `ntk:Access` rolled up into the object-scope handling assertion is what a decision point
  evaluates for need-to-know; it MUST NOT be reconstructed by walking the interior, because
  interior markings may be encrypted.

## 5. Non-goals

This suite does not define:

- rewrap, split-key, or threshold protocols;
- key rotation, revocation, or epoch handling;
- attribute or entitlement resolution for a requester; or
- a canonical policy representation.

A deployment needing any of these composes IC-TDF carriage with an external specification
and states the composition explicitly. Silently extending `@protocol` with locally
meaningful values is interoperable only within that deployment, and a document so produced
is not portable — a consumer elsewhere sees an unrecognized protocol and must reject it.
