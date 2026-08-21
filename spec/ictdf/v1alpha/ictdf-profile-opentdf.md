# ICTDF-OPENTDF: OpenTDF Interoperability Profile

| | |
|---|---|
| Document | ICTDF-OPENTDF |
| Profile version | 0.1 |
| Source spec | IC-TDF.XML.V2014-DEC-r2017-JUL |
| TDF version | 201412.201707 |
| Status | Draft, optional |
| Depends on | ICTDF-SEC, ICTDF-POL, ICTDF-BND, ICTDF-KAO, ICTDF-KAS, ICTDF-SCH |

This profile constrains IC-TDF for deployments where an OpenTDF key access service holds
the keys. It narrows choices; it does not change the XML vocabulary, the schema, the
constraint rules, or the validation procedure. A document conforming to this profile is an
ordinary conforming IC-TDF document.

## 1. Purpose

IC-TDF leaves four things to the deployment: which encryption algorithms are acceptable,
which normalization method and signature algorithm are used, what `RemoteStoredKey/@protocol`
means, and how IC markings become an access decision (ICTDF-KAS §1). A document that
answers those questions differently from its consumer is valid and unusable.

This profile fixes all four for OpenTDF deployments and states the mapping from IC markings
to BaseTDF policy attributes.

## 2. Key access

### 2.1 Required form

An object under this profile uses `RemoteStoredKey` for every layer whose key is held by a
KAS:

```xml
<tdf:KeyAccess>
  <tdf:RemoteStoredKey tdf:protocol="kas" tdf:uri="https://kas.example.com"/>
</tdf:KeyAccess>
```

| Attribute | Value under this profile |
|---|---|
| `@tdf:protocol` | `kas` |
| `@tdf:uri` | The fully qualified KAS base URL, matching BaseTDF-KAO's `kas` field |

`@protocol="kas"` denotes the OpenTDF rewrap interface. It is not registered by IC-TDF; a
consumer outside an OpenTDF deployment sees an unrecognized protocol and MUST reject the
object (ICTDF-KAS §2). Producers MUST NOT rely on this profile for cross-community
interchange.

### 2.2 Prohibited forms

| Form | Status | Reason |
|---|---|---|
| `AttachedKey` | MUST NOT | Provides no confidentiality (ICTDF-KAO §3.6) |
| `PasswordKey` | MUST NOT | Carries no salt or work factor; not a KAS-mediated release |
| `PreSharedKey` | SHOULD NOT | Bypasses policy evaluation entirely |
| `WrappedKey` | MAY | Only where the wrapping key is itself reachable through a `RemoteStoredKey` |
| `WrappedPDPKey` | MAY | See §2.3 |

### 2.3 Policy decision keys

Where `WrappedPDPKey` is used, the `EncryptedPolicyObject` MUST contain a BaseTDF policy
object (BaseTDF-POL §2) — a JSON document with `uuid` and `body.dataAttributes` — encrypted
to the KAS. The KAS evaluates it as it would a policy from a BaseTDF manifest.

The KAS MUST bind its decision to the specific TDO. A policy object lifted from one object
and replayed against another proves nothing (ICTDF-KAS §3).

### 2.4 Splits

IC-TDF has no split identifier. `@sequenceNum` expresses layering, not splitting: every
layer must be removable in turn, so an object under this profile is recoverable only by a
party who can obtain every layer's key.

A deployment needing BaseTDF's `sid` semantics — several KAOs protecting the same share,
any one sufficient — cannot express them in IC-TDF. Use multiple `RemoteStoredKey` children
within one `KeyAccess` for alternative routes to the same key, and do not model an
`allOf` split as layers.

## 3. Mapping markings to policy

IC markings describe data. BaseTDF attributes authorize release. A deployment using this
profile MUST publish a total, deterministic mapping between them, and the producer applies
it at creation.

| IC marking | BaseTDF attribute FQN |
|---|---|
| `ism:classification="S"` | `https://example.gov/attr/classification/value/secret` |
| `ism:ownerProducer="USA"` | `https://example.gov/attr/ownerproducer/value/usa` |
| `ism:releasableTo="USA FVEY"` | `https://example.gov/attr/relto/value/usa`, `…/value/fvey` |
| `ntk:Access` profile identifier | `https://example.gov/attr/ntk/value/<profile>` |

Deployments substitute their own controlled namespace for `example.gov`.

Requirements:

- The mapping MUST be total over the markings the deployment emits. An unmapped marking is
  a creation error, not a permitted omission.
- The marking remains authoritative. The policy is its enforcement projection, and a
  disagreement between them is a validation failure, not a resolution to the more permissive
  side.
- The KAS authorizes against the policy only. It MUST NOT parse IC markings, because doing
  so would put marking semantics — ISM version handling, rollup, portion marking — inside
  the key service.
- The rolled-up object-scope marking is the input to a whole-object decision; a `PAYL`-scope
  marking is the input to a payload-only decision (ICTDF-KAS §4).
- Dissemination lists (BaseTDF-POL `body.dissem`) have no IC-TDF counterpart and are a
  deployment addition, not a projection of any marking.

## 4. Cryptography

| Choice | Required value |
|---|---|
| Payload encryption | `http://www.w3.org/2009/xmlenc11#aes256-gcm` |
| `EncryptionMethod/@algorithm` | Exactly the URI above; a family name such as `AES` MUST NOT be used |
| `IVParams` | 96 bits, unique per key |
| `AuthenticationTag` | REQUIRED; 128 bits |
| Signature algorithm | `SHA256withECDSA` or `SHA256withRSAandMGF1` |
| Hash algorithm | `SHA256` or stronger |
| Normalization method | `http://www.w3.org/2006/12/xml-c14n11` |

`SHA1` and every `SHA1with…` value MUST NOT be produced and MUST be rejected on receipt,
notwithstanding their presence in the source controlled vocabularies (ICTDF-ALG §1).

An inclusive canonicalization method is required so that the dependent-specification
version declarations a fragment inherits are inside the signed bytes (ICTDF-BND §5).

## 5. Bindings

- Every object MUST carry a binding on its `TDO`- or `TDC`-scope handling assertion, so
  that the rolled-up marking a decision point reads is authenticated.
- `@includesStatementMetadata="true"` is REQUIRED on that binding, so that statement
  metadata used in the mapping of §3 is covered.
- Where the payload is not covered by a binding, its integrity comes from the GCM
  authentication tag alone; the profile permits this but a deployment SHOULD add a
  `PAYL`-scope binding where provenance matters.
- Signers are resolved through the deployment's trust anchors. This profile defines no
  certificate distribution mechanism.

## 6. Structural constraints

- `@tdf:version` MUST be `201412.201707`, with a customization suffix only where the
  deployment registers one.
- `StructuredPayload` and `StructuredStatement` MUST name a schema the deployment can
  validate in ICTDF-VAL Step 2. A producer MUST NOT emit structured content whose governing
  schema is not in the deployment catalog.
- `ReferenceValuePayload` MUST NOT be used for content the KAS protects. A referenced
  payload is unauthenticated and unfetched at validation time (ICTDF-LOC §5), so the
  object's protection guarantees do not extend to it.
- The reserved structures — `EXPLICIT` scope, `BoundValueList`, `ReferenceList` — MUST NOT
  be emitted (ICTDF-SCH §5).

## 7. Security

- A `RemoteStoredKey` URI naming a KAS is not authorization to release. The KAS decides by
  evaluating policy against the requester (ICTDF-KAS §4).
- Denials MUST be indistinguishable from key-recovery failures at the consumer. A
  distinguishable denial leaks policy content.
- The mapping in §3 is a security boundary. A bug that maps `S` to an attribute value with
  weaker entitlement requirements silently over-releases, and no validation step detects
  it. Mappings SHOULD be reviewed as policy, versioned, and audited.
- This profile does not make an IC-TDF object interchangeable with a BaseTDF object. They
  remain different formats with different validation procedures; ICTDF-MIG covers
  conversion.
