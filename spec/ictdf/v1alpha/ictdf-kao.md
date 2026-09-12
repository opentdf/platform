# ICTDF-KAO: Key Access and Encryption Method

| | |
|---|---|
| Document | ICTDF-KAO |
| Version | 1 Alpha |
| Source spec | IC-TDF.XML.V2014-DEC-r2017-JUL |
| TDF version | 201412.201707 |
| Status | Draft |
| Depends on | ICTDF-SEC, ICTDF-ALG, ICTDF-LOC |
| Referenced by | ICTDF-PAY, ICTDF-KAS, ICTDF-VAL, ICTDF-CORE, ICTDF-OPENTDF, ICTDF-MIG |

## 1. Structure

`EncryptionInformation` describes one layer of encryption applied to one part of a TDO. It
pairs a means of obtaining the key with a description of the algorithm the key is used
with.

```text
EncryptionInformation          0..unbounded
  KeyAccess                    1
  EncryptionMethod             1
  @sequenceNum                 optional, xs:integer
```

It appears in two places:

- directly under `TrustedDataObject`, describing encryption of the payload; and
- under `tdf:Assertion`, describing encryption of that assertion's statement.

It never appears under `tdf:HandlingAssertion`: handling assertions are not encrypted
(ICTDF-POL §1).

The presence of `EncryptionInformation` and the value of the corresponding
`@tdf:isEncrypted` MUST agree. Encryption information without an encrypted-labeled part is
a failure (`IC-TDF-ID-00014`), and an encrypted-labeled part without encryption
information is a failure (`IC-TDF-ID-00015`).

## 2. Layered encryption

Several `EncryptionInformation` elements on one part describe encryption applied in
layers — the innermost layer applied first, each subsequent layer applied over the
previous one's output.

| Requirement | Rule |
|---|---|
| More than one `EncryptionInformation` on a part requires `@sequenceNum` on each | `IC-TDF-ID-00040` |
| Sequence numbers start at 1, increment by 1, and contain no duplicates | `IC-TDF-ID-00041` |

The **highest** sequence number is the **outermost** layer. Decryption proceeds from the
highest number down to 1; encryption proceeds from 1 up.

```text
plaintext ──[seq 1]──► ──[seq 2]──► ──[seq 3]──► ciphertext as carried
                                                 decrypt 3, then 2, then 1
```

A single `EncryptionInformation` MAY omit `@sequenceNum`; a consumer treats it as the only
layer. A consumer MUST reject a gap, a duplicate, a value below 1, or a partially numbered
set rather than inferring an order — layering ambiguity is a decryption failure at best and
a silent wrong-plaintext at worst.

Layering is how one part is made available to disjoint key holders in sequence, for example
a mission-system key inside an enterprise key. It does not by itself express a threshold or
split; each layer must be removable by whoever holds that layer's key.

## 3. Key access

`KeyAccess` carries one or more key descriptors. The schema permits repetition and
mixing of kinds: each descriptor is an alternative route to the same layer's key, so a
consumer takes the first it can satisfy.

| Element | Required attributes | Optional | Content |
|---|---|---|---|
| `RemoteStoredKey` | `@protocol`, `@uri` | — | empty |
| `WrappedKey` | — | `@keyIdentifier` | `KeyValue`, `EncryptionInformation`* |
| `WrappedPDPKey` | — | `@keyIdentifier` | `EncryptedPolicyObject`, `EncryptionInformation`* |
| `PasswordKey` | `@algorithm` | — | empty |
| `PreSharedKey` | `@alias` | `@store` | empty |
| `AttachedKey` | — | — | `KeyValue` |

`KeyValue` and `EncryptedPolicyObject` are `xs:base64Binary`.

### 3.1 Remote stored key

The key is held by a service. `@protocol` names how to talk to it and `@uri` names where.
IC-TDF defines neither the protocol nor its message format; see ICTDF-KAS.

A consumer MUST resolve `@uri` through deployment policy and MUST NOT dereference it
merely because it appears in the document (ICTDF-SEC §2, ICTDF-LOC §4).

### 3.2 Wrapped key

The key travels in the document, encrypted to a recipient. `KeyValue` holds the wrapped
key material; the nested `EncryptionInformation` describes how it was wrapped, recursively
using this same structure. `@keyIdentifier` names the wrapping key so a recipient holding
several can select without trial decryption.

The nesting terminates: a wrapping layer must eventually reach a `RemoteStoredKey`,
`PreSharedKey`, `PasswordKey`, or a recipient key held out of band. A consumer MUST bound
the nesting depth it will follow.

### 3.3 Wrapped PDP key

The same as a wrapped key, except that what is wrapped is an `EncryptedPolicyObject` — a
policy that a decision point evaluates before releasing the key. The requester does not
hold the key and cannot obtain it by holding a certificate alone; the decision point
applies the policy first. See ICTDF-KAS §3.

### 3.4 Password key

The key is derived from a secret the user supplies. `@algorithm` names the derivation. The
document carries no salt, iteration count, or memory parameter of its own, so those must
come from the algorithm identifier or from deployment configuration. A deployment using
`PasswordKey` MUST specify them and MUST select a memory-hard derivation.

### 3.5 Pre-shared key

The key is already held by both parties. `@alias` names it within an agreement established
out of band; `@store` optionally names the keystore holding it. The document proves nothing
about that agreement, and an alias collision across two agreements yields the wrong key
without any signal.

### 3.6 Attached key

`KeyValue` holds the key itself, unwrapped. This provides no confidentiality: anyone who
can read the document can decrypt the part. It exists for structural completeness and for
cases where confidentiality comes entirely from the transport.

Producers MUST NOT use `AttachedKey` for data requiring protection in transit or at rest.

## 4. Encryption method

```text
EncryptionMethod
  KeySize                       xs:integer         optional
  KeyEncodingFormat             xs:string          optional
  IVParams                      base64Binary       optional
  OaepParams                    base64Binary       optional
  HashAlgorithm                 xs:anyURI          optional
  MGFAlgorithm                  xs:anyURI          optional
  Tweak                         base64Binary       optional
  Nonce                         base64Binary       optional
  AdditionalAuthenticatedData   base64Binary       optional
  AuthenticationTag             base64Binary       optional
  @algorithm                    xs:anyURI          required
```

Every child is optional in the schema, so the schema cannot tell whether the supplied
parameters match the declared algorithm. That check belongs to the consumer:

- A consumer MUST reject an `@algorithm` outside its allow-list rather than approximating
  (ICTDF-SEC §4).
- A consumer MUST verify that every parameter the algorithm requires is present and
  correctly sized, and SHOULD reject parameters the algorithm does not use rather than
  ignoring them.
- `IVParams` and `Nonce` MUST be unique per key. Reuse breaks counter and GCM modes
  outright.
- `AuthenticationTag` is the only integrity IC-TDF provides for a payload that no binding
  covers. An unauthenticated algorithm leaves such a payload malleable.
- `AdditionalAuthenticatedData` is authenticated but not encrypted, so it is readable by
  anyone holding the document.
- `OaepParams`, `HashAlgorithm`, and `MGFAlgorithm` parameterize asymmetric wrapping and
  are normally meaningful only inside a `WrappedKey`'s nested encryption information.

`KeySize` and `KeyEncodingFormat` are descriptive. A consumer MUST NOT let a declared key
size override what the algorithm and the recovered key material actually are.

## 5. Failure handling

Unwrap, decrypt, and authentication failures MUST be reported as one opaque class.
Distinguishing an unknown `@keyIdentifier` from a padding error from a policy denial gives
an attacker an oracle over both the key hierarchy and the policy.

Recovered key material MUST NOT be logged, returned in an error, or retained beyond the
operation.
