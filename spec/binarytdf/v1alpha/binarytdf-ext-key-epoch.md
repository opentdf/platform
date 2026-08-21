# BinaryTDF-KEY-EPOCH: KEY_EPOCH Recovery Extension

| | |
|---|---|
| Document | BinaryTDF-KEY-EPOCH |
| Extension version | 0.1 |
| Source draft | 0.2 |
| Frame version | 2 |
| Registry identifier | `KEY_EPOCH = 3` |
| Status | Draft, optional |
| Depends on | BinaryTDF-SEC, BinaryTDF-REC, BinaryTDF-KAO, BinaryTDF-KAS, BinaryTDF-PAY, BinaryTDF-SCH |

KEY_EPOCH amortizes authority contact across a bounded cryptographic generation while
retaining a unique object key per BinaryTDF. It is intended for independently framed
objects in a dataset or stream sharing policy and recipients for a limited generation.

## 1. Core relationship

Identifier 3 is reserved for this recovery extension. A compatible revision retains
it; incompatible schema, cryptographic, validation, or interpretation changes require
a new identifier.

Support is optional. An implementation MAY claim core conformance without implementing
this extension. A receiver that does not implement KEY_EPOCH MUST reject scheme 3 as
`UNSUPPORTED_CAPABILITY` and MUST NOT substitute another scheme. The extension uses
core KAOs, wrapping, policy binding, rewrap, and DIRECT/XOR_ALL topologies without
modification.

```cddl
$binary-tdf-recovery-scheme-data /= key-epoch-recovery-data
```

## 2. Scope

An epoch is a bounded logical generation, not wall-clock time. It has one anchor whose
KAOs protect a fresh 32-byte epoch secret. Other objects are references identifying the
anchor and contain no KAO. After one authorized anchor recovery, an opener derives a
different object key for every object in that epoch.

Releasing the epoch secret authorizes the complete epoch. This extension MUST NOT be
used when each object requires an independent authority decision.

An epoch share is a 32-byte value used to reconstruct an epoch secret. The extension
defines identity and recovery but not transport, delivery order, packaging, buffering,
or anchor lookup protocol.

```text
anchor KAO release ─► epoch secret ─┬─ context A + HKDF ─► object key A
                                    ├─ context B + HKDF ─► object key B
                                    └─ context C + HKDF ─► object key C
```

The anchor is a payload-bearing object and consumes one unique dataset/epoch/stream/
sequence tuple. It need not be first, though producers SHOULD use sequence zero when
the stream model permits it.

## 3. Wire schema

`recovery_data` is one of two closed maps selected by `role`:

| Key | Field | Anchor | Reference | Type |
|---:|---|---|---|---|
| 1 | `role` | `0`, required | `1`, required | `uint` |
| 2 | `dataset_id` | required | required | 16-byte `bstr` |
| 3 | `epoch` | required | required | `uint64` |
| 4 | `stream_id` | required | required | `uint32` |
| 5 | `sequence` | required | required | `uint64` |
| 6 | `anchor_id` | required | required | 16-byte `bstr` |
| 7 | `epoch_limits` | required | forbidden | map |
| 8 | `epoch_secret_recovery` | required | forbidden | array |

`dataset_id` and `anchor_id` MUST be independently generated with a cryptographically
secure random source. They are identifiers, not locations. The deployment-defined
resolver is untrusted. An opener MUST verify exact anchor, dataset, and epoch equality.
Unknown roles, extra role-specific fields, and mismatched identifiers are malformed.

```cddl
key-epoch-role = &(anchor: 0, reference: 1)

epoch-uint64 = 0..18446744073709551615
epoch-uint32 = 0..4294967295

epoch-limits = {
  1 => max_streams: 1..4294967295,
  2 => max_sequence: epoch-uint64,
  ? 3 => max_total_plaintext_bytes: 1..18446744073709551615,
  ? 4 => producer_not_after: 1..18446744073709551615
}

epoch-secret-recovery = [
  base-scheme: (1 / 2),
  base-data: (direct-kao-set / xor-all-kao-groups)
]

key-epoch-anchor-data = {
  1 => 0,
  2 => bstr .size 16,
  3 => epoch-uint64,
  4 => epoch-uint32,
  5 => epoch-uint64,
  6 => bstr .size 16,
  7 => epoch-limits,
  8 => epoch-secret-recovery
}

key-epoch-reference-data = {
  1 => 1,
  2 => bstr .size 16,
  3 => epoch-uint64,
  4 => epoch-uint32,
  5 => epoch-uint64,
  6 => bstr .size 16
}

key-epoch-recovery-data =
  key-epoch-anchor-data /
  key-epoch-reference-data
```

`stream_id` MUST be less than `max_streams`; `sequence` MUST be at most
`max_sequence`. `producer_not_after` is an unsigned Unix creation deadline in seconds
and does not make existing objects undecryptable. A producer MUST count complete epoch
plaintext when the byte limit is present. Epoch values MUST increase within a dataset
and MUST NOT be reused.

Every epoch limit, including `max_total_plaintext_bytes`, is an authorization
blast-radius and rotation control on a long-lived producer key. It bounds how much data
one released epoch secret exposes and when the producer must rotate, and it is counted
across every object in the epoch. It is not an AEAD usage bound. The AEAD bound is
separate: it applies per content-encryption key per object and is stated by
BinaryTDF-SEC Section 3.1 and BinaryTDF-PAY Section 5. Every object in an epoch has its
own object key by the Section 5 derivation below, so an epoch may carry far more
plaintext than the AEAD bound without any key approaching it. Neither limit relieves
the other: an epoch byte
limit of any size leaves a suite 2 object with its own ceiling, and an object that
respects every partition ceiling still counts its complete plaintext against the epoch
limit.

## 4. Epoch-secret recovery

The anchor selects one base topology:

- DIRECT contains exactly one KAO wrapping the epoch secret.
- XOR_ALL contains two or more required groups whose shares XOR to the epoch secret.

| Topology | KAO path |
|---|---|
| DIRECT | `[1, 0]` |
| XOR_ALL | `[2, group_index, alternative_index]` |

The top-level KAO context identifies KEY_EPOCH. Each KAO wraps the epoch secret or a
share and binds policy using that `kao_value`. The authority returns the value; the
opener XORs when needed.

A reference has no path and MUST NOT be sent directly for rewrap. The opener resolves
the anchor and submits exact anchor sections and anchor paths.

## 5. Object-key derivation

```text
epoch_object_context = encode_deterministic_cbor([
  "binary-tdf:v2:key-epoch",
  frame_version,
  KEY_EPOCH,
  role,
  content_encryption_suite,
  dataset_id,
  epoch,
  stream_id,
  sequence,
  anchor_id
])

object_key = HKDF-SHA256(
  ikm  = epoch_secret,
  salt = UTF8("binary-tdf:v2:hkdf-salt"),
  info = epoch_object_context,
  len  = 32
)
```

Context fields MUST NOT be concatenated outside deterministic CBOR. The object key is
given to the selected content-encryption suite and never serialized. Producers MUST
NOT repeat a dataset/epoch/stream/sequence tuple. Role, suite, and identity changes
change the object key. Payload encryption still uses required fresh randomness.

## 6. Policy and lifecycle

The anchor policy governs the epoch. References MUST omit top-level policy. For a
KEY_EPOCH reference, absence means inheritance from the verified anchor rather than
public access. A reference carrying policy is malformed. Other recovery schemes retain
the core public-policy default.

Changing policy, recipient, KAO topology, wrap suite, or epoch limit requires a fresh
epoch secret, new epoch value, and new anchor ID.

Every epoch is bounded by streams and sequence. Producers MAY add lower byte or
creation-time limits and MUST rotate at the first declared limit. Lost sequence state,
rollback, or inability to prove tuple uniqueness requires a new epoch. If a greater
unused epoch cannot be proved, the producer MUST create a new dataset ID.

An opener MAY cache the epoch secret under verified anchor ID. The cache MUST be
bounded and scoped to the matching dataset and epoch, MUST be excluded from logs, and
MUST be cleared when no longer needed. Persistent clear epoch-secret storage is
forbidden.

## 7. Opening and replay

To open a reference:

1. strictly parse it;
2. resolve anchor ID using a configured resolver;
3. strictly parse and verify the anchor role, limits, and identifiers;
4. validate anchor policy and critical extensions;
5. recover or retrieve the cached epoch secret;
6. derive the object key from exact reference context; and
7. authenticate payload before returning plaintext.

Resolution MUST have finite request, recursion, response-size, and cache limits. An
anchor may be retransmitted or stored, but a reference MUST never mean “use the
previous key.” Failure to resolve the exact anchor fails closed.

A generic opener MAY reopen stored objects. A live-processing profile MUST maintain a
replay window per dataset/epoch/stream, reject accepted sequences, bound out-of-order
acceptance, and reject values past declared limits.

## 8. Security

- An epoch-secret holder can decrypt and construct AEAD-valid objects for the epoch.
  AEAD does not identify the producer.
- Source-sensitive records MUST carry a producer-signed metadata claim or detached
  attestation from a trusted signer.
- Rotation limits exposure but does not provide forward secrecy or post-compromise
  security within an epoch.
- Revocation cannot retract a released epoch secret; changes apply to new objects at
  the next epoch.
- XOR limits what one authority can reconstruct before release, not what an opener can
  do after reconstructing and caching the epoch secret.
- ML-KEM protects KAO and session transport but not symmetric exposure after release.
- References depend on bounded, exact, fail-closed anchor resolution and availability.
  Deployments MUST define retransmission or trusted lookup when references can outlive
  their delivery session.

## 9. Conformance

Vectors MUST include byte-exact anchor and reference data; DIRECT and XOR_ALL recovery;
deterministic contexts and keys; mutations of role, suite, and identity; duplicate
tuples, rollback, and limits; missing, mismatched, malformed, and recursive anchors;
references carrying policy or KAO material; live replay behavior; and indistinguishable
policy, unwrap, derivation, and payload failures.
