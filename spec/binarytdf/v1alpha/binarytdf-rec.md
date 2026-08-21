# BinaryTDF-REC: Object Key Recovery

| | |
|---|---|
| Document | BinaryTDF-REC |
| Version | 1 Alpha |
| Source draft | 0.2 |
| Frame version | 2 |
| Status | Draft |
| Depends on | BinaryTDF-SEC, BinaryTDF-ALG, BinaryTDF-POL, BinaryTDF-KAO |
| Referenced by | BinaryTDF-PAY, BinaryTDF-KAS, BinaryTDF-SCH, BinaryTDF-CORE, BinaryTDF-KEY-EPOCH |

## 1. Recovery object

Object Key Recovery identifies effective authorization policy and contains the
scheme-specific data used to obtain the object key. It never contains the payload key.

| Key | Field | Type | Required |
|---:|---|---|---|
| 1 | `recovery_scheme` | `uint` | yes |
| 2 | `policy` | `canonical-policy` | no |
| 3 | `recovery_data` | `recovery-scheme-data` | yes |

The exact recovery bytes are payload AAD. Each KAO is additionally bound to metadata,
policy, recovery scheme, and position through its KAO context.

`recovery_data` is scheme-specific:

- DIRECT stores exactly one KAO as `[KAO]`.
- XOR_ALL stores alternatives in required share groups as `[[KAO, ...], ...]`.
- KEY_EPOCH anchors store KAOs inside `epoch_secret_recovery`; references store none.

A decoder MUST select and validate the complete recovery schema before attempting
recovery.

## 2. Scheme registry

| Symbol | Integer | Encoded bytes | Result |
|---|---:|---|---|
| `UNSPECIFIED` | 0 | `00` | invalid |
| `DIRECT` | 1 | `01` | one KAO releases the object key |
| `XOR_ALL` | 2 | `02` | required shares reconstruct the object key |
| `KEY_EPOCH` | 3 | `03` | separately defined epoch-secret derivation |
| `PRIVATE_USE` | 24–255 | `18 18`–`18 ff` | explicit interoperability profile |

Identifiers 4 through 23 and 256 or greater are unassigned. Unassigned identifiers
MUST be rejected as `UNSUPPORTED_CAPABILITY`. Private assignments are not globally
unique and MUST be enabled by an explicit profile; otherwise they are rejected.

Every frame version 2 implementation MUST support DIRECT and XOR_ALL. KEY_EPOCH is
optional and defined by [BinaryTDF-KEY-EPOCH](binarytdf-ext-key-epoch.md). A receiver
MUST NOT substitute another scheme for an unsupported one.

## 3. Common recovery result

DIRECT and XOR_ALL produce one fresh uniformly random 32-byte object key for one
BinaryTDF. A KAO protects that key or a share. The object key MUST NOT be serialized
directly or reused.

```text
DIRECT:   KAO ──authorized release──► object key

XOR_ALL:  group 0 ─► share 0 ┐
          group 1 ─► share 1 ├─ XOR ─► object key
          group n ─► share n ┘
```

### 3.1 DIRECT

DIRECT recovery data is an array containing exactly one KAO. The KAO wraps the
32-byte object key. The opener's authenticated `kao_value` is the object key. Any
additional or missing KAO, invalid path, or value of another length is malformed.

### 3.2 XOR_ALL

XOR_ALL recovery data contains two or more non-empty share groups. KAOs within one
group are alternatives protecting the same 32-byte share:

- OR applies within one group.
- AND applies across groups.

For `G` groups, the producer MUST generate `G - 1` independent, uniformly random
32-byte shares and compute the final share such that:

```text
share[0] XOR share[1] XOR ... XOR share[G-1] = object_key
```

Shares MUST NOT be reused across objects or groups. An opener accepts at most one
authenticated share per group, rejects duplicate or inconsistent contributions,
requires every group, and XORs locally. An authority never reconstructs the object
key. Incorrect shares may cause denial of service; plaintext MUST NOT be returned
unless payload authentication succeeds.

## 4. KAO paths

| Scheme | Path |
|---|---|
| DIRECT | `[0]` |
| XOR_ALL | `[group_index, alternative_index]` |

Paths are zero-based and not serialized inside KAOs. They participate in KAO and
rewrap contexts, so reordering changes cryptographic context.

## 5. Extension contract

A recovery-scheme specification MUST define:

- its identifier and deterministic recovery-data CDDL plug;
- an interoperability profile for Private Use assignments;
- whether the object key is generated, reconstructed, or derived;
- every protected value, KAO path, and policy-binding input;
- producer, opener, and authority validation;
- partial-success and indistinguishable-failure behavior;
- resource, lifetime, and replay limits for stateful schemes;
- any scheme-specific meaning of absent policy;
- security and authorization granularity; and
- cross-language positive and negative vectors.

Threshold recovery other than all-shares XOR requires a registered extension.
Every new scheme, including a threshold construction, MUST satisfy this contract before
receiving a registry identifier. A Private Use scheme MUST satisfy the same contract.

## 6. CDDL plug

```cddl
direct-kao-set = [key-access-object]

xor-all-share-group = [1* key-access-object]

xor-all-kao-groups = [2* xor-all-share-group]

direct-recovery-data = direct-kao-set

xor-all-recovery-data = xor-all-kao-groups

$binary-tdf-recovery-scheme-data /= direct-recovery-data
$binary-tdf-recovery-scheme-data /= xor-all-recovery-data
```

The selected `recovery_scheme` determines which otherwise array-shaped plug is valid.

## 7. Conformance

Vectors MUST cover DIRECT cardinality and path validation; XOR_ALL alternatives,
missing groups, duplicates, and reconstruction; KAO reordering; non-32-byte shares;
authenticated incorrect shares ending in payload failure; and generic failure handling
for policy binding, unwrap, and rewrap.
