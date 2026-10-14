# BaseTDF-POL: Policy and Attribute-Based Access Control

| | |
|---|---|
| **Document** | BaseTDF-POL |
| **Title** | Policy and Attribute-Based Access Control |
| **Version** | 4.4.0 |
| **Status** | Standards Track |
| **Date** | 2025-02 |
| **Suite** | BaseTDF Specification Suite |
| **Depends on** | BaseTDF-SEC, BaseTDF-ALG |
| **Referenced by** | BaseTDF-KAO, BaseTDF-KAS, BaseTDF-CORE |

## Table of Contents

1. [Introduction](#1-introduction)
2. [Policy Object Schema](#2-policy-object-schema)
3. [Attribute Representation](#3-attribute-representation)
4. [Attribute Rule Types and Evaluation Semantics](#4-attribute-rule-types-and-evaluation-semantics)
5. [Dissemination List](#5-dissemination-list)
6. [Canonical Serialization and Policy Binding](#6-canonical-serialization-and-policy-binding)
7. [KAS Grant Resolution](#7-kas-grant-resolution)
8. [Key Splitting and Rule Interaction](#8-key-splitting-and-rule-interaction)
9. [Policy Evaluation Flow](#9-policy-evaluation-flow)
10. [Security Considerations](#10-security-considerations)
11. [Normative References](#11-normative-references)

---

## 1. Introduction

### 1.1 Purpose

This document defines the **policy object** embedded in Trusted Data Format
(TDF) containers and the **attribute-based access control (ABAC) evaluation
rules** that govern key release by the Key Access Service (KAS). The policy
object is the mechanism by which data creators express who may access protected
data and under what conditions.

BaseTDF implements a data-centric ABAC model inspired by [NIST SP 800-162][SP800-162]
(Guide to Attribute Based Access Control). In this model:

- **Data attributes** attached to the TDF represent the security properties
  of the protected content (the *resource attributes*).
- **Entity entitlements** provisioned by the identity provider and attribute
  authority represent the clearances, roles, or properties of the requesting
  entity (the *subject attributes*).
- **Attribute rules** (allOf, anyOf, hierarchy) define how resource attributes
  are compared against subject attributes to reach an access decision.

The policy object is embedded in the TDF manifest and is cryptographically
bound to the encrypted key material via the policy binding (see BaseTDF-KAO).
This binding ensures that the policy cannot be separated from, substituted on,
or tampered with for the data it governs.

### 1.2 Scope

This document covers:

- The JSON schema of the policy object.
- The format and semantics of attribute URIs.
- The three attribute rule types (allOf, anyOf, hierarchy) and their precise
  evaluation semantics.
- The dissemination list and its enforcement requirements.
- Canonical serialization of the policy for binding computation.
- KAS grant resolution: how attribute values map to KAS instances.
- The interaction between attribute rules and key splitting.
- The end-to-end policy evaluation flow.

This document does NOT cover:

- The cryptographic construction of the policy binding (see BaseTDF-KAO).
- The wire protocol for the rewrap endpoint (see BaseTDF-KAS).
- The container format in which the policy is carried (see BaseTDF-CORE).

### 1.3 Relationship to Other BaseTDF Documents

- **BaseTDF-SEC**: Defines the security invariants that this document
  operationalizes. SI-2 (Authorization Before Key Release) requires the policy
  evaluation described in Section 9. SI-3 (Dissemination Enforcement) requires
  the dissemination checks described in Section 5.
- **BaseTDF-KAO**: Defines the Key Access Object, which carries the policy
  binding that cryptographically ties the policy object to the wrapped DEK
  share. The policy binding is computed over the canonical serialization
  defined in Section 6.
- **BaseTDF-KAS**: Defines the rewrap protocol through which the KAS receives
  the policy, evaluates it, and releases key material.
- **BaseTDF-ALG**: Defines the algorithm identifiers referenced by attribute
  objects and key protection.
- **BaseTDF-CORE**: Carries the policy object in the manifest's
  `encryptionInformation.policy` field.

### 1.4 Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [BCP 14][RFC2119] [RFC
8174][RFC8174] when, and only when, they appear in ALL CAPITALS, as shown here.

### 1.5 Terminology

| Term | Definition |
|---|---|
| **Attribute authority** | The organizational authority that defines attribute namespaces, attribute definitions, and attribute values. Identified by a fully qualified domain name (FQDN). |
| **Attribute definition** | A named attribute within an authority's namespace, along with its rule type and set of permissible values. |
| **Attribute value** | A specific value within an attribute definition. Represented as a URI. |
| **Data attribute** | An attribute value attached to a TDF's policy object, representing a security requirement of the protected data. |
| **Entity entitlement** | An attribute value held by an entity, representing a clearance, role, or property granted by the attribute authority. |
| **Dissemination list** | A list of entity identifiers that restricts who may access the protected data, independent of attribute-based checks. |
| **KAS grant** | The association between an attribute value (or definition, or namespace) and a KAS instance that holds the corresponding key material. |

---

## 2. Policy Object Schema

The policy object is a JSON structure that expresses the access requirements for
a TDF-protected data object. It is serialized, base64-encoded, and stored in the
manifest's `encryptionInformation.policy` field (see BaseTDF-CORE).

### 2.1 Structure

```json
{
  "uuid": "unique-policy-identifier",
  "body": {
    "dataAttributes": [ ... ],
    "dissem": [ ... ]
  }
}
```

### 2.2 Fields

#### 2.2.1 `uuid`

- **Type**: String
- **Required**: REQUIRED
- **Description**: A unique identifier for this policy instance. This
  identifier is used in audit logs (SI-8) to correlate rewrap requests with
  specific TDF policies.
- **Format**: UUIDv4 ([RFC 9562][RFC9562]) is RECOMMENDED. Implementations MAY
  use other globally unique identifier formats, but the value MUST be unique
  across all policies produced by the implementation.

#### 2.2.2 `body`

- **Type**: Object
- **Required**: REQUIRED
- **Description**: Contains the access control rules for this policy.

#### 2.2.3 `body.dataAttributes`

- **Type**: Array of attribute objects (see Section 3.2)
- **Required**: REQUIRED (MAY be empty)
- **Description**: The set of attribute values that define the access
  requirements for the protected data. Each attribute object identifies a
  specific attribute value and the KAS instance responsible for the
  corresponding key material.
- **Semantics**: When this array is non-empty, the KAS MUST evaluate the
  entity's entitlements against these attributes using the rules defined in
  Section 4. When this array is empty, no attribute-based access control is
  applied (dissemination checks per Section 5 still apply if configured).

#### 2.2.4 `body.dissem`

- **Type**: Array of strings
- **Required**: REQUIRED (MAY be empty)
- **Description**: A list of entity identifiers (typically email addresses)
  that restricts access to the listed entities. See Section 5 for enforcement
  semantics.

### 2.3 Complete Example

```json
{
  "uuid": "5e2f7fa6-a93e-4b9b-8f73-2fd694c0b4d8",
  "body": {
    "dataAttributes": [
      {
        "attribute": "https://example.com/attr/classification/value/secret",
        "displayName": "Classification: Secret",
        "isDefault": false,
        "pubKey": "",
        "kasURL": "https://kas.example.com"
      },
      {
        "attribute": "https://example.com/attr/department/value/engineering",
        "displayName": "Department: Engineering",
        "isDefault": false,
        "pubKey": "",
        "kasURL": "https://kas.example.com"
      }
    ],
    "dissem": [
      "alice@example.com",
      "bob@example.com"
    ]
  }
}
```

In this example, an entity requesting access must:

1. Satisfy the attribute rules for both `classification/value/secret` and
   `department/value/engineering` (evaluated per the rule types of their
   respective attribute definitions; see Section 4).
2. Have an identity matching either `alice@example.com` or `bob@example.com`
   (see Section 5).

---

## 3. Attribute Representation

### 3.1 Attribute URI Format

Attribute values are identified by fully qualified names (FQNs) expressed as
URIs. The canonical form is:

```
https://{authority}/attr/{name}/value/{value}
```

| Component | Description | Example |
|---|---|---|
| `{authority}` | FQDN of the attribute authority, optionally including a path prefix | `example.com` or `ns.example.com/org` |
| `{name}` | The attribute definition name | `classification` |
| `{value}` | The specific attribute value | `secret` |

**Normalization requirements**:

- The scheme MUST be `https` for production deployments. The scheme `http` MAY
  be used in development or testing environments.
- The authority component SHOULD be treated as case-insensitive for matching
  purposes. Implementations SHOULD normalize to lowercase.
- The name and value components are case-sensitive unless the attribute
  authority specifies otherwise.
- The URI MUST NOT contain a trailing slash after the value component.
- The name and value components MUST NOT contain unescaped forward slashes.
  If a name or value naturally contains a slash, it MUST be percent-encoded
  per [RFC 3986][RFC3986].

**Attribute definition FQN**: The parent attribute definition is identified by
truncating the URI at the `/value/` segment:

```
https://{authority}/attr/{name}
```

This prefix groups all values of the same attribute definition and is used to
determine which rule type (allOf, anyOf, hierarchy) governs evaluation.

### 3.2 Attribute Object

Each entry in `body.dataAttributes` is an attribute object with the following
fields:

```json
{
  "attribute": "https://example.com/attr/classification/value/secret",
  "displayName": "Classification: Secret",
  "isDefault": false,
  "pubKey": "",
  "kasURL": "https://kas.example.com"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `attribute` | String | REQUIRED | The fully qualified attribute value URI (see Section 3.1). |
| `displayName` | String | OPTIONAL | A human-readable label for this attribute value. Used for display purposes only; MUST NOT affect access control evaluation. |
| `isDefault` | Boolean | OPTIONAL | Indicates whether this is the default value for the attribute definition. Informational only; MUST NOT affect access control evaluation. |
| `pubKey` | String | OPTIONAL | Legacy field. Was previously used to carry the KAS public key. New implementations SHOULD set this to an empty string. KAS public keys are resolved through the grant system or the KAS discovery endpoint. |
| `kasURL` | String | REQUIRED | The URL of the KAS instance that holds the key material associated with this attribute value. See Section 7 for grant resolution. |

### 3.3 Attribute Object Validation

Implementations MUST validate attribute objects according to the following
rules:

1. The `attribute` field MUST be present and MUST be a syntactically valid
   attribute value URI matching the format in Section 3.1.
2. The `kasURL` field MUST be present and MUST be a valid HTTPS URL (or HTTP
   in development environments).
3. Implementations SHOULD reject attribute objects where the `attribute` field
   is an empty string.
4. Implementations SHOULD treat `displayName` and `isDefault` as purely
   informational and MUST NOT use them in access control decisions.

---

## 4. Attribute Rule Types and Evaluation Semantics

Attribute definitions are configured with a **rule type** that determines how
the KAS authorization service evaluates entity entitlements against the data
attributes present in a TDF policy. The rule type is a property of the
**attribute definition** (not of individual attribute values or of the policy
object itself). The authorization service resolves the rule type from its
attribute definition registry at evaluation time.

Three rule types are defined: **allOf** (conjunctive), **anyOf** (disjunctive),
and **hierarchy** (ordered). Each rule type is evaluated independently per
attribute definition. When a policy contains attribute values from multiple
attribute definitions, the results are combined conjunctively: the entity MUST
satisfy the rule for **every** attribute definition represented in the policy.

### 4.1 allOf (Conjunctive)

**Semantics**: The entity MUST possess entitlements for ALL listed attribute
values of this definition to satisfy the rule.

**Formal definition**: Given a set of data attribute values
$V = \{v_1, v_2, \ldots, v_n\}$ from a single attribute definition with rule
type `allOf`, and a set of entity entitlements $E$, the rule is satisfied if
and only if:

$$\forall v_i \in V : v_i \in E$$

**Evaluation procedure**:

1. For each attribute value FQN in the policy that belongs to this definition,
   verify that the entity holds an entitlement for that exact FQN with the
   requested action (typically `decrypt` / `read`).
2. If ANY attribute value is not found in the entity's entitlements, the rule
   FAILS and access MUST be denied.
3. If ALL attribute values are found, the rule PASSES.

**Key splitting implication**: Each attribute value in an allOf group maps to a
**separate key split** (see Section 8). This means that every KAS associated
with an allOf value independently authorizes access and releases its key share.
All shares are required to reconstruct the DEK.

**Example**:

Policy contains:
- `https://example.com/attr/clearance/value/gamma`
- `https://example.com/attr/clearance/value/delta`

Where `clearance` is defined with rule type `allOf`.

The entity MUST hold entitlements for BOTH `gamma` AND `delta` to gain access.
If the entity holds only `gamma`, access is denied.

### 4.2 anyOf (Disjunctive)

**Semantics**: The entity MUST possess an entitlement for AT LEAST ONE of the
listed attribute values of this definition to satisfy the rule.

**Formal definition**: Given a set of data attribute values
$V = \{v_1, v_2, \ldots, v_n\}$ from a single attribute definition with rule
type `anyOf`, and a set of entity entitlements $E$, the rule is satisfied if
and only if:

$$\exists v_i \in V : v_i \in E$$

**Evaluation procedure**:

1. For each attribute value FQN in the policy that belongs to this definition,
   check whether the entity holds an entitlement for that FQN with the
   requested action.
2. If AT LEAST ONE attribute value is found in the entity's entitlements, the
   rule PASSES.
3. If NONE of the attribute values are found, the rule FAILS and access MUST
   be denied.

**Key splitting implication**: All attribute values in an anyOf group share a
**single key split** (see Section 8). Any KAS in the group can authorize access
and release the shared key share.

**Example**:

Policy contains:
- `https://example.com/attr/department/value/engineering`
- `https://example.com/attr/department/value/research`

Where `department` is defined with rule type `anyOf`.

The entity MUST hold an entitlement for EITHER `engineering` OR `research` (or
both). If the entity holds `engineering` but not `research`, access is granted.
If the entity holds neither, access is denied.

### 4.3 hierarchy (Ordered)

**Semantics**: Attribute values are ordered from highest to lowest. An entity
that possesses an entitlement at a given level is also entitled to access data
at that level and all levels below it.

**Formal definition**: Given an ordered sequence of attribute values
$H = (h_1, h_2, \ldots, h_m)$ where $h_1$ is the highest level and $h_m$ is
the lowest, and a set of data attribute values
$V = \{v_1, v_2, \ldots, v_n\} \subseteq H$ from the policy, and a set of
entity entitlements $E$, the rule is satisfied if and only if:

Let $v^* = \min_{\text{index}}(V)$ be the highest-level data attribute value
in the policy. The rule passes if:

$$\exists h_j \in E : \text{index}(h_j) \leq \text{index}(v^*)$$

That is, the entity holds an entitlement at or above the highest level
required by the policy.

**Evaluation procedure**:

1. Determine the ordering of values from the attribute definition. The order
   is defined by the sequence of values in the attribute definition, where
   index 0 is the highest level and increasing indices represent lower levels.
2. Among the data attribute values in the policy that belong to this
   definition, identify the value with the lowest index (the highest level
   required).
3. Check whether the entity holds an entitlement for that value or for any
   value with a lower index (higher level) in the hierarchy.
4. If such an entitlement is found, the rule PASSES.
5. If no such entitlement is found, the rule FAILS and access MUST be denied.

**Key splitting implication**: Hierarchy rules are treated identically to anyOf
for key splitting purposes: all values share a **single key split** (see
Section 8).

**Example**:

Attribute definition `classification` with rule type `hierarchy` and ordered
values:

| Index | Value | Level |
|---|---|---|
| 0 | `top_secret` | Highest |
| 1 | `secret` | |
| 2 | `confidential` | |
| 3 | `unclassified` | Lowest |

Policy contains:
- `https://example.com/attr/classification/value/secret` (index 1)

An entity with entitlement for `top_secret` (index 0) satisfies the rule
because index 0 < index 1. An entity with entitlement for `secret` (index 1)
also satisfies the rule because index 1 = index 1. An entity with entitlement
for only `confidential` (index 2) does NOT satisfy the rule because
index 2 > index 1.

### 4.4 Cross-Definition Conjunction

When a policy contains attribute values from multiple distinct attribute
definitions, the access decision is the **conjunction** (logical AND) of the
per-definition rule evaluations:

$$\text{access} = \bigwedge_{d \in D} \text{rule}_d(V_d, E)$$

Where $D$ is the set of distinct attribute definitions represented in the
policy, $V_d$ is the subset of data attribute values belonging to definition
$d$, and $\text{rule}_d$ is the evaluation function for definition $d$'s rule
type.

**Example**:

A policy contains:
- `https://example.com/attr/classification/value/secret` (hierarchy rule)
- `https://example.com/attr/department/value/engineering` (anyOf rule)
- `https://example.com/attr/department/value/research` (anyOf rule)

For access to be granted, the entity MUST:
1. Hold a `classification` entitlement at `secret` level or higher, AND
2. Hold a `department` entitlement for `engineering` OR `research`.

### 4.5 Empty Data Attributes

When `body.dataAttributes` is an empty array, no attribute-based access control
is applied. In this case:

- If `body.dissem` is non-empty, only the dissemination check (Section 5)
  determines access.
- If both `body.dataAttributes` and `body.dissem` are empty, the KAS SHOULD
  grant access to any authenticated entity. This configuration is NOT
  RECOMMENDED for production use as it provides no access restriction beyond
  authentication.

### 4.6 Unregistered Attribute Values

If the policy contains an attribute value FQN that is not registered in the
authorization service's attribute definition registry, the KAS MUST deny access
to the resource. Unknown attribute values MUST NOT be silently ignored.

---

## 5. Dissemination List

### 5.1 Purpose

The dissemination list (`body.dissem`) provides an **identity-based access
control** mechanism that operates in addition to, not as a replacement for,
the attribute-based access control described in Section 4. It allows data
creators to restrict access to a specific set of named entities regardless of
their attribute entitlements.

### 5.2 Enforcement Requirements

**Reference**: BaseTDF-SEC, SI-3 (Dissemination Enforcement).

1. When `body.dissem` is a non-empty array, the KAS MUST verify that the
   authenticated entity's identity matches at least one entry in the
   dissemination list BEFORE releasing any key material.

2. The entity's identity MUST be determined from the authenticated access
   token's `sub` claim or equivalent identity assertion. The identity
   determination mechanism is the same as that used for attribute entitlement
   resolution.

3. If the entity's identity does not match any entry in the dissemination
   list, the KAS MUST deny the rewrap request and MUST NOT return any key
   material.

4. The dissemination check is **in addition to** the attribute-based access
   control evaluation (SI-2). Both checks MUST pass for key material to be
   released:

   ```
   access = attributeCheck(policy, entity) AND dissemCheck(policy, entity)
   ```

5. A passing attribute check does NOT override a failing dissemination check,
   and vice versa.

### 5.3 Matching Algorithm

1. Dissemination list entries are typically email addresses (e.g.,
   `alice@example.com`).

2. Matching SHOULD be case-insensitive for email-format identifiers, as
   specified by [RFC 5321][RFC5321] Section 2.4. For example,
   `Alice@Example.COM` and `alice@example.com` SHOULD be considered
   equivalent.

3. The KAS MUST perform an exact match (modulo case normalization) between the
   entity's identity and the dissemination list entries. Wildcard matching,
   domain-level matching, and regular expression matching are NOT defined by
   this specification.

4. If the entity has multiple identity claims (e.g., multiple email addresses
   or aliases), the KAS SHOULD check all available identity claims against the
   dissemination list.

### 5.4 Empty Dissemination List

When `body.dissem` is an empty array, no dissemination restriction is applied.
Attribute-based access control checks (Section 4) still apply if
`body.dataAttributes` is non-empty.

### 5.5 Example

```json
{
  "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "body": {
    "dataAttributes": [],
    "dissem": [
      "alice@example.com",
      "bob@example.com",
      "carol@example.com"
    ]
  }
}
```

In this example, no attribute-based checks are applied (empty
`dataAttributes`), but only `alice@example.com`, `bob@example.com`, and
`carol@example.com` may access the data.

---

## 6. Canonical Serialization and Policy Binding

### 6.1 Policy String

The policy object is serialized to JSON and then base64-encoded. This
base64-encoded string is stored in the manifest's
`encryptionInformation.policy` field. The **exact base64 string** as stored in
the manifest is the canonical representation used for policy binding
computation.

### 6.2 Binding Computation Input

The policy binding (defined in BaseTDF-KAO) is computed over the raw base64
string from `encryptionInformation.policy`:

```
binding = HMAC-SHA256(key=DEK_share, message=policy_base64_string)
```

The input to the HMAC is the **literal base64 string**, not the decoded JSON.

### 6.3 No Re-Serialization

Implementations MUST NOT re-encode, re-serialize, normalize, or otherwise
transform the policy string before computing or verifying the policy binding.
The binding is over the exact bytes of the base64 string as they appear in the
manifest.

**Rationale**: JSON serialization is not canonical -- different serializers may
produce different byte sequences for semantically identical JSON objects (e.g.,
different key ordering, different whitespace, different Unicode escaping). By
binding to the literal base64 string, the specification avoids requiring a
canonical JSON serialization algorithm and prevents a class of canonicalization
attacks where an attacker modifies the serialization without changing the
semantic content.

### 6.4 Implications for Implementations

- When creating a TDF, the implementation serializes the policy object to JSON,
  base64-encodes it, stores the result in `encryptionInformation.policy`, and
  uses that same string as the HMAC input.
- When verifying a policy binding, the KAS reads the
  `encryptionInformation.policy` string verbatim and uses it as the HMAC input.
  The KAS MUST NOT decode the base64, parse the JSON, re-serialize, and
  re-encode before verification.
- If the policy string is modified in transit (even by a semantically neutral
  transformation such as re-serializing the JSON with different whitespace),
  the policy binding verification will fail, and the KAS will correctly reject
  the KAO (SI-1).

---

## 7. KAS Grant Resolution

### 7.1 Overview

Each attribute value in a policy is associated with a KAS instance that holds
the corresponding key material. This association is called a **KAS grant**. KAS
grants determine which KAS a client must contact to obtain each key share
during the rewrap process.

### 7.2 Grant Hierarchy

KAS grants are resolved through a hierarchical lookup. When determining which
KAS holds the key for a given attribute value, the system checks for grants in
the following order of precedence:

1. **Value-level grant**: A KAS grant directly associated with the specific
   attribute value. This is the most specific grant and takes precedence.
2. **Definition-level grant**: A KAS grant associated with the attribute
   definition (parent of the value). Used when no value-level grant exists.
3. **Namespace-level grant**: A KAS grant associated with the attribute
   authority's namespace. Used as a fallback when neither value-level nor
   definition-level grants exist.

The first non-empty grant found in this hierarchy is used. If no grant is
found at any level, the implementation falls back to the default KAS
configuration.

### 7.3 Attribute Object `kasURL` Field

The `kasURL` field in the attribute object (Section 3.2) records the KAS URL
resolved at TDF creation time. During rewrap, the client uses this URL to
determine which KAS to contact for the corresponding key share.

When KAS grants are resolved from the policy service at TDF creation time:

1. The client queries the attribute service for the attribute definitions
   corresponding to the data attributes.
2. For each attribute value, the client resolves the KAS grant using the
   hierarchy in Section 7.2.
3. The resolved KAS URL is recorded in the attribute object's `kasURL` field.
4. The KAS URL is also recorded in the KAO's `url` field (see BaseTDF-KAO),
   which is the authoritative source for the rewrap client.

### 7.4 Multi-KAS Scenarios

Different attribute values MAY be associated with different KAS instances.
This is the basis for the split-key architecture:

- Attribute values from different authorities may naturally point to different
  KASes.
- Even within the same authority, value-level grants can direct specific
  values to different KASes.
- Each KAS independently holds a key share and independently authorizes
  access. An entity must obtain all required key shares from all relevant
  KASes to reconstruct the DEK.

### 7.5 KAS Key Identification

Each KAS grant includes (or resolves to) the KAS's public key, identified by
a key identifier (`kid`). The `kid` allows the KAS to select the correct
private key for unwrapping during rewrap. See BaseTDF-KAO for the `kid` field
specification.

---

## 8. Key Splitting and Rule Interaction

### 8.1 Overview

The attribute rule type determines how key material is split across KAS
instances. This section defines the relationship between attribute rules and
the key splitting topology. For the cryptographic details of key splitting
(XOR-based splitting), see BaseTDF-KAO.

### 8.2 Split Topology by Rule Type

#### 8.2.1 allOf: Separate Splits

For attribute definitions with rule type `allOf`, each attribute value maps to
a **separate key split**. Each split is independently wrapped to the KAS
associated with that attribute value.

```
Policy:  attr/clearance/value/gamma  (allOf)
         attr/clearance/value/delta  (allOf)

Splits:  Split A  ──>  KAS for gamma
         Split B  ──>  KAS for delta

DEK = Split A XOR Split B
```

Both KASes must independently authorize the entity and release their respective
key shares. The entity must obtain ALL shares to reconstruct the DEK. This
provides a cryptographic enforcement of the conjunctive access requirement: even
if one KAS is compromised or misconfigured, the DEK remains protected as long
as the other KAS correctly enforces its authorization.

#### 8.2.2 anyOf: Shared Split

For attribute definitions with rule type `anyOf`, all attribute values share a
**single key split**. The same key split is wrapped to each KAS associated with
any value in the group.

```
Policy:  attr/department/value/engineering  (anyOf)
         attr/department/value/research     (anyOf)

Splits:  Split C  ──>  KAS for engineering
         Split C  ──>  KAS for research

(Split C is the same material, wrapped to different KASes)
```

Any single KAS in the group can authorize the entity and release the key share.
This implements the disjunctive access requirement: the entity needs
authorization from only one of the KASes.

#### 8.2.3 hierarchy: Shared Split

For attribute definitions with rule type `hierarchy`, all attribute values
share a **single key split**, identical to the anyOf behavior.

```
Policy:  attr/classification/value/secret  (hierarchy)

Splits:  Split D  ──>  KAS for classification values

The same split is available from any KAS in the hierarchy group.
```

### 8.3 Cross-Definition Splitting

When a policy contains attribute values from multiple attribute definitions,
the key splits from each definition are combined conjunctively:

```
Policy:  attr/classification/value/secret      (hierarchy, Definition 1)
         attr/department/value/engineering      (anyOf, Definition 2)
         attr/department/value/research         (anyOf, Definition 2)

Splits:  Split 1 (from Definition 1)  AND  Split 2 (from Definition 2)

DEK = Split 1 XOR Split 2
```

Split 1 is shared across the KASes for the hierarchy definition. Split 2 is
shared across the KASes for the anyOf definition. The entity must obtain both
Split 1 and Split 2 to reconstruct the DEK.

### 8.4 Split ID

Each key split is identified by a **split ID** (`sid` field in the KAO). KAOs
that share the same split ID contain the same DEK share wrapped to different
KASes. The client uses the split ID to determine which KAOs are alternatives
(same split, different KAS) versus which represent independent shares that must
all be collected.

- KAOs with the **same** split ID: any ONE of them suffices (disjunction).
- KAOs with **different** split IDs: ALL of them are required (conjunction).

### 8.5 Deduplication

When the split plan is constructed, the implementation SHOULD deduplicate
splits that resolve to the same KAS. If two allOf values both resolve to the
same KAS URL, they MAY be merged into a single split to avoid redundant
wrapping. However, the deduplication MUST NOT change the access control
semantics: if two values from an allOf definition resolve to different KASes,
they MUST remain as separate splits.

---

## 9. Policy Evaluation Flow

This section describes the end-to-end flow for policy evaluation during a
rewrap request. This flow implements the security invariants SI-1, SI-2, and
SI-3 from BaseTDF-SEC.

### 9.1 Prerequisite: Policy Binding Verification (SI-1)

Before policy evaluation begins, the KAS MUST verify the policy binding as
specified in BaseTDF-KAO and SI-1. This step ensures the policy has not been
tampered with. If the policy binding verification fails, the KAS MUST reject
the request and MUST NOT proceed to policy evaluation.

### 9.2 Evaluation Steps

The following steps MUST be performed for each rewrap request:

```
┌─────────────────────────────────────────────────────┐
│ 1. Client presents rewrap request to KAS            │
│    - Signed Request Token (SRT) with KAO + policy   │
│    - DPoP-bound access token (entity identity)      │
└───────────────────────┬─────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│ 2. KAS verifies policy binding (SI-1)               │
│    - Unwrap DEK share from KAO                      │
│    - Compute HMAC-SHA256(DEK_share, policy_base64)  │
│    - Compare with policyBinding.hash                │
│    - REJECT if mismatch                             │
└───────────────────────┬─────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│ 3. KAS extracts data attributes from policy         │
│    - Decode policy from base64                      │
│    - Parse body.dataAttributes                      │
│    - Extract attribute value FQNs                   │
└───────────────────────┬─────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│ 4. KAS submits authorization request (SI-2)         │
│    - Attribute value FQNs (resource attributes)     │
│    - Entity token (subject identity)                │
│    - Requested action (decrypt/read)                │
│    - Fulfillable obligation FQNs (if applicable)    │
└───────────────────────┬─────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│ 5. Authorization service evaluates rules            │
│    - Resolve entity entitlements from identity      │
│    - Group resource attributes by definition        │
│    - Evaluate allOf/anyOf/hierarchy per definition  │
│    - Conjoin per-definition results                 │
│    - Return PERMIT or DENY                          │
└───────────────────────┬─────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│ 6. KAS enforces dissemination list (SI-3)           │
│    - If body.dissem is non-empty:                   │
│      - Verify entity identity in dissem list        │
│      - DENY if not found                            │
└───────────────────────┬─────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│ 7. KAS makes final access decision                  │
│    - PERMIT only if:                                │
│      - Policy binding verified (step 2)             │
│      - Attribute check passed (step 5)              │
│      - Dissem check passed (step 6)                 │
│    - DENY otherwise                                 │
└───────────────────────┬─────────────────────────────┘
                        │
                ┌───────┴───────┐
                │               │
             PERMIT           DENY
                │               │
                ▼               ▼
┌──────────────────┐  ┌──────────────────┐
│ 8a. Rewrap key   │  │ 8b. Return error │
│     share to     │  │     Log denial   │
│     client's     │  │     (SI-8)       │
│     ephemeral    │  └──────────────────┘
│     public key   │
│     Log permit   │
│     (SI-8)       │
└──────────────────┘
```

### 9.3 Authorization Service Interaction

The KAS communicates with the authorization service to evaluate attribute-based
access control. The authorization service:

1. **Resolves entity entitlements**: Determines which attribute values the
   entity is entitled to, based on the entity's identity token and the
   configured subject mappings.

2. **Groups resource attributes by definition**: The data attribute FQNs from
   the policy are grouped by their parent attribute definition. Each group is
   evaluated independently according to the definition's rule type.

3. **Evaluates rules**: For each definition group, the authorization service
   evaluates the appropriate rule (allOf, anyOf, or hierarchy) as defined in
   Section 4.

4. **Returns a decision**: The authorization service returns a PERMIT or DENY
   decision for each resource (policy). The KAS MUST receive an explicit
   PERMIT decision before proceeding.

### 9.4 Per-Request Evaluation

Policy evaluation MUST occur for every rewrap request. The KAS MUST NOT cache
authorization decisions across requests. This ensures that changes to entity
entitlements, attribute definitions, or subject mappings take effect immediately
on the next rewrap request (see BaseTDF-SEC Section 2.2, Tenet 4: Dynamic
Policy).

### 9.5 Unavailable Authorization Service

If the authorization service is unavailable or returns an error, the KAS MUST
deny the rewrap request. The KAS MUST NOT fall back to a default-permit
decision when the authorization service cannot be reached. This fail-closed
behavior ensures that network partitions or service outages do not result in
unauthorized access.

---

## 10. Security Considerations

### 10.1 Policy Integrity (SI-1)

The policy object is integrity-protected via the policy binding mechanism
defined in BaseTDF-KAO. The binding is an HMAC-SHA256 computed over the
base64-encoded policy string using the DEK share as the key. Because the DEK
share is encrypted to the KAS public key, an attacker without the KAS private
key cannot forge a valid binding for a modified policy.

Any modification to the policy -- including semantically neutral changes such
as whitespace normalization or key reordering -- will cause the binding
verification to fail, and the KAS will reject the request (see Section 6.3).

### 10.2 Authorization Before Key Release (SI-2)

The KAS MUST evaluate the policy's data attributes against the entity's
entitlements before releasing any key material. This evaluation MUST be
performed by the authorization service for every rewrap request. The KAS MUST
NOT release key material based on cached decisions, local policy overrides, or
any other mechanism that bypasses the authorization service.

If the policy's `dataAttributes` array is empty, the attribute check is
trivially satisfied, but the dissemination check (SI-3) still applies.

### 10.3 Dissemination Enforcement (SI-3)

When the policy contains a non-empty dissemination list, the KAS MUST verify
the entity's identity against the list as an additional access control check.
This check is not a substitute for attribute evaluation and MUST be performed
even when the attribute check passes. Conversely, a passing dissemination
check does not bypass a failing attribute check.

Implementations that do not enforce the dissemination list when it is present
are non-conformant with this specification and with SI-3.

### 10.4 Dynamic Evaluation

Policy evaluation occurs at rewrap time, not at TDF creation time. This means:

- Revoking an entity's attribute entitlement takes effect on the next rewrap
  request, without requiring re-encryption of existing TDFs.
- Adding new attribute values to an entity's entitlements grants access to
  TDFs whose policies require those values, without re-encryption.
- Changes to attribute definitions (e.g., changing a rule type from anyOf to
  allOf) take effect on the next rewrap request.

This dynamic evaluation model is a core property of the BaseTDF zero trust
architecture (see BaseTDF-SEC Section 2.2, Tenet 4).

### 10.5 Attribute Enumeration

An attacker with valid credentials could systematically create TDFs with
different attribute combinations and observe rewrap success or failure to
enumerate which attributes they hold. The KAS SHOULD implement rate limiting
on rewrap requests and SHOULD return uniform error responses for all denial
reasons to mitigate this attack (see BaseTDF-SEC Section 4.3).

### 10.6 Policy Object in Cleartext

The policy object is stored in the TDF manifest, which is not encrypted. An
attacker with access to the TDF can read the policy and learn:

- Which attribute values are required for access.
- Which entities are in the dissemination list.
- Which KAS instances are involved.

This metadata exposure is an inherent trade-off of the BaseTDF design: the
policy must be readable by the client and KAS to perform the rewrap protocol.
Organizations that consider this metadata sensitive SHOULD apply transport-level
and storage-level access controls to TDF objects in addition to the
data-centric protections.

---

## 11. Normative References

| Reference | Title |
|---|---|
| [NIST SP 800-162][SP800-162] | Guide to Attribute Based Access Control (ABAC) Definition and Considerations |
| [RFC 2119][RFC2119] | Key words for use in RFCs to Indicate Requirement Levels |
| [RFC 8174][RFC8174] | Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words |
| [RFC 9562][RFC9562] | Universally Unique IDentifiers (UUIDs) |
| [RFC 3986][RFC3986] | Uniform Resource Identifier (URI): Generic Syntax |
| [RFC 5321][RFC5321] | Simple Mail Transfer Protocol |

[SP800-162]: https://doi.org/10.6028/NIST.SP.800-162
[RFC2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC8174]: https://www.rfc-editor.org/rfc/rfc8174
[RFC9562]: https://www.rfc-editor.org/rfc/rfc9562
[RFC3986]: https://www.rfc-editor.org/rfc/rfc3986
[RFC5321]: https://www.rfc-editor.org/rfc/rfc5321
