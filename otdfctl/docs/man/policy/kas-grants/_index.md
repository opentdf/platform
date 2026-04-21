---
title: (Deprecated) Manage Key Access Server grants

command:
  name: kas-grants
  aliases:
    - kasg
    - kas-grant
---
# Deprecated

Once Key Access Servers (KASs) have been registered within a platform's policy,
they can be assigned grants to various attribute objects (namespaces, definitions, values).

> See `kas-registry` command within `policy` to manage the KASs known to the platform.

Key Access Grants are associations between a registered KAS (see KAS Registry docs) and an Attribute.

An attribute can be assigned a KAS Grant on its namespace, its definition, or any one of its values.

Grants enable key split behaviors on TDFs with attributes, which can be useful for various collaboration scenarios around shared policy.

> [!WARNING]
> KAS Grants are considered experimental, as grants to namespaces are not fully utilized within encrypt/decrypt flows at present.

## Utilization

The steps below are driven by the SDK on encrypt, and they are the same steps followed
on decrypt by a KAS making a decision request on a key release (once the decision
is found to be permissible):

1. look up the attributes on the TDF within the platform
2. find any associated grants for those attributes' values, definitions, namespaces
3. retrieve the public key of each KAS granted to those attribute objects
4. determine based on the specificity matrix below which keys to utilize in splits

## Specificity

When KAS grants are considered, they follow a most-to-least specificity matrix. Grants to
Attribute Values supersede any grants to Definitions which also supersede any grants to a Namespace.

Grants to Attribute Objects:

| Namespace Grant | Attr Definition Grant | Attr Value Grant | Data Encryption Key Utilized |
| --------------- | --------------------- | ---------------- | ---------------------------- |
| yes             | no                    | no               | namespace                    |
| yes             | yes                   | no               | attr definition              |
| no              | yes                   | no               | attr definition              |
| yes             | yes                   | yes              | value                        |
| no              | yes                   | yes              | value                        |
| no              | no                    | yes              | value                        |
| no              | no                    | no               | default KAS/platform key     |

> [!NOTE]
> A namespace grant may soon be required with deprecation of a default KAS/platform key.

## Split Scenarios

### AnyOf Split

`Bob` and `Alice` want to share data equally, but maintain their ability to decrypt the data without sharing each other’s private keys.

With KAS Grants, they can define a key split where the shared data is wrapped with both of their public keys and AnyOf logic, meaning that each partner could decrypt the data with just one of those keys.

If `Bob` assigns a grant between Bob's running/registered KAS to a known attribute value, and `Alice` defines a grant of Alice's running/registered KAS to the same attribute value,
any data encrypted in a TDF will be decryptable with a key released by _either_ of their Key Access Servers.

Attribute A: `https://conglomerate.com/attr/organization/value/acmeco`

Attribute B: `https://conglomerate.com/attr/organization/value/example_inc`

| Attribute | Namespace        | Definition   | Value       |
| --------- | ---------------- | ------------ | ----------- |
| A         | conglomerate.com | organization | acmeco      |
| B         | conglomerate.com | organization | example_inc |

**Attribute KAS Grant Scenarios**

1. Bob & Alice represent individual KAS Grants to attributes on TDF'd data
2. Note that the attributes A and B are of _the same definition and namespace_

| Definition: organization | Value: acmeco | Value: example_inc | Split |
| ------------------------ | ------------- | ------------------ | ----- |
| Bob, Alice               | -             | -                  | OR    |
| -                        | Bob, Alice    | -                  | OR    |
| -                        | -             | Bob, Alice         | OR    |
| -                        | Bob           | Alice              | OR    |

### AllOf Split

Unlike the `AnyOf` split above, this time `Bob` and `Alice` want to make sure _both_ of their keys must be granted for data in a TDF
to be decrypted. With KAS Grants, they can define a key split where the shared data is wrapped with both of their public keys and
AllOf logic, meaning that neither partner can decrypt the data with just one of those keys.

To accomplish this, they each define KAS Grants between their KASes and policy attributes, and TDF data with at least two attributes -
one assigned a KAS Grant to Bob's KAS and another assigned a KAS Grant to Alice's KAS.

Both KASes will need to permit access and release payload keys for the data TDF'd with multiple attributes assigned KAS Grants to be accessible and decrypted.

Attribute A: `https://conglomerate.com/attr/organization/value/acmeco`

Attribute B: `https://conglomerate.com/attr/department/value/marketing`

| Attribute | Namespace        | Definition   | Value     |
| --------- | ---------------- | ------------ | --------- |
| A         | conglomerate.com | organization | acmeco    |
| A         | conglomerate.com | department   | marketing |

**Attribute KAS Grant Scenarios**

1. Bob & Alice represent individual KAS Grants to attributes on TDF'd data
2. Note that the attributes A and B are of _the same namespace but different definitions_

| Definition: A | Value: A | Definition: B | Value: B | Split |
| ------------- | -------- | ------------- | -------- | ----- |
| Bob           | -        | Alice         | -        | AND   |
| Bob           | -        | -             | Alice    | AND   |
| -             | Bob      | -             | Alice    | AND   |

> [!NOTE]
> Any KAS Grants to attributes across different definitions or namespaces will be `AND` splits.
