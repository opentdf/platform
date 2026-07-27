---
title: Create a new dynamic value mapping
command:
  name: create
  aliases:
    - new
    - add
    - c
  flags:
    - name: attribute
      description: URI or ID of the Attribute Definition to scope the mapping to
      shorthand: a
    - name: selector
      description: Selector for a field on the flattened Entity Representation (e.g. '.patientAssignments[]')
      shorthand: s
    - name: operator
      description: How the requested resource value segment is compared against each entity selector value
      shorthand: o
      enum:
        - IN
        - IN_CONTAINS
    - name: action
      description: Each 'id' or 'name' of an Action to be entitled (i.e. 'create', 'read', 'update', 'delete'). At least one is required.
    - name: subject-condition-set
      description: "Static pre-gate Subject Condition Set: either a known preexisting Subject Condition Set ID, or a JSON array of Subject Sets to create a new one"
    - name: namespace
      description: Namespace ID or FQN
      shorthand: n
    - name: label
      description: "Optional metadata 'labels' in the format: key=value"
      shorthand: l
---

Create a Dynamic Value Mapping to entitle dynamically-requested Attribute Values under an Attribute
Definition. At decision time the resolver compares the requested resource value segment against each
value the `--selector` resolves from the Entity Representation, using the `--operator`.

The `--operator` must be one of `IN` (exact match) or `IN_CONTAINS` (substring match, over-matches by
design). `NOT_IN` is not supported because dynamic resolution is existential over the resolved entity
values.

The `--attribute` flag is required and accepts either the URI (FQN) or ID of the Attribute
Definition to scope the mapping to. A HIERARCHY Attribute Definition is not supported.

Optionally provide a static pre-gate Subject Condition Set with `--subject-condition-set`, which
accepts either an existing Subject Condition Set ID or a JSON array of Subject Sets to create a new
one. When a gate is present, both the gate and the resolver must pass for entitlement.

For more information about attribute definitions, see the `attributes` subcommand.

For more information about subject condition sets, see the `subject-condition-sets` subcommand.

## Examples

Create a dynamic value mapping entitling 'read' where a patient assignment matches the requested value:

```shell
otdfctl policy dynamic-value-mappings create --attribute 891cfe85-b381-4f85-9699-5f7dbfe2a9ab --selector '.patientAssignments[]' --operator IN --action read
```

Create a dynamic value mapping scoped by Attribute Definition FQN with a substring operator:

```shell
otdfctl policy dynamic-value-mappings create --attribute https://hospital.co/attr/mrn --selector '.patientAssignments[]' --operator IN_CONTAINS --action read
```

Create a dynamic value mapping with a static pre-gate Subject Condition Set:

```shell
otdfctl policy dynamic-value-mappings create --attribute 891cfe85-b381-4f85-9699-5f7dbfe2a9ab --selector '.patientAssignments[]' --operator IN --action read --subject-condition-set '[
  {
    "condition_groups": [
      {
        "conditions": [
          {
            "operator": 1,
            "subject_external_values": ["clinician"],
            "subject_external_selector_value": ".role"
          }
        ],
        "boolean_operator": 1
      }
    ]
  }
]'
```
