---
title: Create a new dynamic value mapping
command:
  name: create
  aliases:
    - new
    - add
    - c
  flags:
    - name: attribute-definition-id
      description: The ID of the Attribute Definition to scope the mapping to
      shorthand: a
    - name: attribute-definition-fqn
      description: The FQN of the Attribute Definition to scope the mapping to
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
      description: Each 'id' or 'name' of an Action to be entitled (i.e. 'create', 'read', 'update', 'delete')
    - name: subject-condition-set-id
      description: Known preexisting Subject Condition Set Id to use as a static pre-gate
    - name: subject-condition-set-new
      description: JSON array of Subject Sets to create a new static pre-gate Subject Condition Set associated with the created Dynamic Value Mapping
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

Exactly one of `--attribute-definition-id` or `--attribute-definition-fqn` is required. A HIERARCHY
Attribute Definition is not supported.

Optionally provide a static pre-gate Subject Condition Set with either `--subject-condition-set-id`
(existing) or `--subject-condition-set-new` (JSON to create a new one). When a gate is present, both
the gate and the resolver must pass for entitlement.

For more information about attribute definitions, see the `attributes` subcommand.

For more information about subject condition sets, see the `subject-condition-sets` subcommand.

## Examples

Create a dynamic value mapping entitling 'read' where a patient assignment matches the requested value:
```shell
otdfctl policy dynamic-value-mappings create --attribute-definition-id 891cfe85-b381-4f85-9699-5f7dbfe2a9ab --selector '.patientAssignments[]' --operator IN --action read
```

Create a dynamic value mapping scoped by Attribute Definition FQN with a substring operator:
```shell
otdfctl policy dynamic-value-mappings create --attribute-definition-fqn https://hospital.co/attr/mrn --selector '.patientAssignments[]' --operator IN_CONTAINS --action read
```

Create a dynamic value mapping with a static pre-gate Subject Condition Set:
```shell
otdfctl policy dynamic-value-mappings create --attribute-definition-id 891cfe85-b381-4f85-9699-5f7dbfe2a9ab --selector '.patientAssignments[]' --operator IN --action read --subject-condition-set-new '[
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
