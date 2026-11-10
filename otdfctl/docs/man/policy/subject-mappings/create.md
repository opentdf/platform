---
title: Create a new subject mapping
command:
  name: create
  aliases:
    - new
    - add
    - c
  flags:
    - name: attribute-value-id
      description: The ID of the attribute value to map to a subject condition set
      shorthand: a
      required: true
    - name: action
      description: Each 'id' or 'name' of an Action to be entitled (i.e. 'create', 'read', 'update', 'delete')
    - name: subject-condition-set-id
      description: Known preexisting Subject Condition Set Id
    - name: subject-condition-set-new
      description: JSON array of Subject Sets to create a new Subject Condition Set associated with the created Subject Mapping
    - name: label
      description: "Optional metadata 'labels' in the format: key=value"
      shorthand: l
    - name: action-standard
      description: Deprecated. Migrated to '--action'.
      shorthand: s
    - name: action-custom
      description: Deprecated. Migrated to '--action'.
      shorthand: c
---

Create a Subject Mapping to entitle an entity (via an existing or new Subject Condition Set) to Action(s)
on an Attribute Value.

Subject Mappings may entitle Actions with standard names ('create', 'read', 'update', 'delete'), custom names,
or by their stored 'id' within policy. If the referenced Action name does not already exist within policy,
it will be created along with the new Subject Mapping.

For more information about actions, see the `actions` subcommand.

For more information about subject mappings, see the `subject-mappings` subcommand.

For more information about subject condition sets, see the `subject-condition-sets` subcommand.

## Examples

Create a subject mapping for a 'read' action linking to an existing subject condition set:
```shell
otdfctl policy subject-mapping create --attribute-value-id 891cfe85-b381-4f85-9699-5f7dbfe2a9ab --action read --subject-condition-set-id 8dc98f65-5f0a-4444-bfd1-6a818dc7b447
```

Or you can create a mapping for 'read' or 'create' linking to a new subject condition set:
```shell
otdfctl policy subject-mapping create --attribute-value-id 891cfe85-b381-4f85-9699-5f7dbfe2a9ab --action create --action update --subject-condition-set-new '[                                           
  {
    "condition_groups": [
      {
        "conditions": [
          {
            "operator": 1,
            "subject_external_values": ["myvalue", "myothervalue"],
            "subject_external_selector_value": ".example.field.one"
          },
          {
            "operator": 2,
            "subject_external_values": ["notpresentvalue"],
            "subject_external_selector_value": ".example.field.two"
          }
        ],
        "boolean_operator": 2
      }
    ]
  }
]'
```
