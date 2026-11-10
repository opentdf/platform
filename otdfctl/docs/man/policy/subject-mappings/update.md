---
title: Update a subject mapping
command:
  name: update
  aliases:
    - u
  flags:
    - name: id
      description: The ID of the subject mapping to update
      shorthand: i
      required: true
    - name: action
      description: Each 'id' or 'name' of an Action to be entitled (i.e. 'create', 'read', 'update', 'delete')
    - name: action-standard
      description: Deprecated. Migrated to '--action'.
      shorthand: s
    - name: action-custom
      description: Deprecated. Migrated to '--action'.
      shorthand: c
    - name: subject-condition-set-id
      description: Known preexisting Subject Condition Set Id
      required: false
    - name: label
      description: "Optional metadata 'labels' in the format: key=value"
      shorthand: l
    - name: force-replace-labels
      description: Destructively replace entire set of existing metadata 'labels' with any provided to this command
      default: false
---

Update a Subject Mapping to alter entitlement of an entity to an Attribute Value.

`Actions` are updated in place, destructively replacing the current set. If you want to add or remove actions, you must provide the full set of actions on update.

At this time, creation of a new SCS during update of a subject mapping is not supported.

For more information about subject mappings, see the `subject-mappings` subcommand.

For more information about subject condition sets, see the `subject-condition-sets` subcommand.

## Example

```shell
otdfctl policy subject-mappings update --id 39866dd2-368b-41f6-b292-b4b68c01888b --action read
```
