---
title: Create a Subject Condition Set

command:
  name: create
  aliases:
    - c
    - add
    - new
  flags:
    - name: subject-sets
      description: A JSON array of subject sets, containing a list of condition groups, each with one or more conditions
      shorthand: s
      required: true
      default: ''
    - name: subject-sets-file-json
      description: A JSON file with path from the current working directory containing an array of subject sets
      shorthand: j
      default: ''
      required: false
    - name: label
      description: "Optional metadata 'labels' in the format: key=value"
      shorthand: l
      default: ''
    - name: force-replace-labels
      description: Destructively replace entire set of existing metadata 'labels' with any provided to this command
      default: false
---

### Example Subject Condition Sets

`--subject-sets` example input:

```json
[
  {
    "condition_groups": [
      {
        "conditions": [
          {
            "operator": 1,
            "subject_external_values": ["CoolTool", "RadService", "ShinyThing"],
            "subject_external_selector_value": ".team.name"
          },
          {
            "operator": 2,
            "subject_external_values": ["marketing"],
            "subject_external_selector_value": ".org.name"
          }
        ],
        "boolean_operator": 1
      }
    ]
  }
]
```

ConditionGroup `boolean_operator` is driven through the API `CONDITION_BOOLEAN_TYPE_ENUM` definition:

| CONDITION_BOOLEAN_TYPE_ENUM | index value | comparison            |
| --------------------------- | ----------- | --------------------- |
| AND                         | 1           | all conditions met    |
| OR                          | 2           | any one condition met |

Condition `operator` is driven through the API `SUBJECT_MAPPING_OPERATOR_ENUM` definition,
and is evaluated by applying the `subject_external_selector_value` to the Subject entity
representation (token or Entity Resolution Service response) and comparing the logical operator
against the list of `subject_external_values`:

| SUBJECT_MAPPING_OPERATOR_ENUM | index value | subject value at selector MUST |
| ----------------------------- | ----------- | ------------------------------ |
| IN                            | 1           | be any of the values           |
| NOT_IN                        | 2           | not be any of the values       |
| IN_CONTAINS                   | 3           | contain one of the values      |

In the example SCS above, the Subject entity MUST BE represented with a token claim or ERS response
containing a field at `.team.name` identifying them as team name "CoolTool", "RadService", or "ShinyThing", AND THEY MUST ALSO have a field `org.name` that is NOT "marketing".

This structure if their team name was "CoolTool" and they were entitled might look like:

```json
{
  "team": {
    "name": "CoolTool" // could alternatively be RadService or ShinyThing
  },
  "org": {
    "name": "sales"
  }
}
```

If any condition in the group is not met (such as if `.org.name` were `marketing` instead),
the condition set would not resolve to true, and the Subject would not be found to be entitled
to the Attribute Value applicable to this Subject Condition Set via Subject Mapping between.

For more information about subject condition sets, see the `subject-condition-sets` subcommand.

## Examples

The following subject condition set would resolve to true if the field at `.example.field.one` is 
`myvalue` or `myothervalue1`, or the field at `.example.field.two` is not equal to `notpresentvalue`.
```shell
otdfctl policy subject-condition-set create --subject-sets '[
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

You can perform the same action with the input contained in a file:
```shell
otdfctl policy subject-condition-set create --subject-sets-file-json scs.json
```
