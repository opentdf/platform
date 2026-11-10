---
title: Test resolution of a set of selector expressions for keys and values of a Subject Context.
command:
  name: test
  flags:
    - name: subject
      shorthand: s
      description: A Subject Context string (JSON or JWT, auto-detected)
      default: ''
    - name: selector
      shorthand: x
      description: "Individual selectors to test against the Subject Context (i.e. '.key,.realm_access.roles[]')"
---

Test a subject Entity Representation as a JWT or JSON object, such as that provided by
an Identity Provider (idP), LDAP, or OIDC Access Token JWT, against provided selectors employing [flattening syntax](#flattening-syntax) to
validate their resolution to field values on the subject's entity representation.

# Flattening-syntax

The platform maintains a very simple flattening library such that the below structure flattens into the key/value pairs beneath.

Original:

```json
{
  "key": "abc",
  "something": {
    "nested": "nested_value",
    "list": ["item_1", "item_2"]
  }
}
```

Flattened:

| Selector             | Value          | Significance              |
| -------------------- | -------------- | ------------------------- |
| ".key"               | "abc"          | specified field           |
| ".something.nested"  | "nested_value" | nested field              |
| ".something.list[0]" | "item_1"       | first index specifically  |
| ".something.list[]"  | "item_1"       | any index in the list     |
| ".something.list[1]" | "item_2"       | second index specifically |
| ".something.list[]"  | "item_2"       | any index in the list     |

Testing the example above with `--selector '.key'` would find the value `abc` on the `key` field and return it in the command output.

Testing the example above with `--selector .values[]` would not find a list at a field named `values` because it is missing entirely from the input object.
