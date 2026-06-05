---
title: Generate a set of selector expressions for keys and values of a Subject Context
command:
  name: generate
  aliases:
    - gen
  flags:
    - name: subject
      shorthand: s
      description: A Subject Context string (JSON or JWT, default JSON)
      default: ''
---

Take in an Entity Representation as a JWT or JSON object, such as that provided by
an Identity Provider (idP), LDAP, or OIDC Access Token JWT, and generate
sample selectors employing [flattening syntax](#flattening-syntax) to utilize within
within Subject Condition Sets that resolve an external Subject Context into mapped Attribute
Values.

# Flattening-syntax

The platform maintains a very simple flattening library such that the below structure flattens into the key/value pairs beneath.

Subject input (`--subject`):

```json
{
  "key": "abc",
  "something": {
    "nested": "nested_value",
    "list": ["item_1", "item_2"]
  }
}
```

Generated Selectors:

| Selector             | Value          | Significance              |
| -------------------- | -------------- | ------------------------- |
| ".key"               | "abc"          | specified field           |
| ".something.nested"  | "nested_value" | nested field              |
| ".something.list[0]" | "item_1"       | first index specifically  |
| ".something.list[]"  | "item_1"       | any index in the list     |
| ".something.list[1]" | "item_2"       | second index specifically |
| ".something.list[]"  | "item_2"       | any index in the list     |
