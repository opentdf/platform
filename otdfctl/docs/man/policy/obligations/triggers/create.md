---
title: Create an obligation trigger
command:
  name: create
  aliases:
    - c
    - add
    - new
  flags:
    - name: attribute-value
      description: Attribute value ID or FQN
      required: true
    - name: action
      description: Action ID or Name
      required: true
    - name: obligation-value
      description: Obligation value ID or FQN
      required: true
    - name: client-id
      description: Create a scoped trigger. Optionally include the clientID for which this trigger should be scoped to.
    - name: label
      description: "Optional metadata 'labels' in the format: key=value"
      shorthand: l
---

Add an obligation trigger to the platform Policy with our without a client identifier.

>[!NOTE]
>Creating an obligation trigger with a client-id scopes the
>trigger to a specific policy enforcement point, which is identified
>through the requestor's authentication token.
>Scoping a trigger to a specific client does two things:
>
>1. If the requesting application is **NOT** scoped to the trigger, it will not be used in the authorization decisioning and the obligation does not need to be fulfilled.
>2. If the requesting application **IS** scoped to the trigger, the application must
>be able to fulfill the obligation the trigger is mapped to.

## Examples

Create an obligation trigger with FQNs/Names:

```shell
otdfctl policy obligations triggers create --attribute-value "https://example.com/attr/classification/value/confidential" --action "read" --obligation-value "https://example.com/obl/test/value/mfa"
```

Create an obligation trigger with IDs

```shell
otdfctl policy obligations triggers create --attribute-value "d10e0fb6-4b4a-4976-8036-33903ebc6be3" --action "f15f65db-6889-453a-b032-212f78e8eb18" --obligation-value "0cbbb9bb-ed2d-41c0-8efa-1bcdddc44771"
```

Create a scoped obligation trigger with IDs.

```shell
otdfctl policy obligations triggers create --attribute-value "d10e0fb6-4b4a-4976-8036-33903ebc6be3" --action "f15f65db-6889-453a-b032-212f78e8eb18" --obligation-value "0cbbb9bb-ed2d-41c0-8efa-1bcdddc44771" --client-id "my-service"
```
