---
title: Match a subject or set of selectors to relevant subject mappings
command:
  name: match
  flags:
    - name: subject
      shorthand: s
      description: A Subject Entity Representation string (JSON or JWT, auto-detected)
      default: ''
    - name: selector
      shorthand: x
      description: "Individual selectors (i.e. '.department' or '.realm_access.roles[]') that may be found in SubjectConditionSets"
---

This tool queries platform policies for relevant Subject Mappings using either an Entity Representation or specific selectors.

If an Entity Representation is provided via `--subject` (such as an OIDC JWT or JSON response from an Entity Resolution Service), the tool
parses all valid selectors and checks for matching Subject Condition Sets in Subject Mappings to Attribute Values.

If selectors are provided directly with `--selector`, the tool searches for Subject Mappings with Subject Condition Sets that contain those selectors.

## Examples

Various ways to invoke the `match` command to query Subject Mappings to Attribute Values with relevant Subject Condition Sets.

```shell
# matches either org name or department selectors
otdfctl policy subject-mappings match --selector '.org.name' --selector '.department'

# parses subject entity representation as JSON and matches any selector (with this subject only '.emailAddress')
otdfctl policy subject-mappings match --subject '{"emailAddress":"user@email.com"}'

# parses entity representation as JWT into all possicle claim selectors and matches any of them
otdfctl policy subject-mappings match --subject 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
```

> [!NOTE]
> The values of the selectors and any `IN`/`NOT_IN`/`IN_CONTAINS` logic of Subject Condition Sets is irrelevant to this command.
> Evaluation of any matched conditions is handled by the Authorization Service to determine entitlements. This command
> is specifically for management of policy - to facilitate lookup of current conditions driven by known selectors as a
> precondition for administration of entitlement given the logical _operators_ of the matched conditions and their relations.
