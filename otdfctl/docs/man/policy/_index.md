---
title: Manage policy

command:
  name: policy
  aliases:
    - pol
    - policies
  flags:
    - name: json
      description: output single command in JSON (overrides configured output format)
      default: 'false'
---

Policy is a set of rules that are enforced by the platform. Specific to the the data-centric
security, policy revolves around data attributes (referred to as attributes). Within the context
of attributes are namespaces, values, subject-mappings, resource-mappings, registered-resources, key-access-server grants,
and other key elements.
