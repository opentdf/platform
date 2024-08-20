# Diagram for 20240729000000_drop_attribute_value_members.sql

## Removes 'attribute_value_members'

This migration ERD documents changes in the platform architecture to remove 'members'
from policy. ADR can be [viewed here](https://github.com/opentdf/platform/issues/984).


```mermaid
---
title: Attribute Value Mermaid Diagram
nodes: |
---

erDiagram

    AttributeValue {
        uuid         id                      PK
        uuid         namespace_id            FK
        uuid         attribute_definition_id FK
        varchar      value
        jsonb        metadata
        compIdx      comp_key                UK "ns_id + ad_id + value"
        bool         active
    }

```
