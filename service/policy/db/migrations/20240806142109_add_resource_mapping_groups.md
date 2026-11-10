# Diagram for 20240806142109_add_resource_mapping_groups.sql

## Background

This schema reflects the addition of a `resource_mapping_groups` table, allowing existing Resource Mappings to be grouped by namespace and a common name. The migration also updates the `resource_mappings` table to include a `group_id` column, which will be used to optionally associate a Resource Mapping with a group.

# ERD

```mermaid
---
title: Database Schema Mermaid Diagram
---

erDiagram

    ResourceMappingGroup ||--|{ ResourceMapping : has

    ResourceMappingGroup {
        uuid         id                 PK
        uuid         namespace_id
        varchar      name
        compIdx      comp_key           UK "namespace_id + name"
    }

    ResourceMapping {
        uuid         id                 PK
        uuid         attribute_value_id FK
        varchar[]    terms
        jsonb        metadata
        uuid         group_id           FK
    }
```