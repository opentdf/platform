# Diagram for 20240405000000_update_selector_field_name.sql

## Background

This schema reflects an update to `SubjectConditionSets`, which map external fields and values, like those
provided in the context received about a subject/user from an Identity Provider (idP) to an `Attribute Value`
by way of a `SubjectMapping`. Each `Condition` will be driven by the fields and values of an external user
store, and the syntax to select the appropriate field off the user store (or "subject context"), be it an
access token, JSON representation, endpoint/webhook response value, etc, will be housed within the Condition
field `subject_external_selector_value`, which was formerly called `subject_external_field`.

# ERD

```mermaid
---
title: Database Schema Mermaid Diagram
---

erDiagram

    SubjectMapping }|--|| AttributeValue: has
    SubjectMapping }|--|| SubjectConditionSet: "has"

    AttributeValue {
        uuid         id                      PK
        uuid         attribute_definition_id FK
        varchar      value
        uuid[]       members                 FK "Optional grouping of values"
        jsonb        metadata
        timestamp    created_at
        timestamp    updated_at
        compIdx      comp_key                UK "ns_id + ad_id + value"
        bool         active
    }

    SubjectMapping {
        uuid           id                          PK
        uuid           attribute_value_id          FK
        uuid[]         subject_condition_set_id    FK "subject condition sets are reusable"
        jsonb          actions
        jsonb          metadata
        timestamp      created_at
        timestamp      updated_at
    }

    SubjectConditionSet {
        uuid            id                              PK
        jsonb           condition                "marshaled proto SubjectSets -> ConditionGroups -> Conditions"
        jsonb           metadata
        timestamp       created_at
        timestamp       updated_at
    }

    SubjectMapping }|--|| AttributeValue: has
    SubjectConditionSet ||--|{ SubjectSets: "marshals in condition column"
    SubjectSets ||--|{ ConditionGroups: has
    ConditionGroups ||--|{ Conditions: has

    Conditions {
        varchar         subject_external_selector_value
        varchar[]       subject_external_values
        enum            operator "IN | NOT IN"
    }

    ConditionGroups {
        enum            boolean_operator "AND | OR"
    }

    SubjectSets {}
```
