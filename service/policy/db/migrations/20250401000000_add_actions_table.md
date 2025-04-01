# Add Actions Table

Actions will evolve from a simple enum with limited options (decrypt, transmit) defined solely in protos
to a comprehensive CRUD-inspired policy object with dedicated database storage, explicit relationships to subject
mappings and (incoming) obligations, and improved API support.

This enhancement provides greater flexibility for defining permitted operations on protected
resources while eliminating confusion in action handling across the platform.

```mermaid

erDiagram

    SubjectMapping {
        uuid           id                          PK
        uuid           attribute_value_id          FK
        uuid[]         subject_condition_set_id    FK
        uuid[]         actions                     FK "actions are now defined in actions table"
        jsonb          metadata
        timestamp      created_at
        timestamp      updated_at
    }

    Actions {
        uuid        id              PK  "id used for administration"
        name        varchar         UK  "unique name of the action"
        bool        is_standard         "only custom actions can be updated/deleted"
        jsonb       metadata
        timestamp   created_at
        timestamp   updated_at
    }

    SubjectMapping 1 -- 1+ Actions : "has"

```
