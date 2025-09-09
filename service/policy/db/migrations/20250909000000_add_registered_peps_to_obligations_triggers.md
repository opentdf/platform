# Add Registered_Peps Column Migration

Adds a column for connecting registered peps with obligations. Doing so bridges the gap between PEPs and Obligations.
"this" obligation.

## Schema Changes

```mermaid
erDiagram
    %% Before Migration
    obligation_triggers_before {
        UUID id PK
        UUID attribute_value_id FK
        UUID obligation_value_id FK
        UUID action_id FK
        jsonb metadata
        timestamp created_at
        timestamp updated_at
    }

    %% After Migration  
    obligation_triggers_after {
        uuid action_id FK,UK 
        uuid attribute_value_id FK,UK 
        timestamp_with_time_zone created_at 
        uuid id PK 
        jsonb metadata 
        uuid obligation_value_id FK,UK 
        jsonb registered_peps "Holds the RegisteredPEP objects that are associated with this trigger. Map contains client_id -> RegisteredPEP object"
        timestamp_with_time_zone updated_at 
    }
```

## Key Changes

### 1. **Column Addition**

- Require registered_peps to be apart of a trigger.
