# Add Registered_Peps Column Migration

Adds a column for connecting a client with obligations. Doing so bridges the gap between PEPs and Obligations.

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
        text client_id "Holds the client_id associated with this trigger."
        timestamp_with_time_zone created_at 
        uuid id PK 
        jsonb metadata 
        uuid obligation_value_id FK,UK 
        timestamp_with_time_zone updated_at 
    }
```

## Key Changes

### 1. **Column Addition**

- Add optional `client_id` to be a part of a trigger.
