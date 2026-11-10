```mermaid
erDiagram
    key_access_server_keys {
            timestamp_with_time_zone created_at 
            timestamp_with_time_zone expiration 
            uuid id PK 
            uuid key_access_server_id FK,UK 
            integer key_algorithm 
            character_varying key_id UK 
            integer key_mode 
            integer key_status 
            jsonb metadata 
            jsonb private_key_ctx 
            uuid provider_config_id FK 
            jsonb public_key_ctx 
            timestamp_with_time_zone updated_at 
    }

    key_access_server_keys }o--|| provider_config : "provider_config_id"
```
