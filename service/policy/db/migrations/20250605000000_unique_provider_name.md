```mermaid
erDiagram
    provider_config {
        jsonb config "Configuration details for the key provider"
        timestamp_with_time_zone created_at "Timestamp when the provider configuration was created"
        uuid id PK "Unique identifier for the provider configuration"
        jsonb metadata "Additional metadata for the provider configuration"
        character_varying provider_name UK "Unique name for the key provider."
        timestamp_with_time_zone updated_at "Timestamp when the provider configuration was last updated"
    }
```
<style>div.mermaid{overflow-x:scroll;}div.mermaid>svg{width:250rem;}</style>
