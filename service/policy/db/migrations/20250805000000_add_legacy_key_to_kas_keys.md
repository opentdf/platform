
# Migration: Add Legacy Key to KAS Keys

This migration introduces a `legacy` column to the `key_access_server_keys` table.

## Changes

- **`key_access_server_keys` table:**
  - A new boolean column `legacy` is added.
  - This column defaults to `FALSE`.
  - A unique index `key_access_server_keys_legacy_true_idx` is created on `key_access_server_id` where `legacy` is `TRUE`.

## ERD

### Before

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
```

### After

The updated `key_access_server_keys` table is as follows, with the new `legacy` column highlighted:

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
        boolean legacy "New column"
    }
```
