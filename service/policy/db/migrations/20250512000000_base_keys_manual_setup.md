# Manual Base Key Configuration

## Overview

The base key is the default Key Access Server (KAS) key used by the OpenTDF platform when no specific key mappings (grants) exist for attributes in a TDF encryption operation. This document explains how to manually configure a base key in your platform deployment.

For background on the base key concept and design decisions, see [ADR: Base Platform KAS Key](../../../adr/decisions/2025-04-28-default-kas-keys.md).

## Prerequisites

1. A running OpenTDF platform instance with database access
2. At least one active KAS key registered in the `key_access_server_keys` table
3. Database connection credentials

## Understanding Base Keys

The `base_keys` table has the following structure:

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID | Primary key for the base key entry |
| `key_access_server_key_id` | UUID | Foreign key reference to `key_access_server_keys.id` |

**Important constraints:**
- Only ONE base key can exist in the system at a time (enforced by trigger)
- The referenced KAS key must be in `ACTIVE` status
- The base key will be exposed via the `/wellknown/configuration` endpoint

## Manual Setup Steps

### Step 1: Identify Available KAS Keys

First, query your existing KAS keys to find an appropriate key to set as the base key:

```sql
SELECT 
    kask.id,
    kask.key_id,
    kask.key_algorithm,
    kask.key_status,
    kas.uri as kas_url,
    kas.name as kas_name
FROM opentdf_policy.key_access_server_keys kask
JOIN opentdf_policy.key_access_servers kas ON kask.key_access_server_id = kas.id
WHERE kask.key_status = 1  -- 1 = ACTIVE status
ORDER BY kask.created_at DESC;
```

Choose a key that:
- Has `key_status = 1` (ACTIVE)
- Belongs to a KAS instance that will serve as your default
- Is appropriate for your security requirements (RSA-2048, RSA-4096, EC-P256, etc.)

### Step 2: Insert the Base Key

Insert a base key entry referencing your chosen KAS key ID:

```sql
INSERT INTO opentdf_policy.base_keys (id, key_access_server_key_id)
VALUES (
    gen_random_uuid(),
    '<your-chosen-kas-key-id>'
);
```

**Example with a real UUID:**
```sql
INSERT INTO opentdf_policy.base_keys (id, key_access_server_key_id)
VALUES (
    gen_random_uuid(),
    '7b9c4f44-ee74-418c-b05c-8320e01953be'  -- Replace with your actual key ID
);
```

### Step 3: Verify the Base Key

Confirm the base key was inserted correctly:

```sql
SELECT 
    bk.id as base_key_id,
    kask.key_id,
    kask.key_algorithm,
    kask.key_status,
    kas.uri as kas_url,
    kas.name as kas_name
FROM opentdf_policy.base_keys bk
JOIN opentdf_policy.key_access_server_keys kask ON bk.key_access_server_key_id = kask.id
JOIN opentdf_policy.key_access_servers kas ON kask.key_access_server_id = kas.id;
```

### Step 4: Test via Well-Known Endpoint

The base key should now be available through the well-known configuration endpoint:

```bash
curl http://localhost:8080/wellknown/configuration | jq '.configuration.base_key'
```

You should see output similar to:

```json
{
  "kas_url": "https://your-kas.example.com/kas",
  "public_key": {
    "algorithm": "rsa:2048",
    "kid": "your-key-id",
    "pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
  }
}
```

## Changing the Base Key

To change which key is designated as the base key, use the platform's `SetBaseKey` API:

```bash
curl -X POST http://localhost:8080/policy/kasregistry/v1/set-base-key \
  -H "Content-Type: application/json" \
  -d '{
    "id": "<new-kas-key-id>"
  }'
```

Or update directly in the database:

```sql
UPDATE opentdf_policy.base_keys
SET key_access_server_key_id = '<new-kas-key-id>'
WHERE id = (SELECT id FROM opentdf_policy.base_keys LIMIT 1);
```

**Note:** The `base_keys` table has a trigger that ensures only one row exists. When you insert a new base key, it will automatically update the existing one rather than creating a duplicate.

## Troubleshooting

### Error: No base key found

If SDKs report errors about missing base keys:

1. Verify a base key exists: `SELECT * FROM opentdf_policy.base_keys;`
2. Verify the referenced KAS key is active: Check the `key_status` column in `key_access_server_keys`
3. Restart the platform service to ensure configuration is reloaded

### Error: Foreign key constraint violation

This means the KAS key ID you're trying to reference doesn't exist:

1. Verify the key exists: `SELECT id FROM opentdf_policy.key_access_server_keys WHERE id = '<your-key-id>';`
2. Use Step 1 to find valid key IDs

### Multiple base keys exist

The trigger should prevent this, but if you somehow have multiple:

```sql
DELETE FROM opentdf_policy.base_keys
WHERE id NOT IN (
    SELECT id FROM opentdf_policy.base_keys ORDER BY created_at DESC LIMIT 1
);
```

## Using Fixtures (Development/Testing)

For local development, you can use the fixtures provisioning system:

1. Edit `service/internal/fixtures/policy_fixtures.yaml`
2. Add or update the `base_keys` section:

```yaml
base_keys:
  metadata:
    table_name: base_keys
    columns:
      - id
      - key_access_server_key_id
  data:
    base_key:
      id: 1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d
      key_access_server_key_id: 7b9c4f44-ee74-418c-b05c-8320e01953be  # Reference to an existing KAS key
```

3. Run: `GOWORK=off go run -C test/integration ./cmd/provision-fixtures`

## See Also

- [ADR: Base Platform KAS Key](../../../adr/decisions/2025-04-28-default-kas-keys.md) - Design rationale
- [Base Keys Migration](./20250512000000_base_keys_table.sql) - Database schema
- [KAS Registry API Documentation](../../../../docs/openapi/policy/kasregistry/) - API reference for key management
