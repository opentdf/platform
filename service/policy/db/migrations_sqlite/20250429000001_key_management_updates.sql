-- +goose Up
-- +goose StatementBegin

-- Add source_type column to key_access_servers
ALTER TABLE key_access_servers ADD COLUMN source_type TEXT;

-- Provider config table
CREATE TABLE IF NOT EXISTS provider_config (
    id TEXT PRIMARY KEY,
    provider_name TEXT NOT NULL,
    manager TEXT NOT NULL DEFAULT 'opentdf.io/unspecified',
    config TEXT NOT NULL,
    metadata TEXT,
    created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE (provider_name, manager)
);

CREATE TRIGGER IF NOT EXISTS provider_config_updated_at
AFTER UPDATE ON provider_config
BEGIN
    UPDATE provider_config SET updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
    WHERE id = NEW.id;
END;

-- Key access server keys table (flattened from PostgreSQL INHERITS pattern)
-- Combines asym_key columns directly into key_access_server_keys
CREATE TABLE IF NOT EXISTS key_access_server_keys (
    id TEXT PRIMARY KEY,
    key_access_server_id TEXT NOT NULL REFERENCES key_access_servers(id) ON DELETE CASCADE,
    key_id TEXT NOT NULL,
    key_algorithm INTEGER NOT NULL,
    key_status INTEGER NOT NULL,
    key_mode INTEGER NOT NULL,
    public_key_ctx TEXT,
    private_key_ctx TEXT,
    expiration TEXT,
    provider_config_id TEXT REFERENCES provider_config(id),
    metadata TEXT,
    created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    legacy INTEGER NOT NULL DEFAULT 0,
    UNIQUE (key_access_server_id, key_id)
);

CREATE TRIGGER IF NOT EXISTS key_access_server_keys_updated_at
AFTER UPDATE ON key_access_server_keys
BEGIN
    UPDATE key_access_server_keys SET updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
    WHERE id = NEW.id;
END;

-- Create partial index for legacy key uniqueness
CREATE UNIQUE INDEX IF NOT EXISTS key_access_server_keys_legacy_true_idx
ON key_access_server_keys(key_access_server_id) WHERE legacy = 1;

-- Namespace to key mapping table
CREATE TABLE IF NOT EXISTS attribute_namespace_public_key_map (
    namespace_id TEXT NOT NULL REFERENCES attribute_namespaces(id) ON DELETE CASCADE,
    key_access_server_key_id TEXT NOT NULL REFERENCES key_access_server_keys(id) ON DELETE CASCADE,
    PRIMARY KEY (namespace_id, key_access_server_key_id)
);

-- Definition to key mapping table
CREATE TABLE IF NOT EXISTS attribute_definition_public_key_map (
    definition_id TEXT NOT NULL REFERENCES attribute_definitions(id) ON DELETE CASCADE,
    key_access_server_key_id TEXT NOT NULL REFERENCES key_access_server_keys(id) ON DELETE CASCADE,
    PRIMARY KEY (definition_id, key_access_server_key_id)
);

-- Value to key mapping table
CREATE TABLE IF NOT EXISTS attribute_value_public_key_map (
    value_id TEXT NOT NULL REFERENCES attribute_values(id) ON DELETE CASCADE,
    key_access_server_key_id TEXT NOT NULL REFERENCES key_access_server_keys(id) ON DELETE CASCADE,
    PRIMARY KEY (value_id, key_access_server_key_id)
);

-- Note: Views from PostgreSQL are not created for SQLite
-- The query layer handles JSON aggregation directly

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS attribute_value_public_key_map;
DROP TABLE IF EXISTS attribute_definition_public_key_map;
DROP TABLE IF EXISTS attribute_namespace_public_key_map;
DROP TABLE IF EXISTS key_access_server_keys;
DROP TABLE IF EXISTS provider_config;

-- Note: Cannot easily remove source_type column in SQLite
-- Would require table recreation

-- +goose StatementEnd
