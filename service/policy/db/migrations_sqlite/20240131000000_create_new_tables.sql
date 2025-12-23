-- +goose Up
-- +goose StatementBegin

-- SQLite equivalent of PostgreSQL schema
-- Key conversions:
--   UUID → TEXT (UUIDs generated in application layer)
--   gen_random_uuid() → (application generates UUID before INSERT)
--   ENUM → TEXT with CHECK constraint
--   VARCHAR[] → TEXT (JSON array, e.g., '["val1","val2"]')
--   JSONB → TEXT (JSON stored as text)

-- Note: SQLite does not support CREATE TYPE, so we use CHECK constraints instead

CREATE TABLE IF NOT EXISTS attribute_namespaces
(
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS attribute_definitions
(
    id TEXT PRIMARY KEY,
    namespace_id TEXT NOT NULL REFERENCES attribute_namespaces(id),
    name TEXT NOT NULL,
    -- ENUM replacement: CHECK constraint for allowed values
    rule TEXT NOT NULL CHECK(rule IN ('UNSPECIFIED', 'ALL_OF', 'ANY_OF', 'HIERARCHY')),
    metadata TEXT,
    UNIQUE (namespace_id, name)
);

CREATE TABLE IF NOT EXISTS attribute_values
(
    id TEXT PRIMARY KEY,
    attribute_definition_id TEXT NOT NULL REFERENCES attribute_definitions(id),
    value TEXT NOT NULL,
    -- UUID[] → TEXT (JSON array of UUIDs)
    members TEXT,
    metadata TEXT,
    UNIQUE (attribute_definition_id, value)
);

CREATE TABLE IF NOT EXISTS key_access_servers
(
    id TEXT PRIMARY KEY,
    uri TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    metadata TEXT
);

CREATE TABLE IF NOT EXISTS attribute_definition_key_access_grants
(
    attribute_definition_id TEXT NOT NULL REFERENCES attribute_definitions(id),
    key_access_server_id TEXT NOT NULL REFERENCES key_access_servers(id),
    PRIMARY KEY (attribute_definition_id, key_access_server_id)
);

CREATE TABLE IF NOT EXISTS attribute_value_key_access_grants
(
    attribute_value_id TEXT NOT NULL REFERENCES attribute_values(id),
    key_access_server_id TEXT NOT NULL REFERENCES key_access_servers(id),
    PRIMARY KEY (attribute_value_id, key_access_server_id)
);

CREATE TABLE IF NOT EXISTS resource_mappings
(
    id TEXT PRIMARY KEY,
    attribute_value_id TEXT NOT NULL REFERENCES attribute_values(id),
    -- VARCHAR[] → TEXT (JSON array)
    terms TEXT,
    metadata TEXT
);

CREATE TABLE IF NOT EXISTS subject_mappings
(
    id TEXT PRIMARY KEY,
    attribute_value_id TEXT NOT NULL REFERENCES attribute_values(id),
    -- ENUM replacement: CHECK constraint
    operator TEXT NOT NULL CHECK(operator IN ('UNSPECIFIED', 'IN', 'NOT_IN')),
    subject_attribute TEXT NOT NULL,
    -- VARCHAR[] → TEXT (JSON array)
    subject_attribute_values TEXT,
    metadata TEXT
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS subject_mappings;
DROP TABLE IF EXISTS resource_mappings;
DROP TABLE IF EXISTS attribute_value_key_access_grants;
DROP TABLE IF EXISTS attribute_definition_key_access_grants;
DROP TABLE IF EXISTS key_access_servers;
DROP TABLE IF EXISTS attribute_values;
DROP TABLE IF EXISTS attribute_definitions;
DROP TABLE IF EXISTS attribute_namespaces;
-- +goose StatementEnd
