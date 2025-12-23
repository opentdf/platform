-- +goose Up
-- +goose StatementBegin

-- SQLite does not support ALTER CONSTRAINT for foreign keys.
-- To add ON DELETE CASCADE, we must recreate the tables.
-- This migration recreates affected tables with CASCADE constraints.

-- Disable foreign keys temporarily for the migration
PRAGMA foreign_keys=OFF;

-- 1. Recreate attribute_definitions with CASCADE
CREATE TABLE attribute_definitions_new (
    id TEXT PRIMARY KEY,
    namespace_id TEXT NOT NULL REFERENCES attribute_namespaces(id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK(length(name) <= 253),
    rule TEXT NOT NULL CHECK(rule IN ('UNSPECIFIED', 'ALL_OF', 'ANY_OF', 'HIERARCHY')),
    metadata TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    values_order TEXT DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (namespace_id, name)
);

INSERT INTO attribute_definitions_new
SELECT id, namespace_id, name, rule, metadata, active, values_order, created_at, updated_at
FROM attribute_definitions;

DROP TABLE attribute_definitions;
ALTER TABLE attribute_definitions_new RENAME TO attribute_definitions;

-- Recreate trigger for updated_at
CREATE TRIGGER attribute_definitions_updated_at
AFTER UPDATE ON attribute_definitions
FOR EACH ROW
BEGIN
    UPDATE attribute_definitions SET updated_at = datetime('now') WHERE id = NEW.id;
END;

-- 2. Recreate attribute_values with CASCADE
CREATE TABLE attribute_values_new (
    id TEXT PRIMARY KEY,
    attribute_definition_id TEXT NOT NULL REFERENCES attribute_definitions(id) ON DELETE CASCADE,
    value TEXT NOT NULL CHECK(length(value) <= 253),
    metadata TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (attribute_definition_id, value)
);

INSERT INTO attribute_values_new
SELECT id, attribute_definition_id, value, metadata, active, created_at, updated_at
FROM attribute_values;

DROP TABLE attribute_values;
ALTER TABLE attribute_values_new RENAME TO attribute_values;

CREATE TRIGGER attribute_values_updated_at
AFTER UPDATE ON attribute_values
FOR EACH ROW
BEGIN
    UPDATE attribute_values SET updated_at = datetime('now') WHERE id = NEW.id;
END;

-- 3. Recreate resource_mappings with CASCADE
CREATE TABLE resource_mappings_new (
    id TEXT PRIMARY KEY,
    attribute_value_id TEXT NOT NULL REFERENCES attribute_values(id) ON DELETE CASCADE,
    terms TEXT NOT NULL,
    metadata TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO resource_mappings_new
SELECT id, attribute_value_id, terms, metadata, created_at, updated_at
FROM resource_mappings;

DROP TABLE resource_mappings;
ALTER TABLE resource_mappings_new RENAME TO resource_mappings;

CREATE TRIGGER resource_mappings_updated_at
AFTER UPDATE ON resource_mappings
FOR EACH ROW
BEGIN
    UPDATE resource_mappings SET updated_at = datetime('now') WHERE id = NEW.id;
END;

-- 4. Recreate subject_mappings with CASCADE
CREATE TABLE subject_mappings_new (
    id TEXT PRIMARY KEY,
    attribute_value_id TEXT NOT NULL REFERENCES attribute_values(id) ON DELETE CASCADE,
    subject_condition_set_id TEXT REFERENCES subject_condition_set(id) ON DELETE CASCADE,
    actions TEXT,
    metadata TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO subject_mappings_new
SELECT id, attribute_value_id, subject_condition_set_id, actions, metadata, created_at, updated_at
FROM subject_mappings;

DROP TABLE subject_mappings;
ALTER TABLE subject_mappings_new RENAME TO subject_mappings;

CREATE TRIGGER subject_mappings_updated_at
AFTER UPDATE ON subject_mappings
FOR EACH ROW
BEGIN
    UPDATE subject_mappings SET updated_at = datetime('now') WHERE id = NEW.id;
END;

-- 5. Recreate attribute_fqns with CASCADE
CREATE TABLE attribute_fqns_new (
    id TEXT PRIMARY KEY,
    fqn TEXT NOT NULL UNIQUE,
    namespace_id TEXT NOT NULL REFERENCES attribute_namespaces(id) ON DELETE CASCADE,
    attribute_id TEXT REFERENCES attribute_definitions(id) ON DELETE CASCADE,
    value_id TEXT REFERENCES attribute_values(id) ON DELETE CASCADE
);

INSERT INTO attribute_fqns_new
SELECT id, fqn, namespace_id, attribute_id, value_id
FROM attribute_fqns;

DROP TABLE attribute_fqns;
ALTER TABLE attribute_fqns_new RENAME TO attribute_fqns;

-- Recreate partial indexes for attribute_fqns (NULLS NOT DISTINCT emulation)
CREATE UNIQUE INDEX idx_attr_fqns_ns_only ON attribute_fqns(namespace_id) WHERE attribute_id IS NULL AND value_id IS NULL;
CREATE UNIQUE INDEX idx_attr_fqns_ns_attr ON attribute_fqns(namespace_id, attribute_id) WHERE attribute_id IS NOT NULL AND value_id IS NULL;
CREATE UNIQUE INDEX idx_attr_fqns_ns_attr_val ON attribute_fqns(namespace_id, attribute_id, value_id) WHERE attribute_id IS NOT NULL AND value_id IS NOT NULL;

-- 6. Recreate attribute_definition_key_access_grants with CASCADE
CREATE TABLE attribute_definition_key_access_grants_new (
    attribute_definition_id TEXT NOT NULL REFERENCES attribute_definitions(id) ON DELETE CASCADE,
    key_access_server_id TEXT NOT NULL REFERENCES key_access_servers(id) ON DELETE CASCADE,
    PRIMARY KEY (attribute_definition_id, key_access_server_id)
);

INSERT INTO attribute_definition_key_access_grants_new
SELECT attribute_definition_id, key_access_server_id
FROM attribute_definition_key_access_grants;

DROP TABLE attribute_definition_key_access_grants;
ALTER TABLE attribute_definition_key_access_grants_new RENAME TO attribute_definition_key_access_grants;

-- 7. Recreate attribute_value_key_access_grants with CASCADE
CREATE TABLE attribute_value_key_access_grants_new (
    attribute_value_id TEXT NOT NULL REFERENCES attribute_values(id) ON DELETE CASCADE,
    key_access_server_id TEXT NOT NULL REFERENCES key_access_servers(id) ON DELETE CASCADE,
    PRIMARY KEY (attribute_value_id, key_access_server_id)
);

INSERT INTO attribute_value_key_access_grants_new
SELECT attribute_value_id, key_access_server_id
FROM attribute_value_key_access_grants;

DROP TABLE attribute_value_key_access_grants;
ALTER TABLE attribute_value_key_access_grants_new RENAME TO attribute_value_key_access_grants;

-- 8. Recreate attribute_value_members with CASCADE
CREATE TABLE attribute_value_members_new (
    id TEXT PRIMARY KEY,
    value_id TEXT NOT NULL REFERENCES attribute_values(id) ON DELETE CASCADE,
    member_id TEXT NOT NULL REFERENCES attribute_values(id) ON DELETE CASCADE,
    UNIQUE (value_id, member_id)
);

INSERT INTO attribute_value_members_new
SELECT id, value_id, member_id
FROM attribute_value_members;

DROP TABLE attribute_value_members;
ALTER TABLE attribute_value_members_new RENAME TO attribute_value_members;

-- Re-enable foreign keys
PRAGMA foreign_keys=ON;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Reverse: Remove ON DELETE CASCADE by recreating tables without it
-- Note: This is a destructive migration if there are orphaned records

PRAGMA foreign_keys=OFF;

-- 1. Recreate attribute_definitions without CASCADE
CREATE TABLE attribute_definitions_new (
    id TEXT PRIMARY KEY,
    namespace_id TEXT NOT NULL REFERENCES attribute_namespaces(id),
    name TEXT NOT NULL CHECK(length(name) <= 253),
    rule TEXT NOT NULL CHECK(rule IN ('UNSPECIFIED', 'ALL_OF', 'ANY_OF', 'HIERARCHY')),
    metadata TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    values_order TEXT DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (namespace_id, name)
);

INSERT INTO attribute_definitions_new
SELECT id, namespace_id, name, rule, metadata, active, values_order, created_at, updated_at
FROM attribute_definitions;

DROP TABLE attribute_definitions;
ALTER TABLE attribute_definitions_new RENAME TO attribute_definitions;

CREATE TRIGGER attribute_definitions_updated_at
AFTER UPDATE ON attribute_definitions
FOR EACH ROW
BEGIN
    UPDATE attribute_definitions SET updated_at = datetime('now') WHERE id = NEW.id;
END;

-- 2. Recreate attribute_values without CASCADE
CREATE TABLE attribute_values_new (
    id TEXT PRIMARY KEY,
    attribute_definition_id TEXT NOT NULL REFERENCES attribute_definitions(id),
    value TEXT NOT NULL CHECK(length(value) <= 253),
    metadata TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (attribute_definition_id, value)
);

INSERT INTO attribute_values_new
SELECT id, attribute_definition_id, value, metadata, active, created_at, updated_at
FROM attribute_values;

DROP TABLE attribute_values;
ALTER TABLE attribute_values_new RENAME TO attribute_values;

CREATE TRIGGER attribute_values_updated_at
AFTER UPDATE ON attribute_values
FOR EACH ROW
BEGIN
    UPDATE attribute_values SET updated_at = datetime('now') WHERE id = NEW.id;
END;

-- 3. Recreate resource_mappings without CASCADE
CREATE TABLE resource_mappings_new (
    id TEXT PRIMARY KEY,
    attribute_value_id TEXT NOT NULL REFERENCES attribute_values(id),
    terms TEXT NOT NULL,
    metadata TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO resource_mappings_new
SELECT id, attribute_value_id, terms, metadata, created_at, updated_at
FROM resource_mappings;

DROP TABLE resource_mappings;
ALTER TABLE resource_mappings_new RENAME TO resource_mappings;

CREATE TRIGGER resource_mappings_updated_at
AFTER UPDATE ON resource_mappings
FOR EACH ROW
BEGIN
    UPDATE resource_mappings SET updated_at = datetime('now') WHERE id = NEW.id;
END;

-- 4. Recreate subject_mappings without CASCADE
CREATE TABLE subject_mappings_new (
    id TEXT PRIMARY KEY,
    attribute_value_id TEXT NOT NULL REFERENCES attribute_values(id),
    subject_condition_set_id TEXT REFERENCES subject_condition_set(id),
    actions TEXT,
    metadata TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO subject_mappings_new
SELECT id, attribute_value_id, subject_condition_set_id, actions, metadata, created_at, updated_at
FROM subject_mappings;

DROP TABLE subject_mappings;
ALTER TABLE subject_mappings_new RENAME TO subject_mappings;

CREATE TRIGGER subject_mappings_updated_at
AFTER UPDATE ON subject_mappings
FOR EACH ROW
BEGIN
    UPDATE subject_mappings SET updated_at = datetime('now') WHERE id = NEW.id;
END;

-- 5. Recreate attribute_fqns without CASCADE
CREATE TABLE attribute_fqns_new (
    id TEXT PRIMARY KEY,
    fqn TEXT NOT NULL UNIQUE,
    namespace_id TEXT NOT NULL REFERENCES attribute_namespaces(id),
    attribute_id TEXT REFERENCES attribute_definitions(id),
    value_id TEXT REFERENCES attribute_values(id)
);

INSERT INTO attribute_fqns_new
SELECT id, fqn, namespace_id, attribute_id, value_id
FROM attribute_fqns;

DROP TABLE attribute_fqns;
ALTER TABLE attribute_fqns_new RENAME TO attribute_fqns;

CREATE UNIQUE INDEX idx_attr_fqns_ns_only ON attribute_fqns(namespace_id) WHERE attribute_id IS NULL AND value_id IS NULL;
CREATE UNIQUE INDEX idx_attr_fqns_ns_attr ON attribute_fqns(namespace_id, attribute_id) WHERE attribute_id IS NOT NULL AND value_id IS NULL;
CREATE UNIQUE INDEX idx_attr_fqns_ns_attr_val ON attribute_fqns(namespace_id, attribute_id, value_id) WHERE attribute_id IS NOT NULL AND value_id IS NOT NULL;

-- 6. Recreate attribute_definition_key_access_grants without CASCADE
CREATE TABLE attribute_definition_key_access_grants_new (
    attribute_definition_id TEXT NOT NULL REFERENCES attribute_definitions(id),
    key_access_server_id TEXT NOT NULL REFERENCES key_access_servers(id),
    PRIMARY KEY (attribute_definition_id, key_access_server_id)
);

INSERT INTO attribute_definition_key_access_grants_new
SELECT attribute_definition_id, key_access_server_id
FROM attribute_definition_key_access_grants;

DROP TABLE attribute_definition_key_access_grants;
ALTER TABLE attribute_definition_key_access_grants_new RENAME TO attribute_definition_key_access_grants;

-- 7. Recreate attribute_value_key_access_grants without CASCADE
CREATE TABLE attribute_value_key_access_grants_new (
    attribute_value_id TEXT NOT NULL REFERENCES attribute_values(id),
    key_access_server_id TEXT NOT NULL REFERENCES key_access_servers(id),
    PRIMARY KEY (attribute_value_id, key_access_server_id)
);

INSERT INTO attribute_value_key_access_grants_new
SELECT attribute_value_id, key_access_server_id
FROM attribute_value_key_access_grants;

DROP TABLE attribute_value_key_access_grants;
ALTER TABLE attribute_value_key_access_grants_new RENAME TO attribute_value_key_access_grants;

-- 8. Recreate attribute_value_members without CASCADE
CREATE TABLE attribute_value_members_new (
    id TEXT PRIMARY KEY,
    value_id TEXT NOT NULL REFERENCES attribute_values(id),
    member_id TEXT NOT NULL REFERENCES attribute_values(id),
    UNIQUE (value_id, member_id)
);

INSERT INTO attribute_value_members_new
SELECT id, value_id, member_id
FROM attribute_value_members;

DROP TABLE attribute_value_members;
ALTER TABLE attribute_value_members_new RENAME TO attribute_value_members;

PRAGMA foreign_keys=ON;

-- +goose StatementEnd
