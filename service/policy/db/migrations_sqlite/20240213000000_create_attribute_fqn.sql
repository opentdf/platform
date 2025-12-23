-- +goose Up
-- +goose StatementBegin

-- SQLite equivalent of attribute_fqns table
-- The PostgreSQL version uses UNIQUE NULLS NOT DISTINCT which treats NULLs as equal.
-- SQLite treats NULLs as distinct in UNIQUE constraints, so we use partial indexes.

CREATE TABLE IF NOT EXISTS attribute_fqns (
    id TEXT PRIMARY KEY,
    namespace_id TEXT REFERENCES attribute_namespaces(id) ON DELETE CASCADE,
    attribute_id TEXT REFERENCES attribute_definitions(id) ON DELETE CASCADE,
    value_id TEXT REFERENCES attribute_values(id) ON DELETE CASCADE,
    fqn TEXT NOT NULL UNIQUE
);

-- Partial indexes to emulate UNIQUE NULLS NOT DISTINCT (namespace_id, attribute_id, value_id)
-- This ensures only one row exists for each combination of (namespace_id, attribute_id, value_id)
-- including when some values are NULL.

-- Case 1: All three are non-null
CREATE UNIQUE INDEX idx_fqns_all_non_null
ON attribute_fqns(namespace_id, attribute_id, value_id)
WHERE namespace_id IS NOT NULL AND attribute_id IS NOT NULL AND value_id IS NOT NULL;

-- Case 2: Only namespace_id is set (attribute_id and value_id are null)
CREATE UNIQUE INDEX idx_fqns_ns_only
ON attribute_fqns(namespace_id)
WHERE namespace_id IS NOT NULL AND attribute_id IS NULL AND value_id IS NULL;

-- Case 3: namespace_id and attribute_id are set (value_id is null)
CREATE UNIQUE INDEX idx_fqns_ns_attr
ON attribute_fqns(namespace_id, attribute_id)
WHERE namespace_id IS NOT NULL AND attribute_id IS NOT NULL AND value_id IS NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_fqns_ns_attr;
DROP INDEX IF EXISTS idx_fqns_ns_only;
DROP INDEX IF EXISTS idx_fqns_all_non_null;
DROP TABLE IF EXISTS attribute_fqns;

-- +goose StatementEnd
