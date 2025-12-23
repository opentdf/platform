-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS resource_mapping_groups (
    id TEXT PRIMARY KEY,
    namespace_id TEXT NOT NULL REFERENCES attribute_namespaces(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    UNIQUE(namespace_id, name)
);

-- SQLite: Comments documented here instead of COMMENT ON
-- Table: Store groups of resource mappings by unique namespace and group name combinations
-- id: Primary key for the table
-- namespace_id: Foreign key to the namespace of the attribute
-- name: Name for the group of resource mappings

ALTER TABLE resource_mappings ADD COLUMN group_id TEXT REFERENCES resource_mapping_groups(id) ON DELETE SET NULL;

-- group_id: Foreign key to the parent group of the resource mapping (optional)

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- SQLite doesn't support DROP COLUMN in older versions, but 3.35.0+ does
ALTER TABLE resource_mappings DROP COLUMN group_id;

DROP TABLE IF EXISTS resource_mapping_groups;

-- +goose StatementEnd
