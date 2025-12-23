-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS registered_resources (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  metadata TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- SQLite: Comments documented here instead of COMMENT ON
-- Table: Store registered resources
-- id: Primary key for the table
-- name: Name for the registered resource
-- metadata: Metadata for the registered resource (see protos for structure)
-- created_at: Timestamp when the record was created
-- updated_at: Timestamp when the record was last updated

CREATE TABLE IF NOT EXISTS registered_resource_values (
  id TEXT PRIMARY KEY,
  registered_resource_id TEXT NOT NULL REFERENCES registered_resources(id) ON DELETE CASCADE,
  value TEXT NOT NULL,
  metadata TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(registered_resource_id, value)
);

-- SQLite: Comments documented here instead of COMMENT ON
-- Table: Store registered resource values
-- id: Primary key for the table
-- registered_resource_id: Foreign key to the registered_resources table
-- value: Value for the registered resource value
-- metadata: Metadata for the registered resource value (see protos for structure)

-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER registered_resources_updated_at
AFTER UPDATE ON registered_resources
FOR EACH ROW
BEGIN
    UPDATE registered_resources SET updated_at = datetime('now') WHERE id = NEW.id;
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER registered_resource_values_updated_at
AFTER UPDATE ON registered_resource_values
FOR EACH ROW
BEGIN
    UPDATE registered_resource_values SET updated_at = datetime('now') WHERE id = NEW.id;
END;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TRIGGER IF EXISTS registered_resource_values_updated_at;
DROP TRIGGER IF EXISTS registered_resources_updated_at;

DROP TABLE IF EXISTS registered_resource_values;
DROP TABLE IF EXISTS registered_resources;

-- +goose StatementEnd
