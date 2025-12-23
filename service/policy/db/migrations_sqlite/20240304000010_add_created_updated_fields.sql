-- +goose Up
-- +goose StatementBegin

-- Add created_at and updated_at columns to all main tables
-- SQLite uses TEXT for timestamps (ISO8601 format)
-- datetime('now') returns UTC timestamp

ALTER TABLE attribute_namespaces ADD COLUMN created_at TEXT NOT NULL DEFAULT (datetime('now'));
ALTER TABLE attribute_namespaces ADD COLUMN updated_at TEXT NOT NULL DEFAULT (datetime('now'));

ALTER TABLE attribute_definitions ADD COLUMN created_at TEXT NOT NULL DEFAULT (datetime('now'));
ALTER TABLE attribute_definitions ADD COLUMN updated_at TEXT NOT NULL DEFAULT (datetime('now'));

ALTER TABLE attribute_values ADD COLUMN created_at TEXT NOT NULL DEFAULT (datetime('now'));
ALTER TABLE attribute_values ADD COLUMN updated_at TEXT NOT NULL DEFAULT (datetime('now'));

ALTER TABLE key_access_servers ADD COLUMN created_at TEXT NOT NULL DEFAULT (datetime('now'));
ALTER TABLE key_access_servers ADD COLUMN updated_at TEXT NOT NULL DEFAULT (datetime('now'));

ALTER TABLE resource_mappings ADD COLUMN created_at TEXT NOT NULL DEFAULT (datetime('now'));
ALTER TABLE resource_mappings ADD COLUMN updated_at TEXT NOT NULL DEFAULT (datetime('now'));

ALTER TABLE subject_mappings ADD COLUMN created_at TEXT NOT NULL DEFAULT (datetime('now'));
ALTER TABLE subject_mappings ADD COLUMN updated_at TEXT NOT NULL DEFAULT (datetime('now'));

-- +goose StatementEnd

-- SQLite triggers for auto-updating updated_at
-- Note: SQLite AFTER UPDATE triggers use UPDATE...SET syntax

-- +goose StatementBegin
CREATE TRIGGER attribute_namespaces_updated_at
AFTER UPDATE ON attribute_namespaces
FOR EACH ROW
BEGIN
    UPDATE attribute_namespaces SET updated_at = datetime('now') WHERE id = NEW.id;
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER attribute_definitions_updated_at
AFTER UPDATE ON attribute_definitions
FOR EACH ROW
BEGIN
    UPDATE attribute_definitions SET updated_at = datetime('now') WHERE id = NEW.id;
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER attribute_values_updated_at
AFTER UPDATE ON attribute_values
FOR EACH ROW
BEGIN
    UPDATE attribute_values SET updated_at = datetime('now') WHERE id = NEW.id;
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER key_access_servers_updated_at
AFTER UPDATE ON key_access_servers
FOR EACH ROW
BEGIN
    UPDATE key_access_servers SET updated_at = datetime('now') WHERE id = NEW.id;
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER resource_mappings_updated_at
AFTER UPDATE ON resource_mappings
FOR EACH ROW
BEGIN
    UPDATE resource_mappings SET updated_at = datetime('now') WHERE id = NEW.id;
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER subject_mappings_updated_at
AFTER UPDATE ON subject_mappings
FOR EACH ROW
BEGIN
    UPDATE subject_mappings SET updated_at = datetime('now') WHERE id = NEW.id;
END;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TRIGGER IF EXISTS attribute_namespaces_updated_at;
DROP TRIGGER IF EXISTS attribute_definitions_updated_at;
DROP TRIGGER IF EXISTS attribute_values_updated_at;
DROP TRIGGER IF EXISTS key_access_servers_updated_at;
DROP TRIGGER IF EXISTS resource_mappings_updated_at;
DROP TRIGGER IF EXISTS subject_mappings_updated_at;

ALTER TABLE attribute_namespaces DROP COLUMN created_at;
ALTER TABLE attribute_namespaces DROP COLUMN updated_at;

ALTER TABLE attribute_definitions DROP COLUMN created_at;
ALTER TABLE attribute_definitions DROP COLUMN updated_at;

ALTER TABLE attribute_values DROP COLUMN created_at;
ALTER TABLE attribute_values DROP COLUMN updated_at;

ALTER TABLE key_access_servers DROP COLUMN created_at;
ALTER TABLE key_access_servers DROP COLUMN updated_at;

ALTER TABLE resource_mappings DROP COLUMN created_at;
ALTER TABLE resource_mappings DROP COLUMN updated_at;

ALTER TABLE subject_mappings DROP COLUMN created_at;
ALTER TABLE subject_mappings DROP COLUMN updated_at;

-- +goose StatementEnd
