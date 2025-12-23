-- +goose Up
-- +goose StatementBegin

-- Create subject_condition_set table
CREATE TABLE IF NOT EXISTS subject_condition_set (
    id TEXT PRIMARY KEY,
    condition TEXT NOT NULL,
    metadata TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER subject_condition_set_updated_at
AFTER UPDATE ON subject_condition_set
FOR EACH ROW
BEGIN
    UPDATE subject_condition_set SET updated_at = datetime('now') WHERE id = NEW.id;
END;
-- +goose StatementEnd

-- +goose StatementBegin

-- Add new columns to subject_mappings
ALTER TABLE subject_mappings ADD COLUMN subject_condition_set_id TEXT REFERENCES subject_condition_set(id) ON DELETE CASCADE;
ALTER TABLE subject_mappings ADD COLUMN actions TEXT;

-- Note: The PostgreSQL migration includes complex data migration using JSONB functions.
-- For SQLite fresh installations, we skip the data migration as there's no existing data.
-- If migrating from PostgreSQL to SQLite with existing data, a separate data export/import
-- process would be needed.

-- Drop the old columns (SQLite 3.35.0+)
-- For older SQLite versions, table recreation would be needed
ALTER TABLE subject_mappings DROP COLUMN operator;
ALTER TABLE subject_mappings DROP COLUMN subject_attribute;
ALTER TABLE subject_mappings DROP COLUMN subject_attribute_values;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Restore old columns
ALTER TABLE subject_mappings ADD COLUMN operator TEXT CHECK(operator IN ('UNSPECIFIED', 'IN', 'NOT_IN'));
ALTER TABLE subject_mappings ADD COLUMN subject_attribute TEXT;
ALTER TABLE subject_mappings ADD COLUMN subject_attribute_values TEXT;

-- Drop new columns
ALTER TABLE subject_mappings DROP COLUMN subject_condition_set_id;
ALTER TABLE subject_mappings DROP COLUMN actions;

DROP TRIGGER IF EXISTS subject_condition_set_updated_at;
DROP TABLE IF EXISTS subject_condition_set;

-- +goose StatementEnd
