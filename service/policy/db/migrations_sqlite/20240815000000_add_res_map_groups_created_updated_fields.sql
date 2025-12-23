-- +goose Up
-- +goose StatementBegin

ALTER TABLE resource_mapping_groups ADD COLUMN created_at TEXT NOT NULL DEFAULT (datetime('now'));
ALTER TABLE resource_mapping_groups ADD COLUMN updated_at TEXT NOT NULL DEFAULT (datetime('now'));

-- +goose StatementEnd

-- +goose StatementBegin

-- SQLite trigger to update updated_at when the row is updated
CREATE TRIGGER resource_mapping_groups_updated_at
AFTER UPDATE ON resource_mapping_groups
FOR EACH ROW
BEGIN
    UPDATE resource_mapping_groups SET updated_at = datetime('now') WHERE id = NEW.id;
END;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TRIGGER IF EXISTS resource_mapping_groups_updated_at;

ALTER TABLE resource_mapping_groups DROP COLUMN created_at;
ALTER TABLE resource_mapping_groups DROP COLUMN updated_at;

-- +goose StatementEnd
