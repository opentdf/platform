-- +goose Up
-- +goose StatementBegin

-- Note: This table depends on the 'actions' table created by 20250411000000_add_actions_table.sql
CREATE TABLE IF NOT EXISTS registered_resource_action_attribute_values (
  id TEXT PRIMARY KEY,
  registered_resource_value_id TEXT NOT NULL REFERENCES registered_resource_values(id) ON DELETE CASCADE,
  action_id TEXT NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
  attribute_value_id TEXT NOT NULL REFERENCES attribute_values(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(registered_resource_value_id, action_id, attribute_value_id)
);

-- SQLite: Comments documented here instead of COMMENT ON
-- Table: Store linkage of registered resource values to actions and attribute values
-- id: Primary key for the table
-- registered_resource_value_id: Foreign key to the registered_resource_values table
-- action_id: Foreign key to the actions table
-- attribute_value_id: Foreign key to the attribute_values table

-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER registered_resource_action_attribute_values_updated_at
AFTER UPDATE ON registered_resource_action_attribute_values
FOR EACH ROW
BEGIN
    UPDATE registered_resource_action_attribute_values SET updated_at = datetime('now') WHERE id = NEW.id;
END;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TRIGGER IF EXISTS registered_resource_action_attribute_values_updated_at;

DROP TABLE IF EXISTS registered_resource_action_attribute_values;

-- +goose StatementEnd
