-- +goose Up
-- +goose StatementBegin

ALTER TABLE resource_mapping_groups ADD COLUMN created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE resource_mapping_groups ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP;

-- create trigger to update updated_at when the row is updated
CREATE TRIGGER resource_mapping_groups_updated_at
  BEFORE UPDATE ON resource_mapping_groups
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE resource_mapping_groups DROP COLUMN created_at;
ALTER TABLE resource_mapping_groups DROP COLUMN updated_at;

DROP TRIGGER resource_mapping_groups_updated_at ON resource_mapping_groups;

-- +goose StatementEnd
