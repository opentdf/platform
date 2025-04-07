-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS non_data_resource_groups (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR NOT NULL UNIQUE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE non_data_resource_groups IS 'Table to store non-data resources';
COMMENT ON COLUMN non_data_resource_groups.id IS 'Primary key for the table';
COMMENT ON COLUMN non_data_resource_groups.name IS 'Name for the non-data resource group';
COMMENT ON COLUMN non_data_resource_groups.created_at IS 'Timestamp when the record was created';
COMMENT ON COLUMN non_data_resource_groups.updated_at IS 'Timestamp when the record was last updated';

CREATE TABLE IF NOT EXISTS non_data_resource_values (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  non_data_resource_group_id UUID NOT NULL REFERENCES non_data_resource_groups(id),
  value VARCHAR NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE non_data_resource_values IS 'Table to store non-data resource values';
COMMENT ON COLUMN non_data_resource_values.id IS 'Primary key for the table';
COMMENT ON COLUMN non_data_resource_values.non_data_resource_group_id IS 'Foreign key to the non-data resource group';
COMMENT ON COLUMN non_data_resource_values.value IS 'Value for the non-data resource';
COMMENT ON COLUMN non_data_resource_values.created_at IS 'Timestamp when the record was created';
COMMENT ON COLUMN non_data_resource_values.updated_at IS 'Timestamp when the record was last updated';

CREATE TRIGGER IF NOT EXISTS non_data_resource_groups_updated_at
  BEFORE UPDATE ON non_data_resource_groups
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER IF NOT EXISTS non_data_resource_values_updated_at
  BEFORE UPDATE ON non_data_resource_values
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TRIGGER IF EXISTS non_data_resource_values_updated_at ON non_data_resource_values;
DROP TRIGGER IF EXISTS non_data_resource_groups_updated_at ON non_data_resource_groups;

DROP TABLE IF EXISTS non_data_resource_values;
DROP TABLE IF EXISTS non_data_resource_groups;

-- +goose StatementEnd
