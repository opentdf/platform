-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS registered_resource_action_attribute_values (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  registered_resource_value_id UUID NOT NULL REFERENCES registered_resource_values(id) ON DELETE CASCADE,
  action_id UUID NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
  attribute_value_id UUID NOT NULL REFERENCES attribute_values(id) ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  UNIQUE(registered_resource_value_id, action_id, attribute_value_id)
);
COMMENT ON TABLE registered_resource_action_attribute_values IS 'Table to store the linkage of registered resource values to actions and attribute values';
COMMENT ON COLUMN registered_resource_action_attribute_values.id IS 'Primary key for the table';
COMMENT ON COLUMN registered_resource_action_attribute_values.registered_resource_value_id IS 'Foreign key to the registered_resource_values table';
COMMENT ON COLUMN registered_resource_action_attribute_values.action_id IS 'Foreign key to the actions table';
COMMENT ON COLUMN registered_resource_action_attribute_values.attribute_value_id IS 'Foreign key to the attribute_values table';
COMMENT ON COLUMN registered_resource_action_attribute_values.created_at IS 'Timestamp when the record was created';
COMMENT ON COLUMN registered_resource_action_attribute_values.updated_at IS 'Timestamp when the record was last updated';

CREATE TRIGGER registered_resource_action_attribute_values_updated_at
  BEFORE UPDATE ON registered_resource_action_attribute_values
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TRIGGER IF EXISTS registered_resource_action_attribute_values_updated_at ON registered_resource_action_attribute_values;

DROP TABLE IF EXISTS registered_resource_action_attribute_values;

-- +goose StatementEnd
