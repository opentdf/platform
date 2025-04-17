-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS registered_resources (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR NOT NULL UNIQUE,
  metadata JSONB,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE registered_resources IS 'Table to store registered resources';
COMMENT ON COLUMN registered_resources.id IS 'Primary key for the table';
COMMENT ON COLUMN registered_resources.name IS 'Name for the registered resource';
COMMENT ON COLUMN registered_resources.metadata IS 'Metadata for the registered resource (see protos for structure)';
COMMENT ON COLUMN registered_resources.created_at IS 'Timestamp when the record was created';
COMMENT ON COLUMN registered_resources.updated_at IS 'Timestamp when the record was last updated';

CREATE TABLE IF NOT EXISTS registered_resource_values (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  registered_resource_id UUID NOT NULL REFERENCES registered_resources(id) ON DELETE CASCADE,
  value VARCHAR NOT NULL,
  metadata JSONB,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(registered_resource_id, value)
);
COMMENT ON TABLE registered_resource_values IS 'Table to store registered resource values';
COMMENT ON COLUMN registered_resource_values.id IS 'Primary key for the table';
COMMENT ON COLUMN registered_resource_values.registered_resource_id IS 'Foreign key to the registered_resources table';
COMMENT ON COLUMN registered_resource_values.value IS 'Value for the registered resource value';
COMMENT ON COLUMN registered_resource_values.metadata IS 'Metadata for the registered resource value (see protos for structure)';
COMMENT ON COLUMN registered_resource_values.created_at IS 'Timestamp when the record was created';
COMMENT ON COLUMN registered_resource_values.updated_at IS 'Timestamp when the record was last updated';

CREATE TRIGGER registered_resources_updated_at
  BEFORE UPDATE ON registered_resources
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER registered_resource_values_updated_at
  BEFORE UPDATE ON registered_resource_values
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TRIGGER IF EXISTS registered_resource_values_updated_at ON registered_resource_values;
DROP TRIGGER IF EXISTS registered_resources_updated_at ON registered_resources;

DROP TABLE IF EXISTS registered_resource_values;
DROP TABLE IF EXISTS registered_resources;

-- +goose StatementEnd
