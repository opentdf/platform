-- +goose Up
-- +goose StatementBegin

-- NOTE: pre-1.0 not crucial to migrate existing timestamps stored in the metadata JSONB column into the new columns.

-- Create update function
CREATE OR REPLACE FUNCTION update_updated_at() RETURNS TRIGGER 
LANGUAGE plpgsql
AS
$$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;

-- Add new columns for created and updated fields for tables:
-- 1. attribute_namespaces
-- 2. attribute_definitions
-- 3. attribute_values
-- 4. key_access_servers
-- 5. resource_mappings
-- 6. subject_mappings

ALTER TABLE attribute_namespaces ADD COLUMN created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE attribute_namespaces ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP;

ALTER TABLE attribute_definitions ADD COLUMN created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE attribute_definitions ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP;

ALTER TABLE attribute_values ADD COLUMN created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE attribute_values ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP;

ALTER TABLE key_access_servers ADD COLUMN created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE key_access_servers ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP;

ALTER TABLE resource_mappings ADD COLUMN created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE resource_mappings ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP;

ALTER TABLE subject_mappings ADD COLUMN created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE subject_mappings ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP;

-- create triggers to update updated_at when the row is updated
CREATE TRIGGER attribute_namespaces_updated_at
  BEFORE UPDATE ON attribute_namespaces
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER attribute_definitions_updated_at
  BEFORE UPDATE ON attribute_definitions
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER attribute_values_updated_at
  BEFORE UPDATE ON attribute_values
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER key_access_servers_updated_at
  BEFORE UPDATE ON key_access_servers
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();
  
CREATE TRIGGER resource_mappings_updated_at
  BEFORE UPDATE ON resource_mappings
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER subject_mappings_updated_at
  BEFORE UPDATE ON subject_mappings
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

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

DROP TRIGGER attribute_namespaces_updated_at ON attribute_namespaces;
DROP TRIGGER attribute_definitions_updated_at ON attribute_definitions;
DROP TRIGGER attribute_values_updated_at ON attribute_values;
DROP TRIGGER key_access_servers_updated_at ON key_access_servers;
DROP TRIGGER resource_mappings_updated_at ON resource_mappings;
DROP TRIGGER subject_mappings_updated_at ON subject_mappings;

DROP FUNCTION update_updated_at();

-- +goose StatementEnd
