-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS obligation_definitions
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace_id UUID NOT NULL REFERENCES attribute_namespaces(id),
    -- name is a unique identifier for the obligation definition within the namespace
    name VARCHAR NOT NULL,
    -- implicit index on unique (namespace_id, name) combo
    -- index name: obligation_definitions_namespace_id_name_key
    UNIQUE (namespace_id, name),
    metadata JSONB
);

CREATE TABLE IF NOT EXISTS obligation_values_standard
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    obligation_definition_id UUID NOT NULL REFERENCES obligation_definitions(id),
    -- value is a unique identifier for the obligation value within the definition
    value VARCHAR NOT NULL,
    -- implicit index on unique (obligation_definition_id, value) combo
    -- index name: obligation_values_standard_obligation_definition_id_value_key
    UNIQUE (obligation_definition_id, value),
    metadata JSONB
);

CREATE TABLE IF NOT EXISTS obligation_triggers
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attribute_value_id UUID NOT NULL REFERENCES attribute_values(id),
    obligation_value_id UUID NOT NULL REFERENCES obligation_values_standard(id),
    metadata JSONB
);

CREATE TABLE IF NOT EXISTS obligation_fulfillers
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    obligation_value_id UUID NOT NULL REFERENCES obligation_values_standard(id),
    conditionals JSONB,
    metadata JSONB
);

CREATE TABLE IF NOT EXISTS obligation_action_attribute_values
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    obligation_value_id UUID NOT NULL REFERENCES obligation_values_standard(id),
    action_id UUID NOT NULL REFERENCES actions(id),
    attribute_value_id UUID NOT NULL REFERENCES attribute_values(id),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(obligation_value_id, action_id, attribute_value_id)
);

CREATE TRIGGER obligation_action_attribute_values_updated_at
  BEFORE UPDATE ON obligation_action_attribute_values
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS obligation_definitions;
DROP TABLE IF EXISTS obligation_values_standard;
DROP TABLE IF EXISTS obligation_triggers;
DROP TABLE IF EXISTS obligation_fulfillers;
DROP TRIGGER IF EXISTS obligation_action_attribute_values_updated_at ON obligation_action_attribute_values;
DROP TABLE IF EXISTS obligation_action_attribute_values;
-- +goose StatementEnd
