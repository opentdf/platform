-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS obligation_definitions
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace_id UUID NOT NULL REFERENCES attribute_namespaces(id) ON DELETE CASCADE,
    -- name is a unique identifier for the obligation definition within the namespace
    name VARCHAR NOT NULL,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- implicit index on unique (namespace_id, name) combo
    -- index name: obligation_definitions_namespace_id_name_key
    UNIQUE (namespace_id, name)
);

CREATE TABLE IF NOT EXISTS obligation_values_standard
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    obligation_definition_id UUID NOT NULL REFERENCES obligation_definitions(id) ON DELETE CASCADE,
    -- value is a unique identifier for the obligation value within the definition
    value VARCHAR NOT NULL,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- implicit index on unique (obligation_definition_id, value) combo
    -- index name: obligation_values_standard_obligation_definition_id_value_key
    UNIQUE (obligation_definition_id, value)
);

CREATE TABLE IF NOT EXISTS obligation_triggers
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    obligation_value_id UUID NOT NULL REFERENCES obligation_values_standard(id) ON DELETE CASCADE,
    action_id UUID NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    attribute_value_id UUID NOT NULL REFERENCES attribute_values(id) ON DELETE CASCADE,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(obligation_value_id, action_id, attribute_value_id)
);

CREATE TABLE IF NOT EXISTS obligation_fulfillers
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    obligation_value_id UUID NOT NULL REFERENCES obligation_values_standard(id) ON DELETE CASCADE,
    conditionals JSONB,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER obligation_definitions_updated_at
    BEFORE UPDATE ON obligation_definitions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER obligation_values_standard_updated_at
    BEFORE UPDATE ON obligation_values_standard
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER obligation_triggers_updated_at
    BEFORE UPDATE ON obligation_triggers
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER obligation_fulfillers_updated_at
    BEFORE UPDATE ON obligation_fulfillers
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS obligation_fulfillers;
DROP TABLE IF EXISTS obligation_triggers;
DROP TABLE IF EXISTS obligation_values_standard;
DROP TABLE IF EXISTS obligation_definitions;

-- +goose StatementEnd
