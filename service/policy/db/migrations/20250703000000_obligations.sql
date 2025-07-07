-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS obligation_definitions
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace_id UUID NOT NULL REFERENCES attribute_namespaces(id),
    -- name is a unique identifier for the obligation definition within the namespace
    name VARCHAR NOT NULL UNIQUE,
    -- implicit index on unique (namespace_id, name) combo
    -- index name: obligation_definitions_namespace_id_name_key
    UNIQUE (namespace_id, name)
    -- metadata JSONB,
    -- created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS obligation_values_standard
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    obligation_definition_id UUID NOT NULL REFERENCES obligation_definitions(id),
    -- value is a unique identifier for the obligation value within the definition
    value VARCHAR NOT NULL UNIQUE,
    -- implicit index on unique (obligation_definition_id, value) combo
    -- index name: obligation_values_standard_obligation_definition_id_value_key
    UNIQUE (obligation_definition_id, value)
    -- metadata JSONB,
    -- created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS obligation_triggers
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attribute_value_id UUID NOT NULL REFERENCES attribute_values(id),
    obligation_value_id UUID NOT NULL REFERENCES obligation_values_standard(id)
    -- metadata JSONB,
    -- created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS obligation_fulfillers
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    obligation_value_id UUID NOT NULL REFERENCES obligation_values_standard(id),
    conditionals JSONB
    -- metadata JSONB,
    -- created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS obligation_action_attribute_values
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    obligation_value_id UUID NOT NULL REFERENCES obligation_values_standard(id),
    action_id UUID NOT NULL REFERENCES actions(id),
    attribute_value_id UUID NOT NULL REFERENCES attribute_values(id),
    -- created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    -- updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(obligation_value_id, action_id, attribute_value_id)
);

-- CREATE TRIGGER obligation_definitions_updated_at
--   BEFORE UPDATE ON obligation_definitions
--   FOR EACH ROW
--   EXECUTE FUNCTION update_updated_at();

-- CREATE TRIGGER obligation_values_standard_updated_at
--   BEFORE UPDATE ON obligation_values_standard
--   FOR EACH ROW
--   EXECUTE FUNCTION update_updated_at();

-- CREATE TRIGGER obligation_triggers_updated_at
--   BEFORE UPDATE ON obligation_triggers
--   FOR EACH ROW
--   EXECUTE FUNCTION update_updated_at();

-- CREATE TRIGGER obligation_fulfillers_updated_at
--   BEFORE UPDATE ON obligation_fulfillers
--   FOR EACH ROW
--   EXECUTE FUNCTION update_updated_at();

-- CREATE TRIGGER obligation_action_attribute_values_updated_at
--   BEFORE UPDATE ON obligation_action_attribute_values
--   FOR EACH ROW
--   EXECUTE FUNCTION update_updated_at();

CREATE OR REPLACE FUNCTION standardize_table(table_name regclass, include_metadata boolean DEFAULT TRUE)
RETURNS void AS $$
-- DECLARE alteration text := 'ALTER TABLE %I ADD COLUMN created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP, ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP';
BEGIN
    -- IF include_metadata THEN
    --     alteration := alteration || ', ADD COLUMN metadata JSONB';
    -- END IF;
    EXECUTE FORMAT('
        ALTER TABLE %I 
        ADD COLUMN metadata JSONB,
        ADD COLUMN created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
        ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
    ', table_name);
    
    -- Create trigger for updating updated_at column
    EXECUTE FORMAT('
        CREATE TRIGGER %I_updated_at
        BEFORE UPDATE ON %I
        FOR EACH ROW
        EXECUTE FUNCTION update_updated_at()
    ', table_name, table_name);    
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION standardize_tables(tables text[])
RETURNS void AS $$
BEGIN 
--     FOREACH table_name IN ARRAY tables
--     LOOP
--         PERFORM standardize_table(table_name::regclass);
--     END LOOP;
END;
$$ LANGUAGE plpgsql;

-- tables text[] := ARRAY['obligation_definitions', 'obligation_values_standard', 'obligation_triggers', 'obligation_fulfillers', 'obligation_action_attribute_values'];
-- PERFORM standardize_tables(tables);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS obligation_definitions;
DROP TABLE IF EXISTS obligation_values_standard;
DROP TABLE IF EXISTS obligation_triggers;
DROP TABLE IF EXISTS obligation_fulfillers;
DROP TABLE IF EXISTS obligation_action_attribute_values;
-- +goose StatementEnd
