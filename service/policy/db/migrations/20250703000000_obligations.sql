-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS obligation_definitions
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace_id UUID NOT NULL REFERENCES attribute_namespaces(id) ON DELETE CASCADE,
    -- name is a unique identifier for the obligation definition within the namespace
    name VARCHAR NOT NULL,
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
    UNIQUE(obligation_value_id, action_id, attribute_value_id)
);

CREATE TABLE IF NOT EXISTS obligation_fulfillers
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    obligation_value_id UUID NOT NULL REFERENCES obligation_values_standard(id) ON DELETE CASCADE,
    conditionals JSONB
);

CREATE OR REPLACE FUNCTION get_obligation_tables()
RETURNS text[] AS $$
BEGIN
    RETURN ARRAY['obligation_definitions', 'obligation_values_standard', 
                 'obligation_triggers', 'obligation_fulfillers'];
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION standardize_table(table_name regclass)
RETURNS void AS $$
BEGIN
    -- Add standard columns to the table
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
DECLARE table_name text;
BEGIN 
    FOREACH table_name IN ARRAY tables
    LOOP
        PERFORM standardize_table(table_name::regclass);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

SELECT standardize_tables(get_obligation_tables());

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

CREATE OR REPLACE FUNCTION drop_tables(tables text[])
RETURNS void AS $$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY tables
    LOOP
        EXECUTE FORMAT('DROP TABLE IF EXISTS %I', table_name);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

SELECT drop_tables(get_obligation_tables());
DROP FUNCTION IF EXISTS get_obligation_tables;
DROP FUNCTION IF EXISTS drop_tables;
DROP FUNCTION IF EXISTS standardize_table;
DROP FUNCTION IF EXISTS standardize_tables;

-- +goose StatementEnd
