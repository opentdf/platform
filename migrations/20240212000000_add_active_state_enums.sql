-- +goose Up
-- +goose StatementBegin

CREATE TYPE active_state AS ENUM ('ACTIVE', 'INACTIVE', 'UNSPECIFIED');

ALTER TABLE attribute_namespaces ADD COLUMN IF NOT EXISTS state active_state NOT NULL DEFAULT 'ACTIVE';
ALTER TABLE attribute_definitions ADD COLUMN IF NOT EXISTS state active_state NOT NULL DEFAULT 'ACTIVE';
ALTER TABLE attribute_values ADD COLUMN IF NOT EXISTS state active_state NOT NULL DEFAULT 'ACTIVE';

CREATE INDEX IF NOT EXISTS idx_attribute_namespaces_state ON attribute_namespaces(state);
CREATE INDEX IF NOT EXISTS idx_attribute_definitions_state ON attribute_definitions(state);
CREATE INDEX IF NOT EXISTS idx_attribute_values_state ON attribute_values(state);

--- Triggers deactivation cascade namespaces -> attr definitions -> attr values
--- Expected trigger args cannot be explicitly defined, but are: [tableName text, foreignKeyColumnName text]
CREATE FUNCTION cascade_inactive_state()
RETURNS TRIGGER AS $$
BEGIN
    IF (TG_OP = 'UPDATE' AND NEW.state = 'INACTIVE') THEN
        EXECUTE format('UPDATE %I.%I SET state = $1 WHERE %s = $2', TG_TABLE_SCHEMA, TG_ARGV[0], TG_ARGV[1]) USING NEW.state, OLD.id;
    END IF;
    RETURN NULL;
END
$$ language 'plpgsql';

CREATE TRIGGER namespaces_state_updated
    AFTER
        UPDATE OF state
    ON attribute_namespaces
    FOR EACH ROW
    EXECUTE PROCEDURE cascade_inactive_state('attribute_definitions', 'namespace_id');
    
CREATE TRIGGER attribute_definitions_state_updated
    AFTER
        UPDATE OF state
    ON attribute_definitions
    FOR EACH ROW
    EXECUTE PROCEDURE cascade_inactive_state('attribute_values', 'attribute_definition_id');

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- If rolling back, all soft deletes should become hard deletes.
DELETE FROM attribute_namespaces WHERE state = 'INACTIVE';
DELETE FROM attribute_definitions WHERE state = 'INACTIVE';
DELETE FROM attribute_values WHERE state = 'INACTIVE';

-- There should be no UNSPECIFIED states, but only preserve active rows just in case.
DELETE FROM attribute_namespaces WHERE state = 'UNSPECIFIED';
DELETE FROM attribute_definitions WHERE state = 'UNSPECIFIED';
DELETE FROM attribute_values WHERE state = 'UNSPECIFIED';

DROP TRIGGER IF EXISTS namespaces_state_updated ON attribute_namespaces;
DROP TRIGGER IF EXISTS attribute_definitions_state_updated ON attribute_definitions;
DROP FUNCTION cascade_inactive_state;

DROP INDEX IF EXISTS idx_attribute_namespaces_state;
DROP INDEX IF EXISTS idx_attribute_definitions_state;
DROP INDEX IF EXISTS idx_attribute_values_state;

ALTER TABLE attribute_namespaces DROP COLUMN state;
ALTER TABLE attribute_definitions DROP COLUMN state;
ALTER TABLE attribute_values DROP COLUMN state;

DROP TYPE active_state;

-- +goose StatementEnd