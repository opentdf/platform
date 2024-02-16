-- +goose Up
-- +goose StatementBegin

ALTER TABLE attribute_namespaces ADD COLUMN IF NOT EXISTS active bool NOT NULL DEFAULT true;
ALTER TABLE attribute_definitions ADD COLUMN IF NOT EXISTS active bool NOT NULL DEFAULT true;
ALTER TABLE attribute_values ADD COLUMN IF NOT EXISTS active bool NOT NULL DEFAULT true;

--- Triggers deactivation cascade namespaces -> attr definitions -> attr values
--- Expected trigger args cannot be explicitly defined, but are: [tableName text, foreignKeyColumnName text]
CREATE FUNCTION cascade_deactivation()
RETURNS TRIGGER AS $$
BEGIN
    IF (TG_OP = 'UPDATE' AND NEW.active = false) THEN
        EXECUTE format('UPDATE %I.%I SET active = $1 WHERE %s = $2', TG_TABLE_SCHEMA, TG_ARGV[0], TG_ARGV[1]) USING NEW.active, OLD.id;
    END IF;
    RETURN NULL;
END
$$ language 'plpgsql';

CREATE TRIGGER namespaces_active_updated
    AFTER
        UPDATE OF active
    ON attribute_namespaces
    FOR EACH ROW
    EXECUTE PROCEDURE cascade_deactivation('attribute_definitions', 'namespace_id');
    
CREATE TRIGGER attribute_definitions_active_updated
    AFTER
        UPDATE OF active
    ON attribute_definitions
    FOR EACH ROW
    EXECUTE PROCEDURE cascade_deactivation('attribute_values', 'attribute_definition_id');

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- If rolling back, all deactivations should be hard deletes.
DELETE FROM attribute_namespaces WHERE active = false;
DELETE FROM attribute_definitions WHERE active = false;
DELETE FROM attribute_values WHERE active = false;

DROP TRIGGER IF EXISTS namespaces_active_updated ON attribute_namespaces;
DROP TRIGGER IF EXISTS attribute_definitions_active_updated ON attribute_definitions;
DROP FUNCTION cascade_deactivation;

ALTER TABLE attribute_namespaces DROP COLUMN active;
ALTER TABLE attribute_definitions DROP COLUMN active;
ALTER TABLE attribute_values DROP COLUMN active;

-- +goose StatementEnd