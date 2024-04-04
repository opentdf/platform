-- +goose Up
-- +goose StatementBegin

ALTER TABLE attribute_definitions ADD COLUMN values_order uuid[] DEFAULT '{}';

-- Append the new value row id to the values_order array when a new attribute value is created
CREATE OR REPLACE FUNCTION update_definition_add_values_order()
RETURNS TRIGGER AS $$
BEGIN
    EXECUTE format('UPDATE %I.%I SET values_order = array_append(values_order, $1) WHERE id = $2;', TG_TABLE_SCHEMA, 'attribute_definitions', TG_ARGV[0], TG_ARGV[1]) USING NEW.id, NEW.attribute_definition_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_definition_add_values_order
AFTER INSERT ON attribute_values
FOR EACH ROW
EXECUTE FUNCTION update_definition_add_values_order();

-- Remove the deleted value row id from the values_order array when a value is unsafely deleted
CREATE OR REPLACE FUNCTION update_definition_delete_values_order()
RETURNS TRIGGER AS $$
BEGIN
    EXECUTE format('UPDATE %I.%I SET values_order = array_remove(values_order, $1) WHERE id = $2;', TG_TABLE_SCHEMA, 'attribute_definitions', TG_ARGV[0], TG_ARGV[1]) USING OLD.id, OLD.attribute_definition_id;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_definition_delete_values_order
AFTER DELETE ON attribute_values
FOR EACH ROW
EXECUTE FUNCTION update_definition_delete_values_order();

-- +goose StatementEnd

-- +goose Down

-- +goose StatementBegin

DROP FUNCTION update_definition_add_values_order;
DROP TRIGGER trigger_update_definition_add_values_order;

DROP FUNCTION update_definition_delete_values_order;
DROP TRIGGER trigger_update_definition_delete_values_order;

ALTER TABLE attribute_definitions DROP COLUMN values_order;

-- +goose StatementEnd
