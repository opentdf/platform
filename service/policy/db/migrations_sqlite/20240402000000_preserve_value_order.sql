-- +goose Up
-- +goose StatementBegin

-- Add values_order column to track the order of attribute values
-- PostgreSQL uses uuid[] array; SQLite uses TEXT storing JSON array
-- e.g., '["uuid1","uuid2","uuid3"]'
ALTER TABLE attribute_definitions ADD COLUMN values_order TEXT DEFAULT '[]';

-- Note: The PostgreSQL version uses PL/pgSQL triggers with dynamic SQL
-- (EXECUTE format(...)) to automatically maintain the values_order array.
-- SQLite cannot execute dynamic SQL in triggers, so this logic is
-- implemented in the application layer (PolicyDBClient) instead.
--
-- When inserting a new attribute_value, the application should:
--   1. Read current values_order from attribute_definitions
--   2. Append the new value ID to the JSON array
--   3. Update attribute_definitions with the new values_order
--
-- When deleting an attribute_value, the application should:
--   1. Read current values_order from attribute_definitions
--   2. Remove the deleted value ID from the JSON array
--   3. Update attribute_definitions with the new values_order

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE attribute_definitions DROP COLUMN values_order;

-- +goose StatementEnd
