-- +goose Up
-- +goose StatementBegin

-- Add metadata column to attribute_namespaces
-- JSONB → TEXT (JSON stored as text)
ALTER TABLE attribute_namespaces ADD COLUMN metadata TEXT;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE attribute_namespaces DROP COLUMN metadata;

-- +goose StatementEnd
