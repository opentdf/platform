-- +goose Up
-- +goose StatementBegin

ALTER TABLE attribute_namespaces ADD COLUMN metadata JSONB;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE attribute_namespaces DROP COLUMN metadata;

-- +goose StatementEnd
