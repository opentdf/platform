-- +goose Up
-- +goose StatementBegin

-- JSONB → TEXT (JSON stored as text)
ALTER TABLE resource_mapping_groups ADD COLUMN metadata TEXT;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE resource_mapping_groups DROP COLUMN metadata;

-- +goose StatementEnd
