-- +goose Up
-- +goose StatementBegin

ALTER TABLE resource_mapping_groups ADD COLUMN metadata JSONB;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE resource_mapping_groups DROP COLUMN metadata;

-- +goose StatementEnd
