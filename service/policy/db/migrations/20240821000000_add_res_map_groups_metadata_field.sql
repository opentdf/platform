-- +goose Up
-- +goose StatementBegin

ALTER TABLE IF EXISTS resource_mapping_groups
  ADD COLUMN IF NOT EXISTS metadata JSONB;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE IF EXISTS resource_mapping_groups
  DROP COLUMN IF EXISTS metadata;

-- +goose StatementEnd
