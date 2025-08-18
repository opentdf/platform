-- +goose Up
-- +goose StatementBegin
ALTER TABLE provider_config ADD CONSTRAINT provider_config_provider_name_key UNIQUE (provider_name);

COMMENT ON COLUMN provider_config.provider_name IS 'Unique name for the key provider.';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE provider_config DROP CONSTRAINT IF EXISTS provider_config_provider_name_key;
-- +goose StatementEnd