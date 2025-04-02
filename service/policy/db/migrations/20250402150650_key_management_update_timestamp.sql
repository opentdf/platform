-- +goose Up
-- +goose StatementBegin
ALTER TABLE provider_config
    ALTER COLUMN created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ALTER COLUMN updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP;

-- create trigger to update updated_at when the row is updated
CREATE TRIGGER provider_config_updated_at
  BEFORE UPDATE ON provider_config
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE provider_config DROP COLUMN created_at;
ALTER TABLE provider_config DROP COLUMN updated_at;

DROP TRIGGER provider_config_updated_at ON provider_config;
-- +goose StatementEnd
