-- +goose Up
-- +goose StatementBegin
ALTER TABLE IF EXISTS provider_config
    ALTER COLUMN created_at TYPE TIMESTAMP WITH TIME ZONE,
    ALTER COLUMN updated_at TYPE TIMESTAMP WITH TIME ZONE;

ALTER TABLE IF EXISTS asym_key
    ALTER COLUMN created_at TYPE TIMESTAMP WITH TIME ZONE,
    ALTER COLUMN updated_at TYPE TIMESTAMP WITH TIME ZONE,
    ALTER COLUMN expiration TYPE TIMESTAMP WITH TIME ZONE;

ALTER TABLE IF EXISTS sym_key
    ALTER COLUMN created_at TYPE TIMESTAMP WITH TIME ZONE,
    ALTER COLUMN updated_at TYPE TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS expiration TIMESTAMP WITH TIME ZONE;

-- create trigger to update updated_at when the row is updated
CREATE TRIGGER provider_config_updated_at
  BEFORE UPDATE ON provider_config
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER asym_key_updated_at
  BEFORE UPDATE ON asym_key
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER sym_key_updated_at
  BEFORE UPDATE ON sym_key
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS sym_key_updated_at ON sym_key;
DROP TRIGGER IF EXISTS asym_key_updated_at ON asym_key;
DROP TRIGGER IF EXISTS provider_config_updated_at ON provider_config;

ALTER TABLE IF EXISTS sym_key
    ALTER COLUMN created_at TYPE TIMESTAMP WITHOUT TIME ZONE,
    ALTER COLUMN updated_at TYPE TIMESTAMP WITHOUT TIME ZONE,
    DROP COLUMN IF EXISTS expiration;

ALTER TABLE IF EXISTS asym_key
    ALTER COLUMN created_at TYPE TIMESTAMP WITHOUT TIME ZONE,
    ALTER COLUMN updated_at TYPE TIMESTAMP WITHOUT TIME ZONE,
    ALTER COLUMN expiration TYPE TIMESTAMP WITHOUT TIME ZONE;

ALTER TABLE IF EXISTS provider_config
    ALTER COLUMN created_at TYPE TIMESTAMP WITHOUT TIME ZONE,
    ALTER COLUMN updated_at TYPE TIMESTAMP WITHOUT TIME ZONE;
-- +goose StatementEnd
