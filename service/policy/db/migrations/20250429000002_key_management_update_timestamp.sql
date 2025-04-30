-- +goose Up
-- +goose StatementBegin
ALTER TABLE IF EXISTS provider_config
    ALTER COLUMN created_at TYPE TIMESTAMP WITH TIME ZONE,
    ALTER COLUMN updated_at TYPE TIMESTAMP WITH TIME ZONE;

ALTER TABLE IF EXISTS asym_key
    ALTER COLUMN created_at TYPE TIMESTAMP WITH TIME ZONE,
    ALTER COLUMN updated_at TYPE TIMESTAMP WITH TIME ZONE,
    ALTER COLUMN created_at SET DEFAULT NOW(),
    ALTER COLUMN updated_at SET DEFAULT NOW(),
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

CREATE TRIGGER key_access_server_keys_updated_at
  BEFORE UPDATE ON key_access_server_keys
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS key_access_server_keys_updated_at ON key_access_server_keys;
DROP TRIGGER IF EXISTS provider_config_updated_at ON provider_config;


ALTER TABLE IF EXISTS sym_key
    ALTER COLUMN created_at TYPE TIMESTAMP WITHOUT TIME ZONE,
    ALTER COLUMN updated_at TYPE TIMESTAMP WITHOUT TIME ZONE,
    DROP COLUMN IF EXISTS expiration;

ALTER TABLE IF EXISTS asym_key
    ALTER COLUMN created_at TYPE TIMESTAMP WITHOUT TIME ZONE,
    ALTER COLUMN updated_at TYPE TIMESTAMP WITHOUT TIME ZONE,
    ALTER COLUMN created_at DROP DEFAULT,
    ALTER COLUMN updated_at DROP DEFAULT, 
    ALTER COLUMN expiration TYPE TIMESTAMP WITHOUT TIME ZONE;

ALTER TABLE IF EXISTS provider_config
    ALTER COLUMN created_at TYPE TIMESTAMP WITHOUT TIME ZONE,
    ALTER COLUMN updated_at TYPE TIMESTAMP WITHOUT TIME ZONE;
-- +goose StatementEnd
