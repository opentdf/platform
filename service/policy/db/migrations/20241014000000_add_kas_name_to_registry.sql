-- +goose Up
-- +goose StatementBegin

ALTER TABLE IF EXISTS key_access_servers
  ADD COLUMN IF NOT EXISTS name VARCHAR UNIQUE;

COMMENT ON COLUMN key_access_servers.name IS 'Optional common name of the KAS';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

COMMENT ON COLUMN key_access_servers.name IS NULL;

ALTER TABLE IF EXISTS key_access_servers
  DROP COLUMN IF EXISTS name;

-- +goose StatementEnd
