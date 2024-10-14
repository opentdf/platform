-- +goose Up
-- +goose StatementBegin

ALTER TABLE IF EXISTS key_access_servers
  ADD COLUMN IF NOT EXISTS name VARCHAR UNIQUE;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE IF EXISTS key_access_servers
  DROP COLUMN IF EXISTS name;

-- +goose StatementEnd
