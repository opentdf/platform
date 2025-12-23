-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS base_keys (
    id TEXT PRIMARY KEY,
    key_access_server_key_id TEXT REFERENCES key_access_server_keys(id) ON DELETE RESTRICT
);

-- Note: PostgreSQL upsert trigger is handled in application layer for SQLite
-- The PolicyDBClient manages the single-row constraint for base_keys

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS base_keys;

-- +goose StatementEnd
