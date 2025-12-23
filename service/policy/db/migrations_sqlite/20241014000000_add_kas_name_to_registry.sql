-- +goose Up
-- +goose StatementBegin

ALTER TABLE key_access_servers ADD COLUMN name TEXT UNIQUE;

-- SQLite: Comments documented here instead of COMMENT ON
-- name: Optional common name of the KAS

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE key_access_servers DROP COLUMN name;

-- +goose StatementEnd
