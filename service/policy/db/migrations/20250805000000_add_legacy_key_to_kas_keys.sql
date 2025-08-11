-- +goose Up
-- +goose StatementBegin
ALTER TABLE key_access_server_keys ADD COLUMN legacy BOOLEAN NOT NULL DEFAULT FALSE;
CREATE UNIQUE INDEX key_access_server_keys_legacy_true_idx ON key_access_server_keys (key_access_server_id) WHERE legacy = TRUE;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX key_access_server_keys_legacy_true_idx;
ALTER TABLE key_access_server_keys DROP COLUMN legacy;
-- +goose StatementEnd
