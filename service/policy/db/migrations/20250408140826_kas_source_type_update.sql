-- +goose Up
-- +goose StatementBegin
ALTER TABLE IF EXISTS key_access_servers
    ALTER COLUMN source_type TYPE INT USING source_type::INTEGER;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE IF EXISTS key_access_servers
    ALTER COLUMN source_type TYPE VARCHAR USING source_type::VARCHAR;
-- +goose StatementEnd
