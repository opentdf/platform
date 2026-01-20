-- +goose Up
-- +goose StatementBegin
ALTER TABLE attribute_definitions
    ADD COLUMN IF NOT EXISTS allow_traversal BOOLEAN NOT NULL DEFAULT FALSE;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE attribute_definitions
    DROP COLUMN IF EXISTS allow_traversal;
-- +goose StatementEnd
