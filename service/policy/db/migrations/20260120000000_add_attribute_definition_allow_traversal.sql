-- +goose Up
-- +goose StatementBegin
ALTER TABLE attribute_definitions
    ADD COLUMN IF NOT EXISTS allow_traversal BOOLEAN NOT NULL DEFAULT FALSE;
COMMENT ON COLUMN attribute_definitions.allow_traversal IS 'Whether or not to allow platform to return the definition key when encrypting, if the value specified is missing.';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE attribute_definitions
    DROP COLUMN IF EXISTS allow_traversal;
-- +goose StatementEnd
