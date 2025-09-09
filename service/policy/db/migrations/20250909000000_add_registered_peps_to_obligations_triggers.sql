-- +goose Up
-- +goose StatementBegin
-- Add client_id column to obligation_triggers table
ALTER TABLE IF EXISTS obligation_triggers
ADD COLUMN IF NOT EXISTS client_id TEXT DEFAULT NULL;

COMMENT ON COLUMN obligation_triggers.client_id IS 'Holds the client_id associated with this trigger.';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Drop the client_id column
ALTER TABLE IF EXISTS obligation_triggers
DROP COLUMN IF EXISTS client_id;

-- +goose StatementEnd
