-- +goose Up
-- +goose StatementBegin
-- Add registered_peps column to obligation_triggers table
ALTER TABLE IF EXISTS obligation_triggers
ADD COLUMN IF NOT EXISTS registered_peps JSONB NOT NULL DEFAULT '{}'::jsonb;

COMMENT ON COLUMN obligation_triggers.registered_peps IS 'Holds the RegisteredPEP objects that are associated with this trigger. Map contains client_id -> RegisteredPEP object';
-- +goose StatementEnd


-- +goose Down
-- +goose StatementBegin
-- Drop the registered_peps column
ALTER TABLE IF EXISTS obligation_triggers
DROP COLUMN IF EXISTS registered_peps;

-- +goose StatementEnd
