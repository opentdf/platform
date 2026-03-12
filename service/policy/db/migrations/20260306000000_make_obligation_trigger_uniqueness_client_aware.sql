-- +goose Up
-- +goose StatementBegin
-- Make trigger uniqueness aware of optional client_id scoping.
ALTER TABLE IF EXISTS obligation_triggers
DROP CONSTRAINT IF EXISTS obligation_triggers_obligation_value_id_action_id_attribute_value_id_key;

ALTER TABLE IF EXISTS obligation_triggers
DROP CONSTRAINT IF EXISTS obligation_triggers_obligation_value_id_action_id_attribute_key;

ALTER TABLE IF EXISTS obligation_triggers
DROP CONSTRAINT IF EXISTS obligation_triggers_obligation_value_id_action_id_attribute_val;

CREATE UNIQUE INDEX IF NOT EXISTS obligation_triggers_unscoped_unique_idx
ON obligation_triggers (obligation_value_id, action_id, attribute_value_id)
WHERE client_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS obligation_triggers_scoped_unique_idx
ON obligation_triggers (obligation_value_id, action_id, attribute_value_id, client_id)
WHERE client_id IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS obligation_triggers_scoped_unique_idx;
DROP INDEX IF EXISTS obligation_triggers_unscoped_unique_idx;

ALTER TABLE IF EXISTS obligation_triggers
ADD CONSTRAINT obligation_triggers_obligation_value_id_action_id_attribute_key
UNIQUE (obligation_value_id, action_id, attribute_value_id);
-- +goose StatementEnd
