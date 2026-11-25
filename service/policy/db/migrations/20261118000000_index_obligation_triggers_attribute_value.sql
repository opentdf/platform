-- +goose Up
-- +goose StatementBegin

-- ListObligationTriggers filtered by attribute value FQNs, used by decisioning
-- to load only the triggers for the attribute values being decided.
CREATE INDEX IF NOT EXISTS idx_obligation_triggers_attribute_value_id ON obligation_triggers(attribute_value_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_obligation_triggers_attribute_value_id;

-- +goose StatementEnd
