-- +goose Up
-- +goose StatementBegin

CREATE INDEX IF NOT EXISTS idx_resource_mappings_attribute_value_id
  ON resource_mappings(attribute_value_id);

CREATE INDEX IF NOT EXISTS idx_obligation_triggers_attribute_value_id
  ON obligation_triggers(attribute_value_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_obligation_triggers_attribute_value_id;
DROP INDEX IF EXISTS idx_resource_mappings_attribute_value_id;

-- +goose StatementEnd
