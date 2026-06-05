-- +goose Up
-- +goose StatementBegin

-- Dynamic Value Mappings raise entitlement authority from a concrete
-- attribute value to the attribute definition. A single mapping resolves entitlement for
-- dynamically-requested values under the definition by comparing the requested resource
-- value segment against the entity representation (the value_resolver), optionally gated
-- by a static SubjectConditionSet.
CREATE TABLE IF NOT EXISTS dynamic_value_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attribute_definition_id UUID NOT NULL REFERENCES attribute_definitions(id) ON DELETE CASCADE,
    -- value_resolver: selector against the flattened entity representation + dynamic operator
    subject_external_selector_value TEXT NOT NULL,
    operator SMALLINT NOT NULL,
    -- optional static pre-gate, evaluated with normal SubjectConditionSet semantics
    subject_condition_set_id UUID REFERENCES subject_condition_set(id) ON DELETE CASCADE,
    namespace_id UUID REFERENCES attribute_namespaces(id) ON DELETE CASCADE,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE dynamic_value_mappings IS 'Definition-scoped dynamic value entitlement mappings (DSPX-2754)';
COMMENT ON COLUMN dynamic_value_mappings.subject_external_selector_value IS 'Selector resolved against the entity representation, compared to the requested resource value segment';
COMMENT ON COLUMN dynamic_value_mappings.operator IS 'policy.DynamicValueOperatorEnum value';

CREATE TRIGGER dynamic_value_mappings_updated_at
  BEFORE UPDATE ON dynamic_value_mappings
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();

CREATE TABLE IF NOT EXISTS dynamic_value_mapping_actions (
    dynamic_value_mapping_id UUID NOT NULL REFERENCES dynamic_value_mappings(id) ON DELETE CASCADE,
    action_id UUID NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    PRIMARY KEY (dynamic_value_mapping_id, action_id)
);

CREATE INDEX idx_dynamic_value_mappings_definition_id
  ON dynamic_value_mappings(attribute_definition_id);
CREATE INDEX idx_dynamic_value_mappings_scs_id
  ON dynamic_value_mappings(subject_condition_set_id);
CREATE INDEX idx_dynamic_value_mappings_namespace_id
  ON dynamic_value_mappings(namespace_id);
-- No separate index on dynamic_value_mapping_actions: its composite
-- PRIMARY KEY (dynamic_value_mapping_id, action_id) already covers lookups.

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_dynamic_value_mappings_namespace_id;
DROP INDEX IF EXISTS idx_dynamic_value_mappings_scs_id;
DROP INDEX IF EXISTS idx_dynamic_value_mappings_definition_id;

DROP TABLE IF EXISTS dynamic_value_mapping_actions;

DROP TRIGGER IF EXISTS dynamic_value_mappings_updated_at ON dynamic_value_mappings;
DROP TABLE IF EXISTS dynamic_value_mappings;

-- +goose StatementEnd
