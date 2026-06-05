-- +goose Up
-- +goose StatementBegin

-- Definition Value Entitlement Mappings raise entitlement authority from a concrete
-- attribute value to the attribute definition. A single mapping resolves entitlement for
-- dynamically-requested values under the definition by comparing the requested resource
-- value segment against the entity representation (the value_resolver), optionally gated
-- by a static SubjectConditionSet.
CREATE TABLE IF NOT EXISTS definition_value_entitlement_mappings (
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

COMMENT ON TABLE definition_value_entitlement_mappings IS 'Definition-scoped dynamic value entitlement mappings (DSPX-2754)';
COMMENT ON COLUMN definition_value_entitlement_mappings.subject_external_selector_value IS 'Selector resolved against the entity representation, compared to the requested resource value segment';
COMMENT ON COLUMN definition_value_entitlement_mappings.operator IS 'policy.DynamicValueOperatorEnum value';

CREATE TRIGGER definition_value_entitlement_mappings_updated_at
  BEFORE UPDATE ON definition_value_entitlement_mappings
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();

CREATE TABLE IF NOT EXISTS definition_value_entitlement_mapping_actions (
    definition_value_entitlement_mapping_id UUID NOT NULL REFERENCES definition_value_entitlement_mappings(id) ON DELETE CASCADE,
    action_id UUID NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    PRIMARY KEY (definition_value_entitlement_mapping_id, action_id)
);

CREATE INDEX idx_definition_value_entitlement_mappings_definition_id
  ON definition_value_entitlement_mappings(attribute_definition_id);
CREATE INDEX idx_definition_value_entitlement_mappings_scs_id
  ON definition_value_entitlement_mappings(subject_condition_set_id);
CREATE INDEX idx_definition_value_entitlement_mappings_namespace_id
  ON definition_value_entitlement_mappings(namespace_id);
-- No separate index on definition_value_entitlement_mapping_actions: its composite
-- PRIMARY KEY (definition_value_entitlement_mapping_id, action_id) already covers lookups.

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_definition_value_entitlement_mappings_namespace_id;
DROP INDEX IF EXISTS idx_definition_value_entitlement_mappings_scs_id;
DROP INDEX IF EXISTS idx_definition_value_entitlement_mappings_definition_id;

DROP TABLE IF EXISTS definition_value_entitlement_mapping_actions;

DROP TRIGGER IF EXISTS definition_value_entitlement_mappings_updated_at ON definition_value_entitlement_mappings;
DROP TABLE IF EXISTS definition_value_entitlement_mappings;

-- +goose StatementEnd
