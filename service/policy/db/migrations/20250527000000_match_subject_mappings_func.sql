-- +goose Up
-- +goose StatementBegin

CREATE OR REPLACE FUNCTION check_subject_selectors(condition jsonb, selectors text[]) RETURNS boolean AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM JSONB_ARRAY_ELEMENTS(condition) AS ss, 
             JSONB_ARRAY_ELEMENTS(ss->'conditionGroups') AS cg, 
             JSONB_ARRAY_ELEMENTS(cg->'conditions') AS each_condition
        WHERE (each_condition->>'subjectExternalSelectorValue' = ANY(selectors)) 
    );
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Indexes for join conditions in `matchSubjectMappings`
CREATE INDEX IF NOT EXISTS idx_subject_mappings_attribute_value_id ON subject_mappings(attribute_value_id);
CREATE INDEX IF NOT EXISTS idx_subject_mappings_subject_condition_set_id ON subject_mappings(subject_condition_set_id);
CREATE INDEX IF NOT EXISTS idx_attribute_values_attribute_definition_id ON attribute_values(attribute_definition_id);
CREATE INDEX IF NOT EXISTS idx_attribute_fqns_value_id ON attribute_fqns(value_id);

-- Index for the subject_mapping_actions table to speed up the lateral joins in `matchSubjectMappings`
CREATE INDEX IF NOT EXISTS idx_subject_mapping_actions_mapping_action ON subject_mapping_actions(subject_mapping_id, action_id);

-- Indexes for the WHERE conditions in `matchSubjectMappings`
CREATE INDEX IF NOT EXISTS idx_attribute_namespaces_active ON attribute_namespaces(active);
CREATE INDEX IF NOT EXISTS idx_attribute_definitions_active ON attribute_definitions(active);
CREATE INDEX IF NOT EXISTS idx_attribute_values_active ON attribute_values(active);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP FUNCTION IF EXISTS check_subject_selectors(jsonb, text[]);

DROP INDEX IF EXISTS idx_subject_mappings_attribute_value_id;
DROP INDEX IF EXISTS idx_subject_mappings_subject_condition_set_id;
DROP INDEX IF EXISTS idx_attribute_values_attribute_definition_id;
DROP INDEX IF EXISTS idx_attribute_fqns_value_id;
DROP INDEX IF EXISTS idx_subject_mapping_actions_mapping_action;
DROP INDEX IF EXISTS idx_attribute_namespaces_active;
DROP INDEX IF EXISTS idx_attribute_definitions_active;
DROP INDEX IF EXISTS idx_attribute_values_active;

-- +goose StatementEnd