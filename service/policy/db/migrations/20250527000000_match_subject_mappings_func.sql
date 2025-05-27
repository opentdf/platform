-- +goose Up
-- +goose StatementBegin
-- Create a function to extract the selector values
CREATE OR REPLACE FUNCTION extract_selector_values() RETURNS TRIGGER AS $$
BEGIN
  NEW.selector_values := (
    SELECT ARRAY_AGG(DISTINCT selector_value)
    FROM JSONB_ARRAY_ELEMENTS(NEW.condition) AS ss,
         JSONB_ARRAY_ELEMENTS(ss->'conditionGroups') AS cg,
         JSONB_ARRAY_ELEMENTS(cg->'conditions') AS each_condition,
         JSONB_EXTRACT_PATH_TEXT(each_condition, 'subjectExternalSelectorValue') AS selector_value
    WHERE selector_value IS NOT NULL
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Add the column (not generated)
ALTER TABLE subject_condition_set ADD COLUMN selector_values TEXT[];

COMMENT ON COLUMN subject_condition_set.selector_values IS 'Array of cached selector values extracted from the condition JSONB and maintained via trigger.';

-- Create trigger to maintain the column
CREATE TRIGGER update_selector_values
BEFORE INSERT OR UPDATE ON subject_condition_set
FOR EACH ROW EXECUTE FUNCTION extract_selector_values();

-- Populate new, maintained column on all existing rows
UPDATE subject_condition_set SET condition = condition;

-- Create indices consumed by `matchSubjectMappings` query
CREATE INDEX idx_subject_condition_set_selector_values 
ON subject_condition_set USING GIN(selector_values);

CREATE INDEX IF NOT EXISTS idx_subject_mappings_attribute_value_id 
ON subject_mappings(attribute_value_id);

CREATE INDEX IF NOT EXISTS idx_subject_mappings_subject_condition_set_id 
ON subject_mappings(subject_condition_set_id);

CREATE INDEX IF NOT EXISTS idx_attribute_values_attribute_definition_id 
ON attribute_values(attribute_definition_id);

CREATE INDEX IF NOT EXISTS idx_attribute_fqns_value_id 
ON attribute_fqns(value_id);

CREATE INDEX IF NOT EXISTS idx_subject_mapping_actions_mapping_action 
ON subject_mapping_actions(subject_mapping_id, action_id);

CREATE INDEX IF NOT EXISTS idx_attribute_namespaces_active 
ON attribute_namespaces(active);

CREATE INDEX IF NOT EXISTS idx_attribute_definitions_active 
ON attribute_definitions(active);

CREATE INDEX IF NOT EXISTS idx_attribute_values_active 
ON attribute_values(active);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE subject_condition_set DROP COLUMN IF EXISTS selector_values;
DROP TRIGGER IF EXISTS update_selector_values ON subject_condition_set;
DROP FUNCTION IF EXISTS extract_selector_values;

DROP INDEX IF EXISTS idx_subject_condition_set_selector_values;
DROP INDEX IF EXISTS idx_subject_mappings_attribute_value_id;
DROP INDEX IF EXISTS idx_subject_mappings_subject_condition_set_id;
DROP INDEX IF EXISTS idx_attribute_values_attribute_definition_id;
DROP INDEX IF EXISTS idx_attribute_fqns_value_id;
DROP INDEX IF EXISTS idx_subject_mapping_actions_mapping_action;
DROP INDEX IF EXISTS idx_attribute_namespaces_active;
DROP INDEX IF EXISTS idx_attribute_definitions_active;
DROP INDEX IF EXISTS idx_attribute_values_active;

-- +goose StatementEnd