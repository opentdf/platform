-- +goose Up
-- +goose StatementBegin

--------------------
---- ListAttributes
--------------------

-- For attribute_definitions
CREATE INDEX idx_ad_namespace_id ON attribute_definitions(namespace_id);
CREATE INDEX idx_ad_active ON attribute_definitions(active);
CREATE INDEX idx_ad_namespace_active ON attribute_definitions(namespace_id, active);

-- For attribute_namespaces
CREATE INDEX idx_n_name ON attribute_namespaces(name);

-- For attribute_values
CREATE INDEX idx_av_attr_def_id ON attribute_values(attribute_definition_id);

-- For attribute_value_key_access_grants
CREATE INDEX idx_avg_attr_val_id ON attribute_value_key_access_grants(attribute_value_id);
CREATE INDEX idx_avg_kas_id ON attribute_value_key_access_grants(key_access_server_id);

-- For attribute_fqns
CREATE INDEX idx_fqns_attr_id_val_id ON attribute_fqns(attribute_id, value_id);
CREATE INDEX idx_fqns_attr_id_null_val_id ON attribute_fqns(attribute_id) WHERE value_id IS NULL;

----------------------
-- ListSubjectMappings
----------------------

-- For subject_mappings
CREATE INDEX idx_sm_attribute_value_id ON subject_mappings(attribute_value_id);
CREATE INDEX idx_sm_subject_condition_set_id ON subject_mappings(subject_condition_set_id);

-- For actions
CREATE INDEX idx_a_is_standard ON actions(is_standard);

-- For subject_mapping_actions (critical for subquery performance)
CREATE INDEX idx_sma_subject_mapping_id ON subject_mapping_actions(subject_mapping_id);
CREATE INDEX idx_sma_action_id ON subject_mapping_actions(action_id);
CREATE INDEX idx_sma_subject_mapping_action ON subject_mapping_actions(subject_mapping_id, action_id);

-- For attribute_fqns
CREATE INDEX idx_fqns_value_id ON attribute_fqns(value_id);

-- +goose StatementEnd


-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_ad_namespace_id;
DROP INDEX IF EXISTS idx_ad_active;
DROP INDEX IF EXISTS idx_ad_namespace_active;

DROP INDEX IF EXISTS idx_n_name;

DROP INDEX IF EXISTS idx_av_attr_def_id;

DROP INDEX IF EXISTS idx_avg_attr_val_id;
DROP INDEX IF EXISTS idx_avg_kas_id;

DROP INDEX IF EXISTS idx_fqns_attr_id_val_id;
DROP INDEX IF EXISTS idx_fqns_attr_id_null_val_id;

DROP INDEX IF EXISTS idx_sm_attribute_value_id;
DROP INDEX IF EXISTS idx_sm_subject_condition_set_id;

DROP INDEX IF EXISTS idx_a_is_standard;

DROP INDEX IF EXISTS idx_sma_subject_mapping_id;
DROP INDEX IF EXISTS idx_sma_action_id;
DROP INDEX IF EXISTS idx_sma_subject_mapping_action;

DROP INDEX IF EXISTS idx_fqns_value_id;

-- +goose StatementEnd