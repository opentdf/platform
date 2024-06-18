-- +goose Up
-- +goose StatementBegin


-- Reusable function to replace a foreign key constraint with a new one that has ON DELETE CASCADE
CREATE OR REPLACE FUNCTION replace_fk_constraint_with_fk_delete_cascade(
    p_table_name TEXT,
    p_constraint_name TEXT,
    p_column_name TEXT,
    p_referenced_table TEXT
)
RETURNS VOID AS $$
BEGIN
    -- Drop the existing constraint
    EXECUTE format(
        'ALTER TABLE opentdf_policy.%I DROP CONSTRAINT %I;',
        p_table_name,
        p_constraint_name
    );

    -- Recreate the same constraint but adding ON DELETE CASCADE
    EXECUTE format(
        'ALTER TABLE opentdf_policy.%I ADD CONSTRAINT %I FOREIGN KEY (%I) REFERENCES opentdf_policy.%I (id) ON DELETE CASCADE;',
        p_table_name,
        p_constraint_name,
        p_column_name,
        p_referenced_table
    );
END;
$$ LANGUAGE plpgsql;

-- -- Invoke the function to replace the foreign key constraints with new ones that have ON DELETE CASCADE
SELECT replace_fk_constraint_with_fk_delete_cascade(
    'attribute_definitions',
    'attribute_definitions_namespace_id_fkey',
    'namespace_id',
    'attribute_namespaces'
);

SELECT replace_fk_constraint_with_fk_delete_cascade(
    'attribute_values',
    'attribute_values_attribute_definition_id_fkey',
    'attribute_definition_id',
    'attribute_definitions'
);

-- SELECT replace_fk_constraint_with_fk_delete_cascade(
--     'resource_mappings',
--     'resource_mappings_attribute_value_id_fkey',
--     'attribute_value_id',
--     'attribute_values'
-- );

-- SELECT replace_fk_constraint_with_fk_delete_cascade(
--     'subject_mappings',
--     'subject_mappings_attribute_value_id_fkey',
--     'attribute_value_id',
--     'attribute_values'
-- );

-- SELECT replace_fk_constraint_with_fk_delete_cascade(
--     'attribute_fqns',
--     'attribute_fqns_namespace_id_fkey',
--     'namespace_id',
--     'attribute_namespaces'
-- );

-- SELECT replace_fk_constraint_with_fk_delete_cascade(
--     'attribute_fqns',
--     'attribute_fqns_attribute_id_fkey',
--     'attribute_id',
--     'attribute_definitions'
-- );

-- SELECT replace_fk_constraint_with_fk_delete_cascade(
--     'attribute_fqns',
--     'attribute_fqns_value_id_fkey',
--     'value_id',
--     'attribute_values'
-- );

-- SELECT replace_fk_constraint_with_fk_delete_cascade(
--     'attribute_definition_key_access_grants',
--     'attribute_definition_key_access_grants_attribute_definition_id_fkey',
--     'attribute_definition_id',
--     'attribute_definitions'
-- );

-- SELECT replace_fk_constraint_with_fk_delete_cascade(
--     'attribute_definition_key_access_grants',
--     'attribute_definition_key_access_grant_key_access_server_id_fkey',
--     'key_access_server_id',
--     'key_access_servers'
-- );

-- SELECT replace_fk_constraint_with_fk_delete_cascade(
--     'attribute_value_key_access_grants',
--     'attribute_value_key_access_grants_key_access_server_id_fkey',
--     'key_access_server_id',
--     'key_access_servers'
-- );

-- SELECT replace_fk_constraint_with_fk_delete_cascade(
--     'attribute_value_key_access_grants',
--     'attribute_value_key_access_grants_attribute_value_id_fkey',
--     'attribute_value_id',
--     'attribute_values'
-- );

-- Delete Attribute Definitions when their parent Namespace is deleted
-- ALTER TABLE attribute_definitions
-- DROP CONSTRAINT attribute_definitions_namespace_id_fkey;

-- ALTER TABLE attribute_definitions
-- ADD CONSTRAINT attribute_definitions_namespace_id_fkey
-- FOREIGN KEY (namespace_id)
-- REFERENCES attribute_namespaces (id)
-- ON DELETE CASCADE;

-- -- Delete Attribute Values when their parent Definition is deleted
-- ALTER TABLE attribute_values
-- DROP CONSTRAINT attribute_values_attribute_definition_id_fkey;

-- ALTER TABLE attribute_values
-- ADD CONSTRAINT attribute_values_attribute_definition_id_fkey
-- FOREIGN KEY (attribute_definition_id)
-- REFERENCES attribute_definitions (id)
-- ON DELETE CASCADE;

-- -- Delete Resource Mappings when their parent Attribute Value is deleted
-- ALTER TABLE resource_mappings
-- DROP CONSTRAINT resource_mappings_attribute_value_id_fkey;

-- ALTER TABLE resource_mappings
-- ADD CONSTRAINT resource_mappings_attribute_value_id_fkey
-- FOREIGN KEY (attribute_value_id)
-- REFERENCES attribute_values (id)
-- ON DELETE CASCADE;

-- -- Delete Subject Mappings when their parent Attribute Value is deleted
-- ALTER TABLE subject_mappings
-- DROP CONSTRAINT subject_mappings_attribute_value_id_fkey;

-- ALTER TABLE subject_mappings
-- ADD CONSTRAINT subject_mappings_attribute_value_id_fkey
-- FOREIGN KEY (attribute_value_id)
-- REFERENCES attribute_values (id)
-- ON DELETE CASCADE;

-- -- FQNs
-- ALTER TABLE attribute_fqns
-- DROP CONSTRAINT attribute_fqns_namespace_id_fkey;

-- ALTER TABLE attribute_fqns
-- ADD CONSTRAINT attribute_fqns_namespace_id_fkey
-- FOREIGN KEY (namespace_id)
-- REFERENCES attribute_namespaces (id)
-- ON DELETE CASCADE;

-- ALTER TABLE attribute_fqns
-- DROP CONSTRAINT attribute_fqns_attribute_id_fkey;

-- ALTER TABLE attribute_fqns
-- ADD CONSTRAINT attribute_fqns_attribute_id_fkey
-- FOREIGN KEY (attribute_id)
-- REFERENCES attribute_definitions (id)
-- ON DELETE CASCADE;

-- ALTER TABLE attribute_fqns
-- DROP CONSTRAINT attribute_fqns_value_id_fkey;

-- ALTER TABLE attribute_fqns
-- ADD CONSTRAINT attribute_fqns_value_id_fkey
-- FOREIGN KEY (value_id)
-- REFERENCES attribute_values (id)
-- ON DELETE CASCADE;

-- -- KAS Registrations

-- ALTER TABLE attribute_definition_key_access_grants
-- DROP CONSTRAINT attribute_definition_key_access_gr_attribute_definition_id_fkey;

-- ALTER TABLE attribute_definition_key_access_grants
-- ADD CONSTRAINT attribute_definition_key_access_gr_attribute_definition_id_fkey
-- FOREIGN KEY (attribute_definition_id)
-- REFERENCES attribute_definitions (id)
-- ON DELETE CASCADE;

-- ALTER TABLE attribute_definition_key_access_grants
-- DROP CONSTRAINT attribute_definition_key_access_grant_key_access_server_id_fkey;

-- ALTER TABLE attribute_definition_key_access_grants
-- ADD CONSTRAINT attribute_definition_key_access_grant_key_access_server_id_fkey
-- FOREIGN KEY (key_access_server_id)
-- REFERENCES key_access_servers (id)
-- ON DELETE CASCADE;

-- ALTER TABLE attribute_value_key_access_grants
-- DROP CONSTRAINT attribute_value_key_access_grants_key_access_server_id_fkey;

-- ALTER TABLE attribute_value_key_access_grants
-- ADD CONSTRAINT attribute_value_key_access_grants_key_access_server_id_fkey
-- FOREIGN KEY (key_access_server_id)
-- REFERENCES key_access_servers (id)
-- ON DELETE CASCADE;

-- ALTER TABLE attribute_value_key_access_grants
-- DROP CONSTRAINT attribute_value_key_access_grants_attribute_value_id_fkey;

-- ALTER TABLE attribute_value_key_access_grants
-- ADD CONSTRAINT attribute_value_key_access_grants_attribute_value_id_fkey
-- FOREIGN KEY (attribute_value_id)
-- REFERENCES attribute_values (id)
-- ON DELETE CASCADE;

-- TODO: MEMBERS cascade?
-- TODO: delete value from hierarchy order column in definitions table when value is deleted

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS subject_mappings;
DROP TABLE IF EXISTS resource_mappings;
DROP TABLE IF EXISTS attribute_value_key_access_grants;
DROP TABLE IF EXISTS attribute_definition_key_access_grants;
DROP TABLE IF EXISTS key_access_servers;
DROP TABLE IF EXISTS attribute_values;
DROP TABLE IF EXISTS attribute_definitions;
DROP TABLE IF EXISTS attribute_namespaces;

DROP TYPE attribute_definition_rule;
DROP TYPE subject_mappings_operator;
-- +goose StatementEnd