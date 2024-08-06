-- +goose Up
-- +goose StatementBegin

-- Add comments to every column and table

COMMENT ON TABLE attribute_fqns IS 'Table to store the fully qualified names of attributes for reverse lookup at their object IDs';
COMMENT ON COLUMN attribute_fqns.id IS 'Primary key for the table';
COMMENT ON COLUMN attribute_fqns.fqn IS 'Fully qualified name of the attribute (i.e. https://<namespace>/attr/<attribute name>/value/<value>)';
COMMENT ON COLUMN attribute_fqns.namespace_id IS 'Foreign key to the namespace of the attribute';
COMMENT ON COLUMN attribute_fqns.attribute_id IS 'Foreign key to the attribute definition';
COMMENT ON COLUMN attribute_fqns.value_id IS 'Foreign key to the attribute value';

COMMENT ON TABLE attribute_namespaces IS 'Table to store the parent namespaces of platform policy attributes and related policy objects';
COMMENT ON COLUMN attribute_namespaces.id IS 'Primary key for the table';
COMMENT ON COLUMN attribute_namespaces.name IS 'Name of the namespace (i.e. example.com)';
COMMENT ON COLUMN attribute_namespaces.metadata IS 'Metadata for the namespace (see protos for structure)';
COMMENT ON COLUMN attribute_namespaces.active IS 'Active/Inactive state';

COMMENT ON TABLE attribute_definitions IS 'Table to store the definitions of attributes';
COMMENT ON COLUMN attribute_definitions.id IS 'Primary key for the table';
COMMENT ON COLUMN attribute_definitions.namespace_id IS 'Foreign key to the parent namespace of the attribute definition';
COMMENT ON COLUMN attribute_definitions.name IS 'Name of the attribute (i.e. organization or classification), unique within the namespace';
COMMENT ON COLUMN attribute_definitions.rule IS 'Rule for the attribute (see protos for options)';
COMMENT ON COLUMN attribute_definitions.metadata IS 'Metadata for the attribute definition (see protos for structure)';
COMMENT ON COLUMN attribute_definitions.active IS 'Active/Inactive state';
COMMENT ON COLUMN attribute_definitions.values_order IS 'Order of value ids for the attribute (important for hierarchy rule)';

COMMENT ON TABLE attribute_values IS 'Table to store the values of attributes';
COMMENT ON COLUMN attribute_values.id IS 'Primary key for the table';
COMMENT ON COLUMN attribute_values.attribute_definition_id IS 'Foreign key to the parent attribute definition';
COMMENT ON COLUMN attribute_values.value IS 'Value of the attribute (i.e. "manager" or "admin" on an attribute for titles), unique within the definition';
COMMENT ON COLUMN attribute_values.metadata IS 'Metadata for the attribute value (see protos for structure)';
COMMENT ON COLUMN attribute_values.active IS 'Active/Inactive state';

COMMENT ON TABLE key_access_servers IS 'Table to store the known registrations of key access servers (KASs)';
COMMENT ON COLUMN key_access_servers.id IS 'Primary key for the table';
COMMENT ON COLUMN key_access_servers.uri IS 'URI of the KAS';
COMMENT ON COLUMN key_access_servers.public_key IS 'Public key of the KAS (see protos for structure/options)';
COMMENT ON COLUMN key_access_servers.metadata IS 'Metadata for the KAS (see protos for structure)';

COMMENT ON TABLE attribute_definition_key_access_grants IS 'Table to store the grants of key access servers (KASs) to attribute definitions';
COMMENT ON COLUMN attribute_definition_key_access_grants.attribute_definition_id IS 'Foreign key to the attribute definition';
COMMENT ON COLUMN attribute_definition_key_access_grants.key_access_server_id IS 'Foreign key to the KAS registration';

COMMENT ON TABLE attribute_value_key_access_grants IS 'Table to store the grants of key access servers (KASs) to attribute values';
COMMENT ON COLUMN attribute_value_key_access_grants.attribute_value_id IS 'Foreign key to the attribute value';
COMMENT ON COLUMN attribute_value_key_access_grants.key_access_server_id IS 'Foreign key to the KAS registration';

COMMENT ON TABLE resource_mappings IS 'Table to store associated terms that should map resource data to attribute values';
COMMENT ON COLUMN resource_mappings.id IS 'Primary key for the table';
COMMENT ON COLUMN resource_mappings.attribute_value_id IS 'Foreign key to the attribute value';
COMMENT ON COLUMN resource_mappings.terms IS 'Terms to match against resource data (i.e. translations "roi", "rey", or "kung" in a terms list could map to the value "/attr/card/value/king")';
COMMENT ON COLUMN resource_mappings.metadata IS 'Metadata for the resource mapping (see protos for structure)';

COMMENT ON TABLE subject_mappings IS 'Table to store conditions that logically entitle subject entity representations to attribute values';
COMMENT ON COLUMN subject_mappings.id IS 'Primary key for the table';
COMMENT ON COLUMN subject_mappings.attribute_value_id IS 'Foreign key to the attribute value';
COMMENT ON COLUMN subject_mappings.subject_condition_set_id IS 'Foreign key to the condition set that entitles the subject entity to the attribute value';
COMMENT ON COLUMN subject_mappings.actions IS 'Actions that the subject entity can perform on the attribute value (see protos for details)';
COMMENT ON COLUMN subject_mappings.metadata IS 'Metadata for the subject mapping (see protos for structure)';

COMMENT ON TABLE subject_condition_set IS 'Table to store sets of conditions that logically entitle subject entity representations to attribute values via a subject mapping';
COMMENT ON COLUMN subject_condition_set.id IS 'Primary key for the table';
COMMENT ON COLUMN subject_condition_set.condition IS 'Conditions that must be met for the subject entity to be entitled to the attribute value (see protos for JSON structure)';
COMMENT ON COLUMN subject_condition_set.metadata IS 'Metadata for the condition set (see protos for structure)';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

COMMENT ON TABLE attribute_fqns IS NULL;
COMMENT ON COLUMN attribute_fqns.id IS NULL;
COMMENT ON COLUMN attribute_fqns.fqn IS NULL;
COMMENT ON COLUMN attribute_fqns.namespace_id IS NULL;
COMMENT ON COLUMN attribute_fqns.attribute_id IS NULL;
COMMENT ON COLUMN attribute_fqns.value_id IS NULL;

COMMENT ON TABLE attribute_namespaces IS NULL;
COMMENT ON COLUMN attribute_namespaces.id IS NULL;
COMMENT ON COLUMN attribute_namespaces.name IS NULL;
COMMENT ON COLUMN attribute_namespaces.metadata IS NULL;
COMMENT ON COLUMN attribute_namespaces.active IS NULL;

COMMENT ON TABLE attribute_definitions IS NULL;
COMMENT ON COLUMN attribute_definitions.id IS NULL;
COMMENT ON COLUMN attribute_definitions.namespace_id IS NULL;
COMMENT ON COLUMN attribute_definitions.name IS NULL;
COMMENT ON COLUMN attribute_definitions.rule IS NULL;
COMMENT ON COLUMN attribute_definitions.metadata IS NULL;
COMMENT ON COLUMN attribute_definitions.active IS NULL;
COMMENT ON COLUMN attribute_definitions.values_order IS NULL;

COMMENT ON TABLE attribute_values IS NULL;
COMMENT ON COLUMN attribute_values.id IS NULL;
COMMENT ON COLUMN attribute_values.attribute_definition_id IS NULL;
COMMENT ON COLUMN attribute_values.value IS NULL;
COMMENT ON COLUMN attribute_values.metadata IS NULL;
COMMENT ON COLUMN attribute_values.active IS NULL;

COMMENT ON TABLE key_access_servers IS NULL;
COMMENT ON COLUMN key_access_servers.id IS NULL;
COMMENT ON COLUMN key_access_servers.uri IS NULL;
COMMENT ON COLUMN key_access_servers.public_key IS NULL;
COMMENT ON COLUMN key_access_servers.metadata IS NULL;

COMMENT ON TABLE attribute_definition_key_access_grants IS NULL;
COMMENT ON COLUMN attribute_definition_key_access_grants.attribute_definition_id IS NULL;
COMMENT ON COLUMN attribute_definition_key_access_grants.key_access_server_id IS NULL;

COMMENT ON TABLE attribute_value_key_access_grants IS NULL;
COMMENT ON COLUMN attribute_value_key_access_grants.attribute_value_id IS NULL;
COMMENT ON COLUMN attribute_value_key_access_grants.key_access_server_id IS NULL;

COMMENT ON TABLE resource_mappings IS NULL;
COMMENT ON COLUMN resource_mappings.id IS NULL;
COMMENT ON COLUMN resource_mappings.attribute_value_id IS NULL;
COMMENT ON COLUMN resource_mappings.terms IS NULL;
COMMENT ON COLUMN resource_mappings.metadata IS NULL;

COMMENT ON TABLE subject_mappings IS NULL;
COMMENT ON COLUMN subject_mappings.id IS NULL;
COMMENT ON COLUMN subject_mappings.attribute_value_id IS NULL;
COMMENT ON COLUMN subject_mappings.subject_condition_set_id IS NULL;
COMMENT ON COLUMN subject_mappings.actions IS NULL;
COMMENT ON COLUMN subject_mappings.metadata IS NULL;

COMMENT ON TABLE subject_condition_set IS NULL;
COMMENT ON COLUMN subject_condition_set.id IS NULL;
COMMENT ON COLUMN subject_condition_set.condition IS NULL;
COMMENT ON COLUMN subject_condition_set.metadata IS NULL;

-- +goose StatementEnd