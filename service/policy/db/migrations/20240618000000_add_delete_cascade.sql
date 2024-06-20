-- +goose Up
-- +goose StatementBegin

-- To enable admins to perform unsafe mutations on their data, the Policy UnsafeService will support deletions of Namespaces, Definitions,
-- and Attribute Values. These deletions should be cascading, so we will update our foreign key constraints to cascade deletions throughout
-- when a parent object is deleted.

-- Delete Attribute Definitions when their parent Namespace is deleted
ALTER TABLE attribute_definitions
DROP CONSTRAINT attribute_definitions_namespace_id_fkey;

ALTER TABLE attribute_definitions
ADD CONSTRAINT attribute_definitions_namespace_id_fkey_cascades
FOREIGN KEY (namespace_id)
REFERENCES attribute_namespaces (id)
ON DELETE CASCADE;

-- Delete Attribute Values when their parent Definition is deleted
ALTER TABLE attribute_values
DROP CONSTRAINT attribute_values_attribute_definition_id_fkey;

ALTER TABLE attribute_values
ADD CONSTRAINT attribute_values_attribute_definition_id_fkey_cascades
FOREIGN KEY (attribute_definition_id)
REFERENCES attribute_definitions (id)
ON DELETE CASCADE;

-- Delete Resource Mappings when their parent Attribute Value is deleted
ALTER TABLE resource_mappings
DROP CONSTRAINT resource_mappings_attribute_value_id_fkey;

ALTER TABLE resource_mappings
ADD CONSTRAINT resource_mappings_attribute_value_id_fkey_cascades
FOREIGN KEY (attribute_value_id)
REFERENCES attribute_values (id)
ON DELETE CASCADE;

-- Delete Subject Mappings when their parent Attribute Value is deleted
ALTER TABLE subject_mappings
DROP CONSTRAINT subject_mappings_attribute_value_id_fkey;

ALTER TABLE subject_mappings
ADD CONSTRAINT subject_mappings_attribute_value_id_fkey_cascades
FOREIGN KEY (attribute_value_id)
REFERENCES attribute_values (id)
ON DELETE CASCADE;

-- FQNs
ALTER TABLE attribute_fqns
DROP CONSTRAINT attribute_fqns_namespace_id_fkey;

ALTER TABLE attribute_fqns
ADD CONSTRAINT attribute_fqns_namespace_id_fkey_cascades
FOREIGN KEY (namespace_id)
REFERENCES attribute_namespaces (id)
ON DELETE CASCADE;

ALTER TABLE attribute_fqns
DROP CONSTRAINT attribute_fqns_attribute_id_fkey;

ALTER TABLE attribute_fqns
ADD CONSTRAINT attribute_fqns_attribute_id_fkey_cascades
FOREIGN KEY (attribute_id)
REFERENCES attribute_definitions (id)
ON DELETE CASCADE;

ALTER TABLE attribute_fqns
DROP CONSTRAINT attribute_fqns_value_id_fkey;

ALTER TABLE attribute_fqns
ADD CONSTRAINT attribute_fqns_value_id_fkey_cascades
FOREIGN KEY (value_id)
REFERENCES attribute_values (id)
ON DELETE CASCADE;

-- KAS Registrations

ALTER TABLE attribute_definition_key_access_grants
DROP CONSTRAINT attribute_definition_key_access_gr_attribute_definition_id_fkey;

ALTER TABLE attribute_definition_key_access_grants
ADD CONSTRAINT attr_def_key_access_gr_attr_def_id_fkey_cascades
FOREIGN KEY (attribute_definition_id)
REFERENCES attribute_definitions (id)
ON DELETE CASCADE;

ALTER TABLE attribute_definition_key_access_grants
DROP CONSTRAINT attribute_definition_key_access_grant_key_access_server_id_fkey;

ALTER TABLE attribute_definition_key_access_grants
ADD CONSTRAINT attr_def_key_access_grant_kas_id_fkey_cascades
FOREIGN KEY (key_access_server_id)
REFERENCES key_access_servers (id)
ON DELETE CASCADE;

ALTER TABLE attribute_value_key_access_grants
DROP CONSTRAINT attribute_value_key_access_grants_key_access_server_id_fkey;

ALTER TABLE attribute_value_key_access_grants
ADD CONSTRAINT attr_val_key_access_grants_kas_id_fkey_cascades
FOREIGN KEY (key_access_server_id)
REFERENCES key_access_servers (id)
ON DELETE CASCADE;

ALTER TABLE attribute_value_key_access_grants
DROP CONSTRAINT attribute_value_key_access_grants_attribute_value_id_fkey;

ALTER TABLE attribute_value_key_access_grants
ADD CONSTRAINT attr_val_key_access_grants_attr_val_id_fkey_cascades
FOREIGN KEY (attribute_value_id)
REFERENCES attribute_values (id)
ON DELETE CASCADE;

-- Members are deleted via trigger on attribute_values row deletion (see 20240402000000_preserve_value_order.sql).
-- Foreign key references still need to be updated to cascade delete if a member or parent value with members is deleted.
ALTER TABLE attribute_value_members
DROP CONSTRAINT attribute_value_members_value_id_fkey;

ALTER TABLE attribute_value_members
ADD CONSTRAINT attr_val_members_value_id_fkey_cascades
FOREIGN KEY (value_id)
REFERENCES attribute_values (id)
ON DELETE CASCADE;

ALTER TABLE attribute_value_members
DROP CONSTRAINT attribute_value_members_member_id_fkey;

ALTER TABLE attribute_value_members
ADD CONSTRAINT attr_val_members_member_id_fkey_cascades
FOREIGN KEY (member_id)
REFERENCES attribute_values (id)
ON DELETE CASCADE;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- When migrating down, update foreign key default constraints to put back constraints without cascading deletion.

-- Do not cascade deletion of Attribute Definitions when their parent Namespace is deleted
ALTER TABLE attribute_definitions
DROP CONSTRAINT attribute_definitions_namespace_id_fkey_cascades;

ALTER TABLE attribute_definitions
ADD CONSTRAINT attribute_definitions_namespace_id_fkey
FOREIGN KEY (namespace_id)
REFERENCES attribute_namespaces (id);

-- Do not cascade deletion of Attribute Values when their parent Definition is deleted
ALTER TABLE attribute_values
DROP CONSTRAINT attribute_values_attribute_definition_id_fkey_cascades;

ALTER TABLE attribute_values
ADD CONSTRAINT attribute_values_attribute_definition_id_fkey
FOREIGN KEY (attribute_definition_id)
REFERENCES attribute_definitions (id);

-- Do not cascade deletion of Resource Mappings when their parent Attribute Value is deleted
ALTER TABLE resource_mappings
DROP CONSTRAINT resource_mappings_attribute_value_id_fkey_cascades;

ALTER TABLE resource_mappings
ADD CONSTRAINT resource_mappings_attribute_value_id_fkey
FOREIGN KEY (attribute_value_id)
REFERENCES attribute_values (id);

-- Do not cascade deletion of Subject Mappings when their parent Attribute Value is deleted
ALTER TABLE subject_mappings
DROP CONSTRAINT subject_mappings_attribute_value_id_fkey_cascades;

ALTER TABLE subject_mappings
ADD CONSTRAINT subject_mappings_attribute_value_id_fkey
FOREIGN KEY (attribute_value_id)
REFERENCES attribute_values (id);

-- Do not cascade deletion of FQNs when their parent objects are deleted
ALTER TABLE attribute_fqns
DROP CONSTRAINT attribute_fqns_namespace_id_fkey_cascades;

ALTER TABLE attribute_fqns
ADD CONSTRAINT attribute_fqns_namespace_id_fkey
FOREIGN KEY (namespace_id)
REFERENCES attribute_namespaces (id);

ALTER TABLE attribute_fqns
DROP CONSTRAINT attribute_fqns_attribute_id_fkey_cascades;

ALTER TABLE attribute_fqns
ADD CONSTRAINT attribute_fqns_attribute_id_fkey
FOREIGN KEY (attribute_id)
REFERENCES attribute_definitions (id);

ALTER TABLE attribute_fqns
DROP CONSTRAINT attribute_fqns_value_id_fkey_cascades;

ALTER TABLE attribute_fqns
ADD CONSTRAINT attribute_fqns_value_id_fkey
FOREIGN KEY (value_id)
REFERENCES attribute_values (id);

-- Do not cascade deletion of KAS Registrations when an associated policy object is deleted

ALTER TABLE attribute_definition_key_access_grants
DROP CONSTRAINT attr_def_key_access_gr_attr_def_id_fkey_cascades;

ALTER TABLE attribute_definition_key_access_grants
ADD CONSTRAINT attribute_definition_key_access_gr_attribute_definition_id_fkey
FOREIGN KEY (attribute_definition_id)
REFERENCES attribute_definitions (id);

ALTER TABLE attribute_definition_key_access_grants
DROP CONSTRAINT attr_def_key_access_grant_kas_id_fkey_cascades;

ALTER TABLE attribute_definition_key_access_grants
ADD CONSTRAINT attribute_definition_key_access_grant_key_access_server_id_fkey
FOREIGN KEY (key_access_server_id)
REFERENCES key_access_servers (id);

ALTER TABLE attribute_value_key_access_grants
DROP CONSTRAINT attr_val_key_access_grants_kas_id_fkey_cascades;

ALTER TABLE attribute_value_key_access_grants
ADD CONSTRAINT attribute_value_key_access_grants_key_access_server_id_fkey
FOREIGN KEY (key_access_server_id)
REFERENCES key_access_servers (id);

ALTER TABLE attribute_value_key_access_grants
DROP CONSTRAINT attr_val_key_access_grants_attr_val_id_fkey_cascades;

ALTER TABLE attribute_value_key_access_grants
ADD CONSTRAINT attribute_value_key_access_grants_attribute_value_id_fkey
FOREIGN KEY (attribute_value_id)
REFERENCES attribute_values (id);

ALTER TABLE attribute_value_members
DROP CONSTRAINT attr_val_members_value_id_fkey_cascades;

ALTER TABLE attribute_value_members
ADD CONSTRAINT attribute_value_members_value_id_fkey
FOREIGN KEY (value_id)
REFERENCES attribute_values (id);

ALTER TABLE attribute_value_members
DROP CONSTRAINT attr_val_members_member_id_fkey_cascades;

ALTER TABLE attribute_value_members
ADD CONSTRAINT attribute_value_members_member_id_fkey
FOREIGN KEY (member_id)
REFERENCES attribute_values (id);

-- +goose StatementEnd