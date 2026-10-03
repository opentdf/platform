-- Performance optimization indexes for OpenTDF Platform
-- This migration adds indexes to eliminate sequential scans and improve query performance

-- 1. Foreign Key Indexes (these are critical for JOIN performance)
-- attribute_definitions
CREATE INDEX idx_attribute_definitions_namespace_id ON attribute_definitions(namespace_id);
CREATE INDEX idx_attribute_definitions_namespace_id_active ON attribute_definitions(namespace_id, active);

-- attribute_values
CREATE INDEX idx_attribute_values_attribute_definition_id ON attribute_values(attribute_definition_id);
CREATE INDEX idx_attribute_values_attribute_definition_id_active ON attribute_values(attribute_definition_id, active);

-- attribute_value_members
CREATE INDEX idx_attribute_value_members_value_id ON attribute_value_members(value_id);
CREATE INDEX idx_attribute_value_members_member_id ON attribute_value_members(member_id);

-- resource_mappings
CREATE INDEX idx_resource_mappings_attribute_value_id ON resource_mappings(attribute_value_id);
CREATE INDEX idx_resource_mappings_attribute_value_id_active ON resource_mappings(attribute_value_id, active);

-- subject_mappings
CREATE INDEX idx_subject_mappings_attribute_value_id ON subject_mappings(attribute_value_id);
CREATE INDEX idx_subject_mappings_condition_set_id ON subject_mappings(condition_set_id);
CREATE INDEX idx_subject_mappings_attribute_value_id_active ON subject_mappings(attribute_value_id, active);

-- key_access_grants
CREATE INDEX idx_key_access_grants_namespace_id ON key_access_grants(namespace_id);
CREATE INDEX idx_key_access_grants_attribute_value_id ON key_access_grants(attribute_value_id);

-- 2. Indexes for Common Query Patterns
-- FQN lookups (composite index for namespace + attribute + value pattern)
CREATE INDEX idx_attribute_fqn_composite ON attribute_fqns(namespace, attribute, value, fqn);

-- Active record filtering (partial indexes for better performance)
CREATE INDEX idx_attribute_namespaces_active ON attribute_namespaces(active) WHERE active = true;
CREATE INDEX idx_attribute_definitions_active ON attribute_definitions(active) WHERE active = true;
CREATE INDEX idx_attribute_values_active ON attribute_values(active) WHERE active = true;
CREATE INDEX idx_resource_mappings_active ON resource_mappings(active) WHERE active = true;
CREATE INDEX idx_subject_mappings_active ON subject_mappings(active) WHERE active = true;

-- 3. JSONB Indexes for complex queries
-- GIN index for subject condition queries
CREATE INDEX idx_subject_condition_set_condition_gin ON subject_condition_set USING gin(condition);

-- 4. Composite indexes for specific query patterns from the codebase
-- For GetAttributesByNamespace queries
CREATE INDEX idx_attributes_namespace_lookup ON attribute_definitions(namespace_id, active, id);

-- For value lookups with definition
CREATE INDEX idx_values_definition_lookup ON attribute_values(attribute_definition_id, active, id);

-- For FQN resolution queries
CREATE INDEX idx_fqn_resolution ON attribute_fqns(fqn, namespace, attribute, value);

-- 5. Indexes for aggregation queries
-- For GROUP BY operations in attribute listings
CREATE INDEX idx_attribute_values_groupby ON attribute_values(attribute_definition_id, id, value);

-- For subject mapping aggregations
CREATE INDEX idx_subject_mappings_aggregation ON subject_mappings(attribute_value_id, id);

-- 6. Additional optimization for large table scans
-- Covering index for common attribute queries
CREATE INDEX idx_attribute_definitions_covering
ON attribute_definitions(namespace_id, active, id)
INCLUDE (name, rule, metadata);

-- Covering index for attribute values
CREATE INDEX idx_attribute_values_covering
ON attribute_values(attribute_definition_id, active, id)
INCLUDE (value, members);

-- 7. Index for timestamp-based queries (if needed for audit/history)
CREATE INDEX idx_resource_mappings_created_at ON resource_mappings(created_at);
CREATE INDEX idx_subject_mappings_created_at ON subject_mappings(created_at);
CREATE INDEX idx_resource_mappings_updated_at ON resource_mappings(updated_at);
CREATE INDEX idx_subject_mappings_updated_at ON subject_mappings(updated_at);

-- 8. Specialized indexes for key access service queries
CREATE INDEX idx_key_access_grants_composite ON key_access_grants(namespace_id, attribute_value_id, id);

-- Analyze tables after index creation to update statistics
ANALYZE attribute_namespaces;
ANALYZE attribute_definitions;
ANALYZE attribute_values;
ANALYZE attribute_value_members;
ANALYZE resource_mappings;
ANALYZE subject_mappings;
ANALYZE subject_condition_set;
ANALYZE key_access_grants;
ANALYZE attribute_fqns;
