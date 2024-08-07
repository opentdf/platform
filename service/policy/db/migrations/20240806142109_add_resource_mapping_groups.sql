-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS resource_mapping_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace_id UUID NOT NULL REFERENCES attribute_namespaces(id) ON DELETE CASCADE,
    name VARCHAR NOT NULL,
    UNIQUE(namespace_id, name)
);

COMMENT ON TABLE resource_mapping_groups IS 'Table to store the groups of resource mappings by unique namespace and group name combinations';
COMMENT ON COLUMN resource_mapping_groups.id IS 'Primary key for the table';
COMMENT ON COLUMN resource_mapping_groups.namespace_id IS 'Foreign key to the namespace of the attribute';
COMMENT ON COLUMN resource_mapping_groups.name IS 'Name for the group of resource mappings';

ALTER TABLE resource_mappings ADD COLUMN group_id UUID REFERENCES resource_mapping_groups(id) ON DELETE SET NULL;

COMMENT ON COLUMN resource_mappings.group_id IS 'Foreign key to the parent group of the resource mapping (optional, a resource mapping may not be in a group)';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE resource_mappings DROP COLUMN group_id;

DROP TABLE IF EXISTS resource_mapping_groups;

-- +goose StatementEnd
