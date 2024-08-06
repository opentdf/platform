-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS resource_mapping_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace_id UUID NOT NULL REFERENCES attribute_namespaces(id),
    name VARCHAR NOT NULL,
    UNIQUE(namespace_id, name)
);

ALTER TABLE resource_mappings ADD COLUMN group_id UUID REFERENCES resource_mapping_groups(id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE resource_mappings DROP COLUMN group_id;

DROP TABLE IF EXISTS resource_mapping_groups;

-- +goose StatementEnd
