-- +goose Up
-- +goose StatementBegin

-- Add a nullable owning namespace to resource mappings so they can be optionally
-- namespaced (owned by a tenant), independent of the namespace of the attribute
-- value they map. When a mapping belongs to a group, this matches the group's
-- namespace; ungrouped/legacy mappings leave it NULL.
ALTER TABLE resource_mappings
  ADD COLUMN namespace_id UUID REFERENCES attribute_namespaces(id) ON DELETE CASCADE;

COMMENT ON COLUMN resource_mappings.namespace_id IS 'Optional owning namespace of the resource mapping. If the mapping belongs to a group, it matches the group namespace. The mapped attribute value may belong to a different namespace.';

-- Index for namespace-scoped resource mapping queries.
CREATE INDEX idx_resource_mappings_namespace_id
  ON resource_mappings(namespace_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_resource_mappings_namespace_id;

ALTER TABLE resource_mappings DROP COLUMN IF EXISTS namespace_id;

-- +goose StatementEnd
