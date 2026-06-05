-- +goose Up
-- +goose StatementBegin

-- Add nullable namespace_id column to subject_condition_set for namespace-scoped SCSes.
-- Keep nullable for backwards compatibility with existing SCSes not yet migrated to a namespace.
ALTER TABLE subject_condition_set
  ADD COLUMN namespace_id UUID REFERENCES attribute_namespaces(id) ON DELETE CASCADE;

-- Index for namespace-scoped SCS queries.
CREATE INDEX idx_subject_condition_set_namespace_id
  ON subject_condition_set(namespace_id);

-- Add nullable namespace_id column to subject_mappings for namespace-scoped SMs.
-- Keep nullable for backwards compatibility with existing SMs not yet migrated to a namespace.
ALTER TABLE subject_mappings
  ADD COLUMN namespace_id UUID REFERENCES attribute_namespaces(id) ON DELETE CASCADE;

-- Index for namespace-scoped SM queries.
CREATE INDEX idx_subject_mappings_namespace_id
  ON subject_mappings(namespace_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_subject_mappings_namespace_id;
ALTER TABLE subject_mappings DROP COLUMN IF EXISTS namespace_id;

DROP INDEX IF EXISTS idx_subject_condition_set_namespace_id;
ALTER TABLE subject_condition_set DROP COLUMN IF EXISTS namespace_id;

-- +goose StatementEnd
