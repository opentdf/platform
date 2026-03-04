-- +goose Up
-- +goose StatementBegin

-- Add nullable namespace_id column to registered_resources
ALTER TABLE registered_resources
  ADD COLUMN namespace_id UUID REFERENCES attribute_namespaces(id) ON DELETE CASCADE;

-- Drop existing global uniqueness constraint
ALTER TABLE registered_resources DROP CONSTRAINT registered_resources_name_key;

-- Namespaced RRs: unique name within namespace
CREATE UNIQUE INDEX registered_resources_namespace_name_unique
  ON registered_resources(namespace_id, name) WHERE namespace_id IS NOT NULL;

-- Legacy RRs (no namespace): unique name globally
CREATE UNIQUE INDEX registered_resources_name_unique
  ON registered_resources(name) WHERE namespace_id IS NULL;

-- Index for namespace-scoped queries
CREATE INDEX idx_registered_resources_namespace
  ON registered_resources(namespace_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_registered_resources_namespace;
DROP INDEX IF EXISTS registered_resources_name_unique;
DROP INDEX IF EXISTS registered_resources_namespace_name_unique;

ALTER TABLE registered_resources ADD CONSTRAINT registered_resources_name_key UNIQUE (name);

ALTER TABLE registered_resources DROP COLUMN IF EXISTS namespace_id;

-- +goose StatementEnd
