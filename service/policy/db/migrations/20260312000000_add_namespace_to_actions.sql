-- +goose Up
-- +goose StatementBegin

-- Add nullable namespace_id column to actions for namespace-scoped custom actions.
-- Keep nullable for legacy custom actions and standard CRUD actions.
ALTER TABLE actions
  ADD COLUMN namespace_id UUID REFERENCES attribute_namespaces(id) ON DELETE CASCADE;

-- Drop existing global uniqueness constraint.
ALTER TABLE actions DROP CONSTRAINT actions_name_unique;

-- Namespaced custom actions: unique name per namespace.
CREATE UNIQUE INDEX actions_namespace_name_unique
  ON actions(namespace_id, name) WHERE namespace_id IS NOT NULL;

-- Legacy/global actions (including standard CRUD actions): unique name globally.
CREATE UNIQUE INDEX actions_name_unique
  ON actions(name) WHERE namespace_id IS NULL;

-- Index for namespace-scoped action queries.
CREATE INDEX idx_actions_namespace_id
  ON actions(namespace_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_actions_namespace_id;
DROP INDEX IF EXISTS actions_name_unique;
DROP INDEX IF EXISTS actions_namespace_name_unique;

ALTER TABLE actions ADD CONSTRAINT actions_name_unique UNIQUE (name);

ALTER TABLE actions DROP COLUMN IF EXISTS namespace_id;

-- +goose StatementEnd
