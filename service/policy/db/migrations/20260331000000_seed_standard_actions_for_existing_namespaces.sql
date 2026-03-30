-- +goose Up
-- +goose StatementBegin

-- Seed standard actions (create, read, update, delete) into all existing namespaces.
-- New namespaces already receive standard actions automatically via CreateNamespace().
-- This migration retroactively seeds them for namespaces created before action namespacing was introduced.
-- ON CONFLICT DO NOTHING makes this idempotent.
INSERT INTO actions (name, is_standard, namespace_id)
SELECT a.name, TRUE, ns.id
FROM attribute_namespaces ns
CROSS JOIN (VALUES ('create'), ('read'), ('update'), ('delete')) AS a(name)
ON CONFLICT (namespace_id, name) WHERE namespace_id IS NOT NULL DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Remove namespace-scoped standard actions that were seeded by this migration.
-- Only removes rows where is_standard = TRUE and namespace_id IS NOT NULL,
-- preserving global standard actions and any user-created custom actions.
DELETE FROM actions
WHERE is_standard = TRUE
  AND namespace_id IS NOT NULL;

-- +goose StatementEnd
