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

-- No-op: namespace-scoped standard actions are required for namespace policy
-- evaluation and reference rewrites. Removing them can break existing namespaces.
SELECT 1;

-- +goose StatementEnd
