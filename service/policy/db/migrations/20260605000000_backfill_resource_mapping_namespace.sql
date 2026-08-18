-- +goose Up
-- +goose StatementBegin

-- Backfill the owning namespace for existing grouped resource mappings created
-- before resource_mappings.namespace_id existed, so that namespace filtering
-- works on legacy data. A grouped mapping is owned by its group's namespace.
-- Ungrouped mappings have no group to derive ownership from and remain global
-- (namespace_id stays NULL). Idempotent: only fills rows that are still NULL.
UPDATE resource_mappings m
SET namespace_id = g.namespace_id
FROM resource_mapping_groups g
WHERE m.group_id = g.id
  AND m.namespace_id IS NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- No-op: a backfilled namespace_id cannot be reliably distinguished from one set
-- intentionally after this migration, so the backfill is not reverted. The
-- column itself is removed by the add-namespace migration's down step.
SELECT 1;

-- +goose StatementEnd
