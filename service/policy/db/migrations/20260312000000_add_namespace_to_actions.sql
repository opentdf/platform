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

-- Roll back namespace-scoped actions to global actions by canonicalizing action IDs
-- by action name, remapping references, and deleting duplicate action rows.
-- Canonical action selection prefers legacy/global actions (namespace_id IS NULL),
-- then earliest created_at, then smallest id for deterministic behavior.
--
-- Operator note (optional, run manually outside migration):
-- Preview action-id remaps this Down migration will apply:
--
-- WITH canonical AS (
--   SELECT
--     id,
--     name,
--     FIRST_VALUE(id) OVER (
--       PARTITION BY name
--       ORDER BY (namespace_id IS NULL) DESC, created_at ASC, id ASC
--     ) AS canonical_id
--   FROM actions
-- )
-- SELECT name, id AS old_action_id, canonical_id AS new_action_id
-- FROM canonical
-- WHERE id <> canonical_id
-- ORDER BY name, old_action_id;
--
-- Preview impacted row counts by table:
--   SELECT COUNT(*) FROM subject_mapping_actions sma JOIN actions a ON a.id = sma.action_id WHERE a.namespace_id IS NOT NULL;
--   SELECT COUNT(*) FROM registered_resource_action_attribute_values rr JOIN actions a ON a.id = rr.action_id WHERE a.namespace_id IS NOT NULL;
--   SELECT COUNT(*) FROM obligation_triggers ot JOIN actions a ON a.id = ot.action_id WHERE a.namespace_id IS NOT NULL;
--
-- Post-down verification queries:
--   SELECT name, COUNT(*) FROM actions GROUP BY name HAVING COUNT(*) > 1;
--   SELECT COUNT(*) FROM subject_mapping_actions sma LEFT JOIN actions a ON a.id = sma.action_id WHERE a.id IS NULL;
--   SELECT COUNT(*) FROM registered_resource_action_attribute_values rr LEFT JOIN actions a ON a.id = rr.action_id WHERE a.id IS NULL;
--   SELECT COUNT(*) FROM obligation_triggers ot LEFT JOIN actions a ON a.id = ot.action_id WHERE a.id IS NULL;

CREATE TEMP TABLE action_id_remap AS
WITH canonical AS (
    SELECT
        id,
        name,
        FIRST_VALUE(id) OVER (
            PARTITION BY name
            ORDER BY (namespace_id IS NULL) DESC, created_at ASC, id ASC
        ) AS canonical_id
    FROM actions
)
SELECT id AS old_action_id, canonical_id AS new_action_id
FROM canonical
WHERE id <> canonical_id;

-- subject_mapping_actions references actions(id) and has PK(subject_mapping_id, action_id).
-- Rebuild table contents in deduplicated form after remapping action ids.
CREATE TEMP TABLE subject_mapping_actions_dedup AS
SELECT
    sma.subject_mapping_id,
    COALESCE(r.new_action_id, sma.action_id) AS action_id,
    MIN(sma.created_at) AS created_at
FROM subject_mapping_actions sma
LEFT JOIN action_id_remap r ON r.old_action_id = sma.action_id
GROUP BY sma.subject_mapping_id, COALESCE(r.new_action_id, sma.action_id);

DELETE FROM subject_mapping_actions;

INSERT INTO subject_mapping_actions (subject_mapping_id, action_id, created_at)
SELECT subject_mapping_id, action_id, created_at
FROM subject_mapping_actions_dedup;

-- registered_resource_action_attribute_values references actions(id) and has
-- UNIQUE(registered_resource_value_id, action_id, attribute_value_id).
CREATE TEMP TABLE rr_aav_dedup AS
SELECT DISTINCT ON (
    rr.registered_resource_value_id,
    COALESCE(r.new_action_id, rr.action_id),
    rr.attribute_value_id
)
    rr.id,
    rr.registered_resource_value_id,
    COALESCE(r.new_action_id, rr.action_id) AS action_id,
    rr.attribute_value_id,
    rr.created_at,
    rr.updated_at
FROM registered_resource_action_attribute_values rr
LEFT JOIN action_id_remap r ON r.old_action_id = rr.action_id
ORDER BY rr.registered_resource_value_id, COALESCE(r.new_action_id, rr.action_id), rr.attribute_value_id, rr.id;

DELETE FROM registered_resource_action_attribute_values;

INSERT INTO registered_resource_action_attribute_values (
    id,
    registered_resource_value_id,
    action_id,
    attribute_value_id,
    created_at,
    updated_at
)
SELECT
    id,
    registered_resource_value_id,
    action_id,
    attribute_value_id,
    created_at,
    updated_at
FROM rr_aav_dedup;

-- obligation_triggers references actions(id) and has client-aware uniqueness.
CREATE TEMP TABLE obligation_triggers_dedup AS
SELECT DISTINCT ON (
    ot.obligation_value_id,
    COALESCE(r.new_action_id, ot.action_id),
    ot.attribute_value_id,
    ot.client_id
)
    ot.id,
    ot.obligation_value_id,
    COALESCE(r.new_action_id, ot.action_id) AS action_id,
    ot.attribute_value_id,
    ot.client_id,
    ot.metadata,
    ot.created_at,
    ot.updated_at
FROM obligation_triggers ot
LEFT JOIN action_id_remap r ON r.old_action_id = ot.action_id
ORDER BY ot.obligation_value_id, COALESCE(r.new_action_id, ot.action_id), ot.attribute_value_id, ot.client_id, ot.id;

DELETE FROM obligation_triggers;

INSERT INTO obligation_triggers (
    id,
    obligation_value_id,
    action_id,
    attribute_value_id,
    client_id,
    metadata,
    created_at,
    updated_at
)
SELECT
    id,
    obligation_value_id,
    action_id,
    attribute_value_id,
    client_id,
    metadata,
    created_at,
    updated_at
FROM obligation_triggers_dedup;

-- Remove duplicate actions after references are remapped.
DELETE FROM actions a
USING action_id_remap r
WHERE a.id = r.old_action_id;

DROP INDEX IF EXISTS idx_actions_namespace_id;
DROP INDEX IF EXISTS actions_name_unique;
DROP INDEX IF EXISTS actions_namespace_name_unique;

ALTER TABLE actions ADD CONSTRAINT actions_name_unique UNIQUE (name);

ALTER TABLE actions DROP COLUMN IF EXISTS namespace_id;

-- +goose StatementEnd
