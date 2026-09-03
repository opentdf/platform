-- Internal count queries used to enforce configured policy object limits.
-- These intentionally return only counts instead of hydrating list responses.

-- name: countAttributeDefinitions :one
SELECT COUNT(*)
FROM attribute_definitions
WHERE namespace_id = @namespace_id;

-- name: countAttributeValues :one
SELECT COUNT(*)
FROM attribute_values
WHERE attribute_definition_id = @attribute_definition_id;

-- name: getResourceMappingGroupCount :one
WITH target_namespace AS (
    SELECT COALESCE(
        sqlc.narg('namespace_id')::uuid,
        (
            SELECT namespace_id
            FROM attribute_fqns
            WHERE fqn = sqlc.narg('namespace_fqn')::text
              AND attribute_id IS NULL
              AND value_id IS NULL
        )
    ) AS id
)
SELECT
    target_namespace.id::text AS namespace_id,
    COUNT(resource_mapping_groups.id) AS object_count
FROM target_namespace
LEFT JOIN resource_mapping_groups
    ON resource_mapping_groups.namespace_id = target_namespace.id
WHERE target_namespace.id IS NOT NULL
GROUP BY target_namespace.id;

-- name: countResourceMappings :one
SELECT COUNT(*)
FROM resource_mappings
WHERE attribute_value_id = @attribute_value_id;

-- name: countSubjectMappings :one
SELECT COUNT(*)
FROM subject_mappings
WHERE attribute_value_id = @attribute_value_id;

-- name: countSubjectConditionSets :one
WITH target_namespace AS (
    SELECT COALESCE(
        sqlc.narg('namespace_id')::uuid,
        (
            SELECT namespace_id
            FROM attribute_fqns
            WHERE fqn = sqlc.narg('namespace_fqn')::text
              AND attribute_id IS NULL
              AND value_id IS NULL
        )
    ) AS id
)
SELECT COUNT(*)
FROM subject_condition_set
WHERE namespace_id IS NOT DISTINCT FROM (SELECT id FROM target_namespace)
HAVING (SELECT id FROM target_namespace) IS NOT NULL
    OR (sqlc.narg('namespace_id')::uuid IS NULL AND sqlc.narg('namespace_fqn')::text IS NULL);

-- name: countObligationDefinitions :one
WITH target_namespace AS (
    SELECT COALESCE(
        sqlc.narg('namespace_id')::uuid,
        (
            SELECT namespace_id
            FROM attribute_fqns
            WHERE fqn = sqlc.narg('namespace_fqn')::text
              AND attribute_id IS NULL
              AND value_id IS NULL
        )
    ) AS id
)
SELECT COUNT(*)
FROM obligation_definitions
WHERE namespace_id = (SELECT id FROM target_namespace);

-- name: countObligationValues :one
WITH target_obligation AS (
    SELECT od.id
    FROM obligation_definitions od
    LEFT JOIN attribute_fqns fqn
        ON fqn.namespace_id = od.namespace_id
       AND fqn.attribute_id IS NULL
       AND fqn.value_id IS NULL
    WHERE (sqlc.narg('obligation_id')::uuid IS NOT NULL AND od.id = sqlc.narg('obligation_id')::uuid)
       OR (
            sqlc.narg('namespace_fqn')::text IS NOT NULL
            AND sqlc.narg('obligation_name')::text IS NOT NULL
            AND fqn.fqn = sqlc.narg('namespace_fqn')::text
            AND od.name = sqlc.narg('obligation_name')::text
       )
)
SELECT COUNT(*)
FROM obligation_values_standard
WHERE obligation_definition_id = (SELECT id FROM target_obligation);

-- name: countObligationTriggersForAttributeValue :one
WITH target_attribute_value AS (
    SELECT COALESCE(
        sqlc.narg('attribute_value_id')::uuid,
        (SELECT value_id FROM attribute_fqns WHERE fqn = sqlc.narg('attribute_value_fqn')::text),
        '00000000-0000-0000-0000-000000000000'::uuid
    ) AS id
)
SELECT COUNT(*)
FROM obligation_triggers
WHERE attribute_value_id = (SELECT id FROM target_attribute_value)
  AND (
      sqlc.narg('excluded_obligation_value_id')::uuid IS NULL
      OR obligation_value_id != sqlc.narg('excluded_obligation_value_id')::uuid
  );

-- name: countActions :one
WITH target_namespace AS (
    SELECT COALESCE(
        sqlc.narg('namespace_id')::uuid,
        (
            SELECT namespace_id
            FROM attribute_fqns
            WHERE fqn = sqlc.narg('namespace_fqn')::text
              AND attribute_id IS NULL
              AND value_id IS NULL
        )
    ) AS id
)
SELECT COUNT(*)
FROM actions
WHERE namespace_id IS NOT DISTINCT FROM (SELECT id FROM target_namespace)
HAVING (SELECT id FROM target_namespace) IS NOT NULL
    OR (sqlc.narg('namespace_id')::uuid IS NULL AND sqlc.narg('namespace_fqn')::text IS NULL);

-- name: countActionsWithMissingNames :one
WITH target_namespace AS (
    SELECT COALESCE(
        sqlc.narg('namespace_id')::uuid,
        (
            SELECT namespace_id
            FROM attribute_fqns
            WHERE fqn = sqlc.narg('namespace_fqn')::text
              AND attribute_id IS NULL
              AND value_id IS NULL
        )
    ) AS id
),
requested_actions AS (
    SELECT DISTINCT LOWER(name) AS name
    FROM UNNEST(@action_names::text[]) AS name
    WHERE name <> ''
)
SELECT
    (
        SELECT COUNT(*)
        FROM actions
        WHERE namespace_id IS NOT DISTINCT FROM (SELECT id FROM target_namespace)
    ) AS current_count,
    (
        SELECT COUNT(*)
        FROM requested_actions requested
        WHERE NOT EXISTS (
            SELECT 1
            FROM actions existing
            WHERE existing.namespace_id IS NOT DISTINCT FROM (SELECT id FROM target_namespace)
              AND LOWER(existing.name) = requested.name
        )
    ) AS missing_count
FROM target_namespace
WHERE target_namespace.id IS NOT NULL
   OR (sqlc.narg('namespace_id')::uuid IS NULL AND sqlc.narg('namespace_fqn')::text IS NULL);

-- name: getAttributeDefinitionNamespaceID :one
SELECT namespace_id
FROM attribute_definitions
WHERE id = @attribute_definition_id;

-- name: getAttributeValueNamespaceID :one
SELECT definitions.namespace_id
FROM attribute_values values
JOIN attribute_definitions definitions ON definitions.id = values.attribute_definition_id
LEFT JOIN attribute_fqns fqns ON fqns.value_id = values.id
WHERE (sqlc.narg('attribute_value_id')::uuid IS NOT NULL AND values.id = sqlc.narg('attribute_value_id')::uuid)
   OR (sqlc.narg('attribute_value_fqn')::text IS NOT NULL AND fqns.fqn = sqlc.narg('attribute_value_fqn')::text)
LIMIT 1;
