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

-- name: countResourceMappingGroups :one
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
FROM resource_mapping_groups
WHERE namespace_id = (SELECT id FROM target_namespace);

-- name: countResourceMappings :one
WITH target_namespace AS (
    SELECT COALESCE(
        sqlc.narg('namespace_id')::uuid,
        (
            SELECT namespace_id
            FROM attribute_fqns
            WHERE fqn = sqlc.narg('namespace_fqn')::text
              AND attribute_id IS NULL
              AND value_id IS NULL
        ),
        (
            SELECT namespace_id
            FROM resource_mapping_groups
            WHERE id = sqlc.narg('group_id')::uuid
        )
    ) AS id
)
SELECT COUNT(*)
FROM resource_mappings
WHERE namespace_id = (SELECT id FROM target_namespace);

-- name: countSubjectMappings :one
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
FROM subject_mappings
WHERE namespace_id IS NOT DISTINCT FROM (SELECT id FROM target_namespace);

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
WHERE namespace_id IS NOT DISTINCT FROM (SELECT id FROM target_namespace);

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

-- name: countObligationTriggersForAttributeDefinition :one
WITH target_namespace AS (
    SELECT COALESCE(
        (
            SELECT ad.namespace_id
            FROM attribute_definitions ad
            WHERE ad.id = @attribute_definition_id
        ),
        '00000000-0000-0000-0000-000000000000'::uuid
    )::uuid AS namespace_id
)
SELECT
    target_namespace.namespace_id,
    COUNT(ot.id) AS count
FROM target_namespace
LEFT JOIN attribute_definitions ad ON ad.namespace_id = target_namespace.namespace_id
LEFT JOIN attribute_values av ON av.attribute_definition_id = ad.id
LEFT JOIN obligation_triggers ot ON ot.attribute_value_id = av.id
GROUP BY target_namespace.namespace_id;

-- name: countObligationTriggersForAttributeValue :one
WITH target_namespace AS (
    SELECT COALESCE(
        (
            SELECT ad.namespace_id
            FROM attribute_values av
            JOIN attribute_definitions ad ON ad.id = av.attribute_definition_id
            LEFT JOIN attribute_fqns fqn ON fqn.value_id = av.id
            WHERE (sqlc.narg('attribute_value_id')::uuid IS NOT NULL AND av.id = sqlc.narg('attribute_value_id')::uuid)
               OR (sqlc.narg('attribute_value_fqn')::text IS NOT NULL AND fqn.fqn = sqlc.narg('attribute_value_fqn')::text)
        ),
        '00000000-0000-0000-0000-000000000000'::uuid
    )::uuid AS namespace_id
)
SELECT
    target_namespace.namespace_id,
    COUNT(ot.id) AS count
FROM target_namespace
LEFT JOIN attribute_definitions ad ON ad.namespace_id = target_namespace.namespace_id
LEFT JOIN attribute_values av ON av.attribute_definition_id = ad.id
LEFT JOIN obligation_triggers ot ON ot.attribute_value_id = av.id
GROUP BY target_namespace.namespace_id;
