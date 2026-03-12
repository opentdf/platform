----------------------------------------------------------------
-- ACTIONS
----------------------------------------------------------------

-- name: listActions :many
WITH resolved_namespace AS (
    SELECT
        n.id,
        n.name,
        fqns.fqn
    FROM attribute_namespaces n
    LEFT JOIN attribute_fqns fqns ON fqns.namespace_id = n.id AND fqns.attribute_id IS NULL AND fqns.value_id IS NULL
    WHERE
        (sqlc.narg('namespace_id')::uuid IS NOT NULL AND n.id = sqlc.narg('namespace_id')::uuid)
        OR
        (sqlc.narg('namespace_fqn')::text IS NOT NULL AND fqns.fqn = sqlc.narg('namespace_fqn')::text)
    LIMIT 1
),
counted AS (
    SELECT COUNT(a.id) AS total
    FROM actions a
    JOIN resolved_namespace rn ON TRUE
    WHERE a.is_standard = TRUE OR a.namespace_id = rn.id OR a.namespace_id IS NULL
)
SELECT 
    a.id,
    a.name,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT(
        'labels', a.metadata -> 'labels', 
        'created_at', a.created_at, 
        'updated_at', a.updated_at
    )) as metadata,
    a.is_standard,
    CASE
        WHEN a.namespace_id IS NULL THEN JSON_BUILD_OBJECT(
            'id', rn.id,
            'name', rn.name,
            'fqn', rn.fqn
        )
        ELSE JSON_BUILD_OBJECT(
            'id', n.id,
            'name', n.name,
            'fqn', ns_fqns.fqn
        )
    END AS namespace,
    counted.total
FROM actions a
JOIN resolved_namespace rn ON TRUE
LEFT JOIN attribute_namespaces n ON a.namespace_id = n.id
LEFT JOIN attribute_fqns ns_fqns ON ns_fqns.namespace_id = n.id AND ns_fqns.attribute_id IS NULL AND ns_fqns.value_id IS NULL
CROSS JOIN counted
WHERE a.is_standard = TRUE OR a.namespace_id = rn.id OR a.namespace_id IS NULL
ORDER BY a.created_at DESC
LIMIT @limit_ 
OFFSET @offset_;

-- name: getAction :one
WITH resolved_namespace AS (
    SELECT
        n.id,
        n.name,
        fqns.fqn
    FROM attribute_namespaces n
    LEFT JOIN attribute_fqns fqns ON fqns.namespace_id = n.id AND fqns.attribute_id IS NULL AND fqns.value_id IS NULL
    WHERE
        (sqlc.narg('namespace_id')::uuid IS NOT NULL AND n.id = sqlc.narg('namespace_id')::uuid)
        OR
        (sqlc.narg('namespace_fqn')::text IS NOT NULL AND fqns.fqn = sqlc.narg('namespace_fqn')::text)
    LIMIT 1
)
SELECT 
    a.id,
    a.name,
    a.is_standard,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', a.metadata -> 'labels', 'created_at', a.created_at, 'updated_at', a.updated_at)) AS metadata,
    CASE
        WHEN a.namespace_id IS NULL AND sqlc.narg('name')::text IS NOT NULL THEN JSON_BUILD_OBJECT(
            'id', rn.id,
            'name', rn.name,
            'fqn', rn.fqn
        )
        WHEN a.namespace_id IS NULL THEN NULL
        ELSE JSON_BUILD_OBJECT(
            'id', n.id,
            'name', n.name,
            'fqn', ns_fqns.fqn
        )
    END AS namespace
FROM actions a
LEFT JOIN attribute_namespaces n ON a.namespace_id = n.id
LEFT JOIN attribute_fqns ns_fqns ON ns_fqns.namespace_id = n.id AND ns_fqns.attribute_id IS NULL AND ns_fqns.value_id IS NULL
LEFT JOIN resolved_namespace rn ON TRUE
WHERE 
  (
    (sqlc.narg('id')::uuid IS NOT NULL AND a.id = sqlc.narg('id')::uuid)
    OR
    (
        sqlc.narg('name')::text IS NOT NULL
        AND a.name = sqlc.narg('name')::text
        AND rn.id IS NOT NULL
        AND (a.namespace_id = rn.id OR a.namespace_id IS NULL)
    )
  )
ORDER BY
    CASE
        WHEN sqlc.narg('name')::text IS NULL THEN 0
        WHEN a.namespace_id = rn.id THEN 0
        WHEN a.is_standard = TRUE THEN 1
        ELSE 2
    END,
    a.created_at DESC
LIMIT 1;

-- name: createOrListActionsByName :many
WITH input_actions AS (
    SELECT unnest(sqlc.arg('action_names')::text[]) AS name
),
new_actions AS (
    INSERT INTO actions (name, is_standard, namespace_id)
    SELECT 
        input.name, 
        FALSE, -- custom actions
        NULL
    FROM input_actions input
    WHERE NOT EXISTS (
        SELECT 1 FROM actions a WHERE LOWER(a.name) = LOWER(input.name) AND a.namespace_id IS NULL
    )
    ON CONFLICT (name) WHERE namespace_id IS NULL DO NOTHING
    RETURNING id, name, is_standard, created_at
),
all_actions AS (
    -- Get existing actions that match input names
    SELECT a.id, a.name, a.is_standard, a.created_at, 
           TRUE AS pre_existing
    FROM actions a
    JOIN input_actions input ON LOWER(a.name) = LOWER(input.name)
    WHERE a.namespace_id IS NULL
    
    UNION ALL
    
    -- Include newly created actions
    SELECT id, name, is_standard, created_at,
           FALSE AS pre_existing
    FROM new_actions
)
SELECT 
    id,
    name,
    is_standard,
    created_at,
    pre_existing
FROM all_actions
ORDER BY name;

-- name: createCustomAction :one
INSERT INTO actions (name, metadata, is_standard, namespace_id)
SELECT
    @name,
    @metadata,
    FALSE,
    COALESCE(sqlc.narg('namespace_id')::uuid, fqns.namespace_id)
FROM (
    SELECT
        sqlc.narg('namespace_id')::uuid as direct_namespace_id
) direct
LEFT JOIN attribute_fqns fqns ON fqns.fqn = sqlc.narg('namespace_fqn')::text AND sqlc.narg('namespace_id')::text IS NULL
WHERE
    (sqlc.narg('namespace_id')::text IS NOT NULL AND direct.direct_namespace_id IS NOT NULL)
    OR
    (sqlc.narg('namespace_fqn')::text IS NOT NULL AND fqns.namespace_id IS NOT NULL)
RETURNING id;

-- name: updateCustomAction :execrows
UPDATE actions
SET
    name = COALESCE(sqlc.narg('name'), name),
    metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE id = $1
  AND is_standard = FALSE;

-- name: deleteCustomAction :execrows
DELETE FROM actions
WHERE id = $1
  AND is_standard = FALSE;
