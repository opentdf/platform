----------------------------------------------------------------
-- ACTIONS
----------------------------------------------------------------

-- name: listActions :many
WITH counted AS (
    SELECT COUNT(id) AS total FROM actions
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
    counted.total
FROM actions a
CROSS JOIN counted
ORDER BY a.created_at DESC
LIMIT @limit_ 
OFFSET @offset_;

-- name: getAction :one
SELECT 
    a.id,
    a.name,
    a.is_standard,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', a.metadata -> 'labels', 'created_at', a.created_at, 'updated_at', a.updated_at)) AS metadata
FROM actions a
WHERE 
  (sqlc.narg('id')::uuid IS NULL OR a.id = sqlc.narg('id')::uuid)
  AND (sqlc.narg('name')::text IS NULL OR a.name = sqlc.narg('name')::text);

-- name: createOrListActionsByName :many
WITH input_actions AS (
    SELECT unnest(sqlc.arg('action_names')::text[]) AS name
),
new_actions AS (
    INSERT INTO actions (name, is_standard)
    SELECT 
        input.name, 
        FALSE -- custom actions
    FROM input_actions input
    WHERE NOT EXISTS (
        SELECT 1 FROM actions a WHERE LOWER(a.name) = LOWER(input.name)
    )
    ON CONFLICT (name) DO NOTHING
    RETURNING id, name, is_standard, created_at
),
all_actions AS (
    -- Get existing actions that match input names
    SELECT a.id, a.name, a.is_standard, a.created_at, 
           TRUE AS pre_existing
    FROM actions a
    JOIN input_actions input ON LOWER(a.name) = LOWER(input.name)
    
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
INSERT INTO actions (name, metadata, is_standard)
VALUES ($1, $2, FALSE)
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
