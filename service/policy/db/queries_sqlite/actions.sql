----------------------------------------------------------------
-- ACTIONS (SQLite)
----------------------------------------------------------------

-- name: listActions :many
WITH counted AS (
    SELECT COUNT(id) AS total FROM actions
)
SELECT
    a.id,
    a.name,
    json_object(
        'labels', json_extract(a.metadata, '$.labels'),
        'created_at', a.created_at,
        'updated_at', a.updated_at
    ) as metadata,
    a.is_standard,
    counted.total
FROM actions a
CROSS JOIN counted
LIMIT @limit_
OFFSET @offset_;

-- name: getAction :one
SELECT
    id,
    name,
    is_standard,
    json_object(
        'labels', json_extract(metadata, '$.labels'),
        'created_at', created_at,
        'updated_at', updated_at
    ) AS metadata
FROM actions a
WHERE
  (sqlc.narg('id') IS NULL OR a.id = sqlc.narg('id'))
  AND (sqlc.narg('name') IS NULL OR a.name = sqlc.narg('name'));

-- name: getActionsByNames :many
-- Note: Uses json_each instead of unnest for array matching
SELECT
    id,
    name,
    is_standard,
    json_object(
        'labels', json_extract(metadata, '$.labels'),
        'created_at', created_at,
        'updated_at', updated_at
    ) AS metadata
FROM actions
WHERE LOWER(name) IN (SELECT LOWER(value) FROM json_each(@action_names));

-- name: createCustomAction :one
-- Note: ID generated in application layer before INSERT
INSERT INTO actions (id, name, metadata, is_standard)
VALUES (@id, @name, @metadata, 0)
RETURNING id;

-- name: updateCustomAction :execrows
UPDATE actions
SET
    name = COALESCE(sqlc.narg('name'), name),
    metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE id = @id
  AND is_standard = 0;

-- name: deleteCustomAction :execrows
DELETE FROM actions
WHERE id = @id
  AND is_standard = 0;
