----------------------------------------------------------------
-- Provider Config (SQLite)
----------------------------------------------------------------

-- name: createProviderConfig :one
-- Note: ID generated in application layer before INSERT
INSERT INTO provider_config (id, provider_name, manager, config, metadata)
VALUES (@id, @provider_name, @manager, @config, @metadata)
RETURNING id;

-- name: getProviderConfigFull :one
SELECT
    pc.id,
    pc.provider_name,
    pc.manager,
    pc.config,
    json_object(
        'labels', json_extract(pc.metadata, '$.labels'),
        'created_at', pc.created_at,
        'updated_at', pc.updated_at
    ) AS metadata
FROM provider_config AS pc
WHERE (sqlc.narg('id') IS NULL OR pc.id = sqlc.narg('id'))
  AND (sqlc.narg('name') IS NULL OR pc.provider_name = sqlc.narg('name'))
  AND (sqlc.narg('manager') IS NULL OR pc.manager = sqlc.narg('manager'));

-- name: listProviderConfigs :many
WITH counted AS (
    SELECT COUNT(pc.id) AS total
    FROM provider_config pc
)
SELECT
    pc.id,
    pc.provider_name,
    pc.manager,
    pc.config,
    json_object(
        'labels', json_extract(pc.metadata, '$.labels'),
        'created_at', pc.created_at,
        'updated_at', pc.updated_at
    ) AS metadata,
    counted.total
FROM provider_config AS pc
CROSS JOIN counted
LIMIT @limit_
OFFSET @offset_;

-- name: updateProviderConfig :execrows
UPDATE provider_config
SET
    provider_name = COALESCE(sqlc.narg('provider_name'), provider_name),
    manager = COALESCE(sqlc.narg('manager'), manager),
    config = COALESCE(sqlc.narg('config'), config),
    metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE id = @id;

-- name: deleteProviderConfig :execrows
DELETE FROM provider_config
WHERE id = @id;
