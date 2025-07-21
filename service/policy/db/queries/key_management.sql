---------------------------------------------------------------- 
-- Provider Config
----------------------------------------------------------------

-- name: createProviderConfig :one
WITH inserted AS (
  INSERT INTO provider_config (provider_name, config, metadata)
  VALUES ($1, $2, $3)
  RETURNING *
)
SELECT 
  id,
  provider_name,
  config,
  JSON_STRIP_NULLS(
    JSON_BUILD_OBJECT(
      'labels', metadata -> 'labels',         
      'created_at', created_at,               
      'updated_at', updated_at                
    )
  ) AS metadata
FROM inserted;

-- name: getProviderConfig :one
SELECT 
    pc.id,
    pc.provider_name,
    pc.config,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', pc.metadata -> 'labels', 'created_at', pc.created_at, 'updated_at', pc.updated_at)) AS metadata
FROM provider_config AS pc
WHERE (sqlc.narg('id')::uuid IS NULL OR pc.id = sqlc.narg('id')::uuid)
  AND (sqlc.narg('name')::text IS NULL OR pc.provider_name = sqlc.narg('name')::text);


-- name: listProviderConfigs :many
WITH counted AS (
    SELECT COUNT(pc.id) AS total 
    FROM provider_config pc
)
SELECT 
    pc.id,
    pc.provider_name,
    pc.config,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', pc.metadata -> 'labels', 'created_at', pc.created_at, 'updated_at', pc.updated_at)) AS metadata,
    counted.total
FROM provider_config AS pc
CROSS JOIN counted
LIMIT @limit_ 
OFFSET @offset_;

-- name: updateProviderConfig :execrows
UPDATE provider_config
SET
    provider_name = COALESCE(sqlc.narg('provider_name'), provider_name),
    config = COALESCE(sqlc.narg('config'), config),
    metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE id = $1;

-- name: deleteProviderConfig :execrows
DELETE FROM provider_config 
WHERE id = $1;
