---------------------------------------------------------------- 
-- Provider Config
----------------------------------------------------------------

-- name: createProviderConfig :one
WITH inserted AS (
  INSERT INTO provider_config (provider_name, manager, config, metadata)
  VALUES ($1, $2, $3, $4)
  RETURNING *
)
SELECT 
  id,
  provider_name,
  manager,
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
WITH params AS (
    SELECT
        sqlc.narg('id')::uuid as id,
        sqlc.narg('name')::text as name,
        sqlc.narg('manager')::text as manager
)
SELECT 
    pc.id,
    pc.provider_name,
    pc.manager,
    pc.config,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', pc.metadata -> 'labels', 'created_at', pc.created_at, 'updated_at', pc.updated_at)) AS metadata
FROM provider_config AS pc
CROSS JOIN params
WHERE (params.id IS NULL OR pc.id = params.id)
  AND (params.name IS NULL OR pc.provider_name = params.name)
  AND (params.manager IS NULL OR pc.manager = params.manager);


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
    manager = COALESCE(sqlc.narg('manager'), manager),
    config = COALESCE(sqlc.narg('config'), config),
    metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE id = $1;

-- name: deleteProviderConfig :execrows
DELETE FROM provider_config 
WHERE id = $1;
