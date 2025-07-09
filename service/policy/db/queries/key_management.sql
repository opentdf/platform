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

-- name: listKeyMappings :many
WITH filtered_keys AS (
    -- Get all keys matching the filter criteria
    SELECT
        kask.created_at,
        kask.id AS id,
        kask.key_id AS kid,
        kas.id AS kas_id,
        kas.uri AS kas_uri
    FROM key_access_server_keys kask
    INNER JOIN key_access_servers kas ON kask.key_access_server_id = kas.id
    WHERE (
        -- Case 1: Filter by system key ID if provided
        (sqlc.narg('id')::uuid IS NOT NULL AND kask.id = sqlc.narg('id')::uuid)
        -- Case 2: Filter by KID + at least one KAS identifier
        OR (
            sqlc.narg('kid')::text IS NOT NULL 
            AND kask.key_id = sqlc.narg('kid')::text
            AND (
                (sqlc.narg('kas_id')::uuid IS NOT NULL AND kas.id = sqlc.narg('kas_id')::uuid)
                OR (sqlc.narg('kas_name')::text IS NOT NULL AND kas.name = sqlc.narg('kas_name')::text)
                OR (sqlc.narg('kas_uri')::text IS NOT NULL AND kas.uri = sqlc.narg('kas_uri')::text)
            )
        )
        -- Case 3: Return all keys if no filters are provided
        OR (
            sqlc.narg('id')::uuid IS NULL 
            AND sqlc.narg('kid')::text IS NULL
        )
    )
),
keys_with_mappings AS (
    SELECT id
    FROM filtered_keys fk
    WHERE EXISTS (
        SELECT 1 FROM attribute_namespace_public_key_map anpm WHERE anpm.key_access_server_key_id = fk.id
    ) OR EXISTS (
        SELECT 1 FROM attribute_definition_public_key_map adpm WHERE adpm.key_access_server_key_id = fk.id
    ) OR EXISTS (
        SELECT 1 FROM attribute_value_public_key_map avpm WHERE avpm.key_access_server_key_id = fk.id
    )
),
keys_with_mappings_count AS (
    SELECT COUNT(*) AS total FROM keys_with_mappings
),
namespace_mappings AS (
    -- Get namespace mappings for each key
    SELECT 
        fk.id as key_id,
        JSON_AGG(
            JSON_BUILD_OBJECT(
                'id', anpm.namespace_id,
                'fqn', fqns.fqn
            )
        ) FILTER (WHERE anpm.namespace_id IS NOT NULL) AS namespace_mappings
    FROM filtered_keys fk
    INNER JOIN attribute_namespace_public_key_map anpm ON fk.id = anpm.key_access_server_key_id
    INNER JOIN attribute_fqns fqns ON anpm.namespace_id = fqns.namespace_id AND fqns.attribute_id IS NULL AND fqns.value_id IS NULL
    GROUP BY fk.id
),
definition_mappings AS (
    -- Get attribute definition mappings for each key
    SELECT 
        fk.id as key_id,
        JSON_AGG(
            JSON_BUILD_OBJECT(
                'id', adpm.definition_id,
                'fqn', fqns.fqn
            )
        ) FILTER (WHERE adpm.definition_id IS NOT NULL) AS definition_mappings
    FROM filtered_keys fk
    INNER JOIN attribute_definition_public_key_map adpm ON fk.id = adpm.key_access_server_key_id
    INNER JOIN attribute_fqns fqns ON adpm.definition_id = fqns.attribute_id AND fqns.value_id IS NULL
    GROUP BY fk.id
),
value_mappings AS (
    -- Get attribute value mappings for each key
    SELECT 
        fk.id as key_id,
        JSON_AGG(
            JSON_BUILD_OBJECT(
                'id', avpm.value_id,
                'fqn', fqns.fqn
            )
        ) FILTER (WHERE avpm.value_id IS NOT NULL) AS value_mappings
    FROM filtered_keys fk
    INNER JOIN attribute_value_public_key_map avpm ON fk.id = avpm.key_access_server_key_id
    INNER JOIN attribute_fqns fqns ON avpm.value_id = fqns.value_id
    GROUP BY fk.id
)
SELECT 
    fk.kid,
    fk.kas_uri,
    COALESCE(nm.namespace_mappings, '[]'::json) AS namespace_mappings,
    COALESCE(dm.definition_mappings, '[]'::json) AS attribute_mappings,
    COALESCE(vm.value_mappings, '[]'::json) AS value_mappings,
    kwmc.total
FROM filtered_keys fk
INNER JOIN keys_with_mappings kwm ON fk.id = kwm.id
CROSS JOIN keys_with_mappings_count kwmc
LEFT JOIN namespace_mappings nm ON fk.id = nm.key_id
LEFT JOIN definition_mappings dm ON fk.id = dm.key_id
LEFT JOIN value_mappings vm ON fk.id = vm.key_id
ORDER BY fk.created_at
LIMIT @limit_ 
OFFSET @offset_;
