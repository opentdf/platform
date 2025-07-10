---------------------------------------------------------------- 
-- KEY ACCESS SERVERS
----------------------------------------------------------------
-- name: listKeyAccessServerGrants :many
WITH listed AS (
    SELECT
        COUNT(*) OVER () AS total,
        kas.id AS kas_id,
        kas.uri AS kas_uri,
        kas.name AS kas_name,
        kas.public_key AS kas_public_key,
        JSON_STRIP_NULLS(JSON_BUILD_OBJECT(
            'labels', kas.metadata -> 'labels',
            'created_at', kas.created_at,
            'updated_at', kas.updated_at
        )) AS kas_metadata,
        JSON_AGG(DISTINCT JSONB_BUILD_OBJECT(
            'id', attrkag.attribute_definition_id,
            'fqn', fqns_on_attr.fqn
        )) FILTER (WHERE attrkag.attribute_definition_id IS NOT NULL) AS attributes_grants,
        JSON_AGG(DISTINCT JSONB_BUILD_OBJECT(
            'id', valkag.attribute_value_id,
            'fqn', fqns_on_vals.fqn
        )) FILTER (WHERE valkag.attribute_value_id IS NOT NULL) AS values_grants,
        JSON_AGG(DISTINCT JSONB_BUILD_OBJECT(
            'id', nskag.namespace_id,
            'fqn', fqns_on_ns.fqn
        )) FILTER (WHERE nskag.namespace_id IS NOT NULL) AS namespace_grants
    FROM key_access_servers AS kas
    LEFT JOIN
        attribute_definition_key_access_grants AS attrkag
        ON kas.id = attrkag.key_access_server_id
    LEFT JOIN
        attribute_fqns AS fqns_on_attr
        ON attrkag.attribute_definition_id = fqns_on_attr.attribute_id
            AND fqns_on_attr.value_id IS NULL
    LEFT JOIN
        attribute_value_key_access_grants AS valkag
        ON kas.id = valkag.key_access_server_id
    LEFT JOIN 
        attribute_fqns AS fqns_on_vals
        ON valkag.attribute_value_id = fqns_on_vals.value_id
    LEFT JOIN
        attribute_namespace_key_access_grants AS nskag
        ON kas.id = nskag.key_access_server_id
    LEFT JOIN
        attribute_fqns AS fqns_on_ns
            ON nskag.namespace_id = fqns_on_ns.namespace_id
        AND fqns_on_ns.attribute_id IS NULL AND fqns_on_ns.value_id IS NULL
    WHERE (NULLIF(@kas_id, '') IS NULL OR kas.id = @kas_id::uuid) 
        AND (NULLIF(@kas_uri, '') IS NULL OR kas.uri = @kas_uri::varchar) 
        AND (NULLIF(@kas_name, '') IS NULL OR kas.name = @kas_name::varchar) 
    GROUP BY 
        kas.id
)
SELECT 
    listed.kas_id,
    listed.kas_uri,
    listed.kas_name,
    listed.kas_public_key,
    listed.kas_metadata,
    listed.attributes_grants,
    listed.values_grants,
    listed.namespace_grants,
    listed.total  
FROM listed
LIMIT @limit_ 
OFFSET @offset_; 

-- name: listKeyAccessServers :many
WITH counted AS (
    SELECT COUNT(kas.id) AS total
    FROM key_access_servers AS kas
)
SELECT kas.id,
    kas.uri,
    kas.public_key,
    kas.name AS kas_name,
    kas.source_type,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', kas.metadata -> 'labels', 'created_at', kas.created_at, 'updated_at', kas.updated_at)) AS metadata,
    kask_keys.keys,
    counted.total
FROM key_access_servers AS kas
CROSS JOIN counted
LEFT JOIN (
        SELECT
            kask.key_access_server_id,
            JSONB_AGG(
                DISTINCT JSONB_BUILD_OBJECT(
                    'kas_uri', kas.uri,
                    'kas_id', kas.id,
                    'public_key', JSONB_BUILD_OBJECT(
                         'algorithm', kask.key_algorithm::INTEGER,
                         'kid', kask.key_id,
                         'pem', CONVERT_FROM(DECODE(kask.public_key_ctx ->> 'pem', 'base64'), 'UTF8')
                    )
                )
            ) FILTER (WHERE kask.id IS NOT NULL) AS keys
        FROM key_access_server_keys kask
        INNER JOIN key_access_servers kas ON kask.key_access_server_id = kas.id
        GROUP BY kask.key_access_server_id
    ) kask_keys ON kas.id = kask_keys.key_access_server_id
LIMIT @limit_ 
OFFSET @offset_; 

-- name: getKeyAccessServer :one
SELECT 
    kas.id,
    kas.uri, 
    kas.public_key, 
    kas.name,
    kas.source_type,
    JSON_STRIP_NULLS(
        JSON_BUILD_OBJECT(
            'labels', metadata -> 'labels', 
            'created_at', created_at, 
            'updated_at', updated_at
        )
    ) AS metadata,
    kask_keys.keys
FROM key_access_servers AS kas
LEFT JOIN (
        SELECT
            kask.key_access_server_id,
            JSONB_AGG(
                DISTINCT JSONB_BUILD_OBJECT(
                    'kas_uri', kas.uri,
                    'kas_id', kas.id,
                    'public_key', JSONB_BUILD_OBJECT(
                         'algorithm', kask.key_algorithm::INTEGER,
                         'kid', kask.key_id,
                         'pem', CONVERT_FROM(DECODE(kask.public_key_ctx ->> 'pem', 'base64'), 'UTF8')
                    )
                )
            ) FILTER (WHERE kask.id IS NOT NULL) AS keys
        FROM key_access_server_keys kask
        INNER JOIN key_access_servers kas ON kask.key_access_server_id = kas.id
        GROUP BY kask.key_access_server_id
    ) kask_keys ON kas.id = kask_keys.key_access_server_id
WHERE (sqlc.narg('id')::uuid IS NULL OR kas.id = sqlc.narg('id')::uuid)
  AND (sqlc.narg('name')::text IS NULL OR kas.name = sqlc.narg('name')::text)
  AND (sqlc.narg('uri')::text IS NULL OR kas.uri = sqlc.narg('uri')::text);

-- name: createKeyAccessServer :one
INSERT INTO key_access_servers (uri, public_key, name, metadata, source_type)
VALUES ($1, $2, $3, $4, $5)
RETURNING id;

-- name: updateKeyAccessServer :execrows
UPDATE key_access_servers
SET
    uri = COALESCE(sqlc.narg('uri'), uri),
    public_key = COALESCE(sqlc.narg('public_key'), public_key),
    name = COALESCE(sqlc.narg('name'), name),
    metadata = COALESCE(sqlc.narg('metadata'), metadata),
    source_type = COALESCE(sqlc.narg('source_type'), source_type)
WHERE id = $1;

-- name: deleteKeyAccessServer :execrows
DELETE FROM key_access_servers WHERE id = $1;


-----------------------------------------------------------------
-- Key Access Server Keys
------------------------------------------------------------------
-- name: createKey :one
INSERT INTO key_access_server_keys
    (key_access_server_id, key_algorithm, key_id, key_mode, key_status, metadata, private_key_ctx, public_key_ctx, provider_config_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING id;

-- name: getKey :one
SELECT 
  kask.id,
  kask.key_id,
  kask.key_status,
  kask.key_mode,
  kask.key_algorithm,
  kask.private_key_ctx,
  kask.public_key_ctx,
  kask.provider_config_id,
  kask.key_access_server_id,
  kas.uri AS kas_uri,
  JSON_STRIP_NULLS(
    JSON_BUILD_OBJECT(
      'labels', kask.metadata -> 'labels',         
      'created_at', kask.created_at,               
      'updated_at', kask.updated_at                
    )
  ) AS metadata,
  pc.provider_name,
  pc.config AS pc_config,
  JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', pc.metadata -> 'labels', 'created_at', pc.created_at, 'updated_at', pc.updated_at)) AS pc_metadata
FROM key_access_server_keys AS kask
LEFT JOIN 
    provider_config as pc ON kask.provider_config_id = pc.id
INNER JOIN 
    key_access_servers AS kas ON kask.key_access_server_id = kas.id
WHERE (sqlc.narg('id')::uuid IS NULL OR kask.id = sqlc.narg('id')::uuid)
  AND (sqlc.narg('key_id')::text IS NULL OR kask.key_id = sqlc.narg('key_id')::text)
  AND (sqlc.narg('kas_id')::uuid IS NULL OR kask.key_access_server_id = sqlc.narg('kas_id')::uuid)
  AND (sqlc.narg('kas_uri')::text IS NULL OR kas.uri = sqlc.narg('kas_uri')::text)
  AND (sqlc.narg('kas_name')::text IS NULL OR kas.name = sqlc.narg('kas_name')::text);


-- name: updateKey :execrows
UPDATE key_access_server_keys
SET
    key_status = COALESCE(sqlc.narg('key_status'), key_status),
    metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE id = $1;

-- name: listKeys :many
WITH listed AS (
    SELECT
        kas.id AS kas_id,
        kas.uri AS kas_uri
    FROM key_access_servers AS kas
    WHERE (sqlc.narg('kas_id')::uuid IS NULL OR kas.id = sqlc.narg('kas_id')::uuid)
            AND (sqlc.narg('kas_name')::text IS NULL OR kas.name = sqlc.narg('kas_name')::text)
            AND (sqlc.narg('kas_uri')::text IS NULL OR kas.uri = sqlc.narg('kas_uri')::text)
)
SELECT 
  COUNT(*) OVER () AS total,
  kask.id,
  kask.key_id,
  kask.key_status,
  kask.key_mode,
  kask.key_algorithm,
  kask.private_key_ctx,
  kask.public_key_ctx,
  kask.provider_config_id,
  kask.key_access_server_id,
  listed.kas_uri AS kas_uri,
  JSON_STRIP_NULLS(
    JSON_BUILD_OBJECT(
      'labels', kask.metadata -> 'labels',         
      'created_at', kask.created_at,               
      'updated_at', kask.updated_at                
    )
  ) AS metadata,
  pc.provider_name,
  pc.config AS provider_config,
  JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', pc.metadata -> 'labels', 'created_at', pc.created_at, 'updated_at', pc.updated_at)) AS pc_metadata
FROM key_access_server_keys AS kask
INNER JOIN
    listed ON kask.key_access_server_id = listed.kas_id
LEFT JOIN 
    provider_config as pc ON kask.provider_config_id = pc.id
WHERE
    (sqlc.narg('key_algorithm')::integer IS NULL OR kask.key_algorithm = sqlc.narg('key_algorithm')::integer)
ORDER BY kask.created_at DESC
LIMIT @limit_ 
OFFSET @offset_;

-- name: deleteKey :execrows
DELETE FROM key_access_server_keys WHERE id = $1;


---------------------------------------------------------------- 
-- Default KAS Keys
----------------------------------------------------------------

-- name: getBaseKey :one
SELECT
    DISTINCT JSONB_BUILD_OBJECT(
       'kas_uri', kas.uri,
       'kas_id', kas.id,
       'public_key', JSONB_BUILD_OBJECT(
            'algorithm', kask.key_algorithm::INTEGER,
            'kid', kask.key_id,
            'pem', CONVERT_FROM(DECODE(kask.public_key_ctx ->> 'pem', 'base64'), 'UTF8')
       )
    ) AS base_keys
FROM base_keys bk
INNER JOIN key_access_server_keys kask ON bk.key_access_server_key_id = kask.id
INNER JOIN key_access_servers kas ON kask.key_access_server_id = kas.id;

-- name: setBaseKey :execrows
INSERT INTO base_keys (key_access_server_key_id)
VALUES ($1);

-- name: deleteAllBaseKeys :execrows
DELETE FROM base_keys;
