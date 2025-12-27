---------------------------------------------------------------- 
-- KEY ACCESS SERVERS
----------------------------------------------------------------
-- name: listKeyAccessServerGrants :many
WITH params AS (
    SELECT
        sqlc.narg('kas_id')::uuid as kas_id,
        sqlc.narg('kas_uri')::text as kas_uri,
        sqlc.narg('kas_name')::text as kas_name
),
listed AS (
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
    CROSS JOIN params
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
    WHERE (params.kas_id IS NULL OR kas.id = params.kas_id) 
        AND (params.kas_uri IS NULL OR kas.uri = params.kas_uri) 
        AND (params.kas_name IS NULL OR kas.name = params.kas_name) 
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
WITH params AS (
    SELECT
        sqlc.narg('id')::uuid as id,
        sqlc.narg('name')::text as name,
        sqlc.narg('uri')::text as uri
)
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
CROSS JOIN params
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
WHERE (params.id IS NULL OR kas.id = params.id)
  AND (params.name IS NULL OR kas.name = params.name)
  AND (params.uri IS NULL OR kas.uri = params.uri);

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
    (key_access_server_id, key_algorithm, key_id, key_mode, key_status, metadata, private_key_ctx, public_key_ctx, provider_config_id, legacy)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING id;

-- name: getKey :one
WITH params AS (
    SELECT
        sqlc.narg('id')::uuid as id,
        sqlc.narg('key_id')::text as key_id,
        sqlc.narg('kas_id')::uuid as kas_id,
        sqlc.narg('kas_uri')::text as kas_uri,
        sqlc.narg('kas_name')::text as kas_name
)
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
  pc.manager AS pc_manager,
  pc.provider_name,
  pc.config AS pc_config,
  JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', pc.metadata -> 'labels', 'created_at', pc.created_at, 'updated_at', pc.updated_at)) AS pc_metadata,
  kask.legacy
FROM key_access_server_keys AS kask
CROSS JOIN params
LEFT JOIN 
    provider_config as pc ON kask.provider_config_id = pc.id
INNER JOIN 
    key_access_servers AS kas ON kask.key_access_server_id = kas.id
WHERE (params.id IS NULL OR kask.id = params.id)
  AND (params.key_id IS NULL OR kask.key_id = params.key_id)
  AND (params.kas_id IS NULL OR kask.key_access_server_id = params.kas_id)
  AND (params.kas_uri IS NULL OR kas.uri = params.kas_uri)
  AND (params.kas_name IS NULL OR kas.name = params.kas_name);

-- name: listKeyMappings :many
WITH params AS (
    SELECT
        sqlc.narg('id')::uuid as id,
        sqlc.narg('kid')::text as kid,
        sqlc.narg('kas_id')::uuid as kas_id,
        sqlc.narg('kas_name')::text as kas_name,
        sqlc.narg('kas_uri')::text as kas_uri
),
filtered_keys AS (
    -- Get all keys matching the filter criteria
    SELECT
        kask.created_at,
        kask.id AS id,
        kask.key_id AS kid,
        kas.id AS kas_id,
        kas.uri AS kas_uri
    FROM key_access_server_keys kask
    CROSS JOIN params
    INNER JOIN key_access_servers kas ON kask.key_access_server_id = kas.id
    WHERE (
        -- Case 1: Filter by system key ID if provided
        (params.id IS NOT NULL AND kask.id = params.id)
        -- Case 2: Filter by KID + at least one KAS identifier
        OR (
            params.kid IS NOT NULL 
            AND kask.key_id = params.kid
            AND (
                (params.kas_id IS NOT NULL AND kas.id = params.kas_id)
                OR (params.kas_name IS NOT NULL AND kas.name = params.kas_name)
                OR (params.kas_uri IS NOT NULL AND kas.uri = params.kas_uri)
            )
        )
        -- Case 3: Return all keys if no filters are provided
        OR (
            params.id IS NULL 
            AND params.kid IS NULL
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

-- name: updateKey :execrows
UPDATE key_access_server_keys
SET
    key_status = COALESCE(sqlc.narg('key_status'), key_status),
    metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE id = $1;

-- name: listKeys :many
WITH params AS (
    SELECT
        sqlc.narg('kas_id')::uuid as kas_id,
        sqlc.narg('kas_name')::text as kas_name,
        sqlc.narg('kas_uri')::text as kas_uri,
        sqlc.narg('key_algorithm')::integer as key_algorithm,
        sqlc.narg('legacy')::boolean as legacy
),
listed AS (
    SELECT
        kas.id AS kas_id,
        kas.uri AS kas_uri
    FROM key_access_servers AS kas
    CROSS JOIN params
    WHERE (params.kas_id IS NULL OR kas.id = params.kas_id)
            AND (params.kas_name IS NULL OR kas.name = params.kas_name)
            AND (params.kas_uri IS NULL OR kas.uri = params.kas_uri)
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
  JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', pc.metadata -> 'labels', 'created_at', pc.created_at, 'updated_at', pc.updated_at)) AS pc_metadata,
  kask.legacy
FROM key_access_server_keys AS kask
CROSS JOIN params
INNER JOIN
    listed ON kask.key_access_server_id = listed.kas_id
LEFT JOIN 
    provider_config as pc ON kask.provider_config_id = pc.id
WHERE
    (params.key_algorithm IS NULL OR kask.key_algorithm = params.key_algorithm)
    AND (params.legacy IS NULL OR kask.legacy = params.legacy)
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
