----------------------------------------------------------------
-- KEY ACCESS SERVERS (SQLite)
----------------------------------------------------------------

-- name: listKeyAccessServerGrants :many
WITH listed AS (
    SELECT
        COUNT(*) OVER () AS total,
        kas.id AS kas_id,
        kas.uri AS kas_uri,
        kas.name AS kas_name,
        kas.public_key AS kas_public_key,
        json_object(
            'labels', json_extract(kas.metadata, '$.labels'),
            'created_at', kas.created_at,
            'updated_at', kas.updated_at
        ) AS kas_metadata,
        -- Attribute grants as subquery
        (
            SELECT json_group_array(json_object(
                'id', attrkag.attribute_definition_id,
                'fqn', fqns_on_attr.fqn
            ))
            FROM attribute_definition_key_access_grants attrkag
            LEFT JOIN attribute_fqns fqns_on_attr ON attrkag.attribute_definition_id = fqns_on_attr.attribute_id AND fqns_on_attr.value_id IS NULL
            WHERE attrkag.key_access_server_id = kas.id
        ) AS attributes_grants,
        -- Value grants as subquery
        (
            SELECT json_group_array(json_object(
                'id', valkag.attribute_value_id,
                'fqn', fqns_on_vals.fqn
            ))
            FROM attribute_value_key_access_grants valkag
            LEFT JOIN attribute_fqns fqns_on_vals ON valkag.attribute_value_id = fqns_on_vals.value_id
            WHERE valkag.key_access_server_id = kas.id
        ) AS values_grants,
        -- Namespace grants as subquery
        (
            SELECT json_group_array(json_object(
                'id', nskag.namespace_id,
                'fqn', fqns_on_ns.fqn
            ))
            FROM attribute_namespace_key_access_grants nskag
            LEFT JOIN attribute_fqns fqns_on_ns ON nskag.namespace_id = fqns_on_ns.namespace_id AND fqns_on_ns.attribute_id IS NULL AND fqns_on_ns.value_id IS NULL
            WHERE nskag.key_access_server_id = kas.id
        ) AS namespace_grants
    FROM key_access_servers AS kas
    WHERE (NULLIF(@kas_id, '') IS NULL OR kas.id = @kas_id)
        AND (NULLIF(@kas_uri, '') IS NULL OR kas.uri = @kas_uri)
        AND (NULLIF(@kas_name, '') IS NULL OR kas.name = @kas_name)
    GROUP BY kas.id
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
    json_object(
        'labels', json_extract(kas.metadata, '$.labels'),
        'created_at', kas.created_at,
        'updated_at', kas.updated_at
    ) AS metadata,
    -- Keys subquery (base64 decoding handled in app layer)
    (
        SELECT json_group_array(
            json_object(
                'kas_uri', kas.uri,
                'kas_id', kas.id,
                'key_id', kask.key_id,
                'algorithm', kask.key_algorithm,
                'public_key_ctx', kask.public_key_ctx
            )
        )
        FROM key_access_server_keys kask
        WHERE kask.key_access_server_id = kas.id
    ) AS keys,
    counted.total
FROM key_access_servers AS kas
CROSS JOIN counted
LIMIT @limit_
OFFSET @offset_;

-- name: getKeyAccessServer :one
SELECT
    kas.id,
    kas.uri,
    kas.public_key,
    kas.name,
    kas.source_type,
    json_object(
        'labels', json_extract(metadata, '$.labels'),
        'created_at', created_at,
        'updated_at', updated_at
    ) AS metadata,
    -- Keys subquery (base64 decoding handled in app layer)
    (
        SELECT json_group_array(
            json_object(
                'kas_uri', kas.uri,
                'kas_id', kas.id,
                'key_id', kask.key_id,
                'algorithm', kask.key_algorithm,
                'public_key_ctx', kask.public_key_ctx
            )
        )
        FROM key_access_server_keys kask
        WHERE kask.key_access_server_id = kas.id
    ) AS keys
FROM key_access_servers AS kas
WHERE (sqlc.narg('id') IS NULL OR kas.id = sqlc.narg('id'))
  AND (sqlc.narg('name') IS NULL OR kas.name = sqlc.narg('name'))
  AND (sqlc.narg('uri') IS NULL OR kas.uri = sqlc.narg('uri'));

-- name: createKeyAccessServer :one
-- Note: ID generated in application layer before INSERT
INSERT INTO key_access_servers (id, uri, public_key, name, metadata, source_type)
VALUES (@id, @uri, @public_key, @name, @metadata, @source_type)
RETURNING id;

-- name: updateKeyAccessServer :execrows
UPDATE key_access_servers
SET
    uri = COALESCE(sqlc.narg('uri'), uri),
    public_key = COALESCE(sqlc.narg('public_key'), public_key),
    name = COALESCE(sqlc.narg('name'), name),
    metadata = COALESCE(sqlc.narg('metadata'), metadata),
    source_type = COALESCE(sqlc.narg('source_type'), source_type)
WHERE id = @id;

-- name: deleteKeyAccessServer :execrows
DELETE FROM key_access_servers WHERE id = @id;


-----------------------------------------------------------------
-- Key Access Server Keys (SQLite)
------------------------------------------------------------------

-- name: createKey :one
-- Note: ID generated in application layer before INSERT
INSERT INTO key_access_server_keys
    (id, key_access_server_id, key_algorithm, key_id, key_mode, key_status, metadata, private_key_ctx, public_key_ctx, provider_config_id, legacy)
VALUES (@id, @key_access_server_id, @key_algorithm, @key_id, @key_mode, @key_status, @metadata, @private_key_ctx, @public_key_ctx, @provider_config_id, @legacy)
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
  json_object(
    'labels', json_extract(kask.metadata, '$.labels'),
    'created_at', kask.created_at,
    'updated_at', kask.updated_at
  ) AS metadata,
  pc.manager AS pc_manager,
  pc.provider_name,
  pc.config AS pc_config,
  json_object(
      'labels', json_extract(pc.metadata, '$.labels'),
      'created_at', pc.created_at,
      'updated_at', pc.updated_at
  ) AS pc_metadata,
  kask.legacy
FROM key_access_server_keys AS kask
LEFT JOIN
    provider_config as pc ON kask.provider_config_id = pc.id
INNER JOIN
    key_access_servers AS kas ON kask.key_access_server_id = kas.id
WHERE (sqlc.narg('id') IS NULL OR kask.id = sqlc.narg('id'))
  AND (sqlc.narg('key_id') IS NULL OR kask.key_id = sqlc.narg('key_id'))
  AND (sqlc.narg('kas_id') IS NULL OR kask.key_access_server_id = sqlc.narg('kas_id'))
  AND (sqlc.narg('kas_uri') IS NULL OR kas.uri = sqlc.narg('kas_uri'))
  AND (sqlc.narg('kas_name') IS NULL OR kas.name = sqlc.narg('kas_name'));

-- name: listKeyMappings :many
-- Note: Complex query simplified for SQLite
WITH filtered_keys AS (
    SELECT
        kask.created_at,
        kask.id AS id,
        kask.key_id AS kid,
        kas.id AS kas_id,
        kas.uri AS kas_uri
    FROM key_access_server_keys kask
    INNER JOIN key_access_servers kas ON kask.key_access_server_id = kas.id
    WHERE (
        (sqlc.narg('id') IS NOT NULL AND kask.id = sqlc.narg('id'))
        OR (
            sqlc.narg('kid') IS NOT NULL
            AND kask.key_id = sqlc.narg('kid')
            AND (
                (sqlc.narg('kas_id') IS NOT NULL AND kas.id = sqlc.narg('kas_id'))
                OR (sqlc.narg('kas_name') IS NOT NULL AND kas.name = sqlc.narg('kas_name'))
                OR (sqlc.narg('kas_uri') IS NOT NULL AND kas.uri = sqlc.narg('kas_uri'))
            )
        )
        OR (sqlc.narg('id') IS NULL AND sqlc.narg('kid') IS NULL)
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
)
SELECT
    fk.kid,
    fk.kas_uri,
    -- Namespace mappings as subquery
    (
        SELECT json_group_array(json_object('id', anpm.namespace_id, 'fqn', fqns.fqn))
        FROM attribute_namespace_public_key_map anpm
        INNER JOIN attribute_fqns fqns ON anpm.namespace_id = fqns.namespace_id AND fqns.attribute_id IS NULL AND fqns.value_id IS NULL
        WHERE anpm.key_access_server_key_id = fk.id
    ) AS namespace_mappings,
    -- Attribute mappings as subquery
    (
        SELECT json_group_array(json_object('id', adpm.definition_id, 'fqn', fqns.fqn))
        FROM attribute_definition_public_key_map adpm
        INNER JOIN attribute_fqns fqns ON adpm.definition_id = fqns.attribute_id AND fqns.value_id IS NULL
        WHERE adpm.key_access_server_key_id = fk.id
    ) AS attribute_mappings,
    -- Value mappings as subquery
    (
        SELECT json_group_array(json_object('id', avpm.value_id, 'fqn', fqns.fqn))
        FROM attribute_value_public_key_map avpm
        INNER JOIN attribute_fqns fqns ON avpm.value_id = fqns.value_id
        WHERE avpm.key_access_server_key_id = fk.id
    ) AS value_mappings,
    kwmc.total
FROM filtered_keys fk
INNER JOIN keys_with_mappings kwm ON fk.id = kwm.id
CROSS JOIN keys_with_mappings_count kwmc
ORDER BY fk.created_at
LIMIT @limit_
OFFSET @offset_;

-- name: updateKey :execrows
UPDATE key_access_server_keys
SET
    key_status = COALESCE(sqlc.narg('key_status'), key_status),
    metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE id = @id;

-- name: listKeys :many
WITH listed AS (
    SELECT
        kas.id AS kas_id,
        kas.uri AS kas_uri
    FROM key_access_servers AS kas
    WHERE (sqlc.narg('kas_id') IS NULL OR kas.id = sqlc.narg('kas_id'))
            AND (sqlc.narg('kas_name') IS NULL OR kas.name = sqlc.narg('kas_name'))
            AND (sqlc.narg('kas_uri') IS NULL OR kas.uri = sqlc.narg('kas_uri'))
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
  json_object(
    'labels', json_extract(kask.metadata, '$.labels'),
    'created_at', kask.created_at,
    'updated_at', kask.updated_at
  ) AS metadata,
  pc.provider_name,
  pc.config AS provider_config,
  json_object(
      'labels', json_extract(pc.metadata, '$.labels'),
      'created_at', pc.created_at,
      'updated_at', pc.updated_at
  ) AS pc_metadata,
  kask.legacy
FROM key_access_server_keys AS kask
INNER JOIN
    listed ON kask.key_access_server_id = listed.kas_id
LEFT JOIN
    provider_config as pc ON kask.provider_config_id = pc.id
WHERE
    (sqlc.narg('key_algorithm') IS NULL OR kask.key_algorithm = sqlc.narg('key_algorithm'))
    AND (sqlc.narg('legacy') IS NULL OR kask.legacy = sqlc.narg('legacy'))
ORDER BY kask.created_at DESC
LIMIT @limit_
OFFSET @offset_;

-- name: deleteKey :execrows
DELETE FROM key_access_server_keys WHERE id = @id;


----------------------------------------------------------------
-- Default KAS Keys (SQLite)
----------------------------------------------------------------

-- name: getBaseKey :one
-- Note: Base64 decoding of PEM handled in app layer
SELECT
    json_object(
       'kas_uri', kas.uri,
       'kas_id', kas.id,
       'key_id', kask.key_id,
       'algorithm', kask.key_algorithm,
       'public_key_ctx', kask.public_key_ctx
    ) AS base_keys
FROM base_keys bk
INNER JOIN key_access_server_keys kask ON bk.key_access_server_key_id = kask.id
INNER JOIN key_access_servers kas ON kask.key_access_server_id = kas.id
LIMIT 1;

-- name: setBaseKey :execrows
INSERT INTO base_keys (key_access_server_key_id)
VALUES (@key_access_server_key_id);
