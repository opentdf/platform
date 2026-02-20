----------------------------------------------------------------
-- NAMESPACES
----------------------------------------------------------------

-- name: listNamespaces :many
SELECT
    COUNT(*) OVER() AS total,
    ns.id,
    ns.name,
    ns.active,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', ns.metadata -> 'labels', 'created_at', ns.created_at, 'updated_at', ns.updated_at)) as metadata,
    fqns.fqn
FROM attribute_namespaces ns
LEFT JOIN attribute_fqns fqns ON ns.id = fqns.namespace_id AND fqns.attribute_id IS NULL
WHERE (sqlc.narg('active')::BOOLEAN IS NULL OR ns.active = sqlc.narg('active')::BOOLEAN)
ORDER BY ns.created_at DESC
LIMIT @limit_
OFFSET @offset_;

-- name: getNamespace :one
SELECT
    ns.id,
    ns.name,
    ns.active,
    fqns.fqn,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', ns.metadata -> 'labels', 'created_at', ns.created_at, 'updated_at', ns.updated_at)) as metadata,
    JSONB_AGG(DISTINCT JSONB_BUILD_OBJECT(
        'id', kas.id,
        'uri', kas.uri,
        'name', kas.name,
        'public_key', kas.public_key
    )) FILTER (WHERE kas_ns_grants.namespace_id IS NOT NULL) as grants,
    nmp_keys.keys as keys
FROM attribute_namespaces ns
LEFT JOIN attribute_namespace_key_access_grants kas_ns_grants ON kas_ns_grants.namespace_id = ns.id
LEFT JOIN key_access_servers kas ON kas.id = kas_ns_grants.key_access_server_id
LEFT JOIN attribute_fqns fqns ON fqns.namespace_id = ns.id
LEFT JOIN (
    SELECT
        k.namespace_id,
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
    FROM attribute_namespace_public_key_map k
    INNER JOIN key_access_server_keys kask ON k.key_access_server_key_id = kask.id
    INNER JOIN key_access_servers kas ON kask.key_access_server_id = kas.id
    GROUP BY k.namespace_id
) nmp_keys ON ns.id = nmp_keys.namespace_id
WHERE fqns.attribute_id IS NULL AND fqns.value_id IS NULL
  AND (sqlc.narg('id')::uuid IS NULL OR ns.id = sqlc.narg('id')::uuid)
  AND (sqlc.narg('name')::text IS NULL OR ns.name = REGEXP_REPLACE(sqlc.narg('name')::text, '^https://', ''))
GROUP BY ns.id, fqns.fqn, nmp_keys.keys;

-- name: createNamespace :one
INSERT INTO attribute_namespaces (name, metadata)
VALUES ($1, $2)
RETURNING id;

-- updateNamespace: both Safe and Unsafe Updates
-- name: updateNamespace :execrows
UPDATE attribute_namespaces
SET
    name = COALESCE(sqlc.narg('name'), name),
    active = COALESCE(sqlc.narg('active'), active),
    metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE id = $1;

-- name: deleteNamespace :execrows
DELETE FROM attribute_namespaces WHERE id = $1;

-- name: removeKeyAccessServerFromNamespace :execrows
DELETE FROM attribute_namespace_key_access_grants
WHERE namespace_id = $1 AND key_access_server_id = $2;

-- name: assignPublicKeyToNamespace :one
INSERT INTO attribute_namespace_public_key_map (namespace_id, key_access_server_key_id)
VALUES ($1, $2)
RETURNING namespace_id, key_access_server_key_id;

-- name: removePublicKeyFromNamespace :execrows
DELETE FROM attribute_namespace_public_key_map
WHERE namespace_id = $1 AND key_access_server_key_id = $2;

-- name: rotatePublicKeyForNamespace :many
UPDATE attribute_namespace_public_key_map
SET key_access_server_key_id = sqlc.arg('new_key_id')::uuid
WHERE (key_access_server_key_id = sqlc.arg('old_key_id')::uuid)
RETURNING namespace_id;
