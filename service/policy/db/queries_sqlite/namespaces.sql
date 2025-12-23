----------------------------------------------------------------
-- NAMESPACES (SQLite)
----------------------------------------------------------------

-- name: listNamespaces :many
SELECT
    COUNT(*) OVER() AS total,
    ns.id,
    ns.name,
    ns.active,
    json_object(
        'labels', json_extract(ns.metadata, '$.labels'),
        'created_at', ns.created_at,
        'updated_at', ns.updated_at
    ) as metadata,
    fqns.fqn
FROM attribute_namespaces ns
LEFT JOIN attribute_fqns fqns ON ns.id = fqns.namespace_id AND fqns.attribute_id IS NULL
WHERE (sqlc.narg('active') IS NULL OR ns.active = sqlc.narg('active'))
LIMIT @limit_
OFFSET @offset_;

-- name: getNamespace :one
-- Note: SQLite version simplified - complex JSONB aggregations handled in app layer
-- Keys and certs returned as separate queries or handled by PolicyDBClient
SELECT
    ns.id,
    ns.name,
    ns.active,
    fqns.fqn,
    json_object(
        'labels', json_extract(ns.metadata, '$.labels'),
        'created_at', ns.created_at,
        'updated_at', ns.updated_at
    ) as metadata,
    -- Grants aggregation using json_group_array
    (
        SELECT json_group_array(
            json_object(
                'id', kas.id,
                'uri', kas.uri,
                'name', kas.name,
                'public_key', kas.public_key
            )
        )
        FROM attribute_namespace_key_access_grants kas_ns_grants
        JOIN key_access_servers kas ON kas.id = kas_ns_grants.key_access_server_id
        WHERE kas_ns_grants.namespace_id = ns.id
    ) as grants,
    -- Keys: simplified, full key details fetched separately
    (
        SELECT json_group_array(
            json_object(
                'kas_id', kas.id,
                'kas_uri', kas.uri,
                'key_id', kask.key_id,
                'algorithm', kask.key_algorithm
            )
        )
        FROM attribute_namespace_public_key_map k
        INNER JOIN key_access_server_keys kask ON k.key_access_server_key_id = kask.id
        INNER JOIN key_access_servers kas ON kask.key_access_server_id = kas.id
        WHERE k.namespace_id = ns.id
    ) as keys,
    -- Certs aggregation
    (
        SELECT json_group_array(
            json_object(
                'id', cert.id,
                'pem', cert.pem
            )
        )
        FROM attribute_namespace_certificates c
        INNER JOIN certificates cert ON c.certificate_id = cert.id
        WHERE c.namespace_id = ns.id
    ) as certs
FROM attribute_namespaces ns
LEFT JOIN attribute_fqns fqns ON fqns.namespace_id = ns.id
WHERE fqns.attribute_id IS NULL AND fqns.value_id IS NULL
  AND (sqlc.narg('id') IS NULL OR ns.id = sqlc.narg('id'))
  AND (sqlc.narg('name') IS NULL OR ns.name = REPLACE(REPLACE(sqlc.narg('name'), 'https://', ''), 'http://', ''));

-- name: createNamespace :one
-- Note: ID generated in application layer before INSERT
INSERT INTO attribute_namespaces (id, name, metadata)
VALUES (@id, @name, @metadata)
RETURNING id;

-- updateNamespace: both Safe and Unsafe Updates
-- name: updateNamespace :execrows
UPDATE attribute_namespaces
SET
    name = COALESCE(sqlc.narg('name'), name),
    active = COALESCE(sqlc.narg('active'), active),
    metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE id = @id;

-- name: deleteNamespace :execrows
DELETE FROM attribute_namespaces WHERE id = @id;

-- name: removeKeyAccessServerFromNamespace :execrows
DELETE FROM attribute_namespace_key_access_grants
WHERE namespace_id = @namespace_id AND key_access_server_id = @key_access_server_id;

-- name: assignPublicKeyToNamespace :one
INSERT INTO attribute_namespace_public_key_map (namespace_id, key_access_server_key_id)
VALUES (@namespace_id, @key_access_server_key_id)
RETURNING namespace_id, key_access_server_key_id;

-- name: removePublicKeyFromNamespace :execrows
DELETE FROM attribute_namespace_public_key_map
WHERE namespace_id = @namespace_id AND key_access_server_key_id = @key_access_server_key_id;

-- name: rotatePublicKeyForNamespace :many
UPDATE attribute_namespace_public_key_map
SET key_access_server_key_id = sqlc.arg('new_key_id')
WHERE (key_access_server_key_id = sqlc.arg('old_key_id'))
RETURNING namespace_id;

----------------------------------------------------------------
-- CERTIFICATES (SQLite)
----------------------------------------------------------------

-- name: createCertificate :one
-- Note: ID generated in application layer before INSERT
INSERT INTO certificates (id, pem, metadata)
VALUES (@id, @pem, @metadata)
RETURNING id;

-- name: getCertificate :one
SELECT
    id,
    pem,
    json_object(
        'labels', json_extract(metadata, '$.labels'),
        'created_at', created_at,
        'updated_at', updated_at
    ) as metadata
FROM certificates
WHERE id = @id;

-- name: getCertificateByPEM :one
SELECT
    id,
    pem,
    json_object(
        'labels', json_extract(metadata, '$.labels'),
        'created_at', created_at,
        'updated_at', updated_at
    ) as metadata
FROM certificates
WHERE pem = @pem;

-- name: deleteCertificate :execrows
DELETE FROM certificates WHERE id = @id;

-- name: assignCertificateToNamespace :one
INSERT INTO attribute_namespace_certificates (namespace_id, certificate_id)
VALUES (@namespace_id, @certificate_id)
RETURNING namespace_id, certificate_id;

-- name: removeCertificateFromNamespace :execrows
DELETE FROM attribute_namespace_certificates
WHERE namespace_id = @namespace_id AND certificate_id = @certificate_id;

-- name: countCertificateNamespaceAssignments :one
SELECT COUNT(*) FROM attribute_namespace_certificates
WHERE certificate_id = @certificate_id;
