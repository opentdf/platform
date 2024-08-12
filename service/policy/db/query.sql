---------------------------------------------------------------- 
-- KEY ACCESS SERVERS
----------------------------------------------------------------

-- name: ListKeyAccessServers :many
SELECT id, uri, public_key,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', metadata -> 'labels', 'created_at', created_at, 'updated_at', updated_at)) as metadata
FROM key_access_servers;

-- name: GetKeyAccessServer :one
SELECT id, uri, public_key,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', metadata -> 'labels', 'created_at', created_at, 'updated_at', updated_at)) as metadata
FROM key_access_servers WHERE id = $1;

-- name: CreateKeyAccessServer :one
INSERT INTO key_access_servers (uri, public_key, metadata)
VALUES ($1, $2, $3)
RETURNING id;

-- name: UpdateKeyAccessServer :one
UPDATE key_access_servers
SET 
    uri = coalesce(sqlc.narg('uri'), uri),
    public_key = coalesce(sqlc.narg('public_key'), public_key),
    metadata = coalesce(sqlc.narg('metadata'), metadata)
WHERE id = $1
RETURNING id;

-- name: DeleteKeyAccessServer :execrows
DELETE FROM key_access_servers WHERE id = $1;

---------------------------------------------------------------- 
-- RESOURCE MAPPING GROUPS
----------------------------------------------------------------

-- name: ListResourceMappingGroups :many
SELECT id, namespace_id, name
FROM resource_mapping_groups;

-- name: GetResourceMappingGroup :one
SELECT id, namespace_id, name
FROM resource_mapping_groups
WHERE id = $1;

-- name: CreateResourceMappingGroup :one
INSERT INTO resource_mapping_groups (namespace_id, name)
VALUES ($1, $2)
RETURNING id;

-- name: UpdateResourceMappingGroup :one
UPDATE resource_mapping_groups
SET
    namespace_id = coalesce(sqlc.narg('namespace_id'), namespace_id),
    name = coalesce(sqlc.narg('name'), name)
WHERE id = $1
RETURNING id;

-- name: DeleteResourceMappingGroup :execrows
DELETE FROM resource_mapping_groups WHERE id = $1;

---------------------------------------------------------------- 
-- NAMESPACES
----------------------------------------------------------------

-- name: GetNamespace :one
SELECT ns.id, ns.name, ns.active,
    attribute_fqns.fqn as fqn,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', ns.metadata -> 'labels', 'created_at', ns.created_at, 'updated_at', ns.updated_at)) as metadata,
    JSONB_AGG(DISTINCT JSON_BUILD_OBJECT('id', kas.id, 'uri', kas.uri, 'public_key', kas.public_key)) FILTER (WHERE ankg.namespace_id IS NOT NULL) as grants
FROM attribute_namespaces ns
LEFT JOIN attribute_namespace_key_access_grants ankg ON ankg.namespace_id = ns.id
LEFT JOIN key_access_servers kas ON kas.id = ankg.key_access_server_id
LEFT JOIN attribute_fqns ON attribute_fqns.namespace_id = ns.id
WHERE ns.id = $1
AND attribute_fqns.attribute_id IS NULL AND attribute_fqns.value_id IS NULL;

-- name: AssignKeyAccessServerToNamespace :execrows
INSERT INTO attribute_namespace_key_access_grants
(namespace_id, key_access_server_id)
VALUES ($1, $2);

-- name: RemoveKeyAccessServerFromNamespace :execrows
DELETE FROM attribute_namespace_key_access_grants
WHERE namespace_id = $1 AND key_access_server_id = $2
IS TRUE RETURNING *;