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
-- ATTRIBUTES
----------------------------------------------------------------

-- name: ListKeyAccessServerGrantsByKasUri :many
SELECT kas.id AS kas_id, kas.uri AS kas_uri, kas.public_key AS kas_public_key,
       JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', kas.metadata -> 'labels', 'created_at', kas.created_at, 'updated_at', kas.updated_at)) as kas_metadata,
       ARRAY_AGG(DISTINCT attrkag.attribute_definition_id) as attribute_grant_ids,
       ARRAY_AGG(DISTINCT valkag.attribute_value_id) as value_grant_ids
FROM key_access_servers kas
LEFT JOIN attribute_definition_key_access_grants attrkag ON kas.id = attrkag.key_access_server_id
LEFT JOIN attribute_value_key_access_grants valkag ON kas.id = valkag.key_access_server_id
WHERE kas.uri = $1
GROUP BY kas.id;

-- name: ListKeyAccessServerGrantsByKasId :many
SELECT kas.id AS kas_id, kas.uri AS kas_uri, kas.public_key AS kas_public_key,
       JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', kas.metadata -> 'labels', 'created_at', kas.created_at, 'updated_at', kas.updated_at)) as kas_metadata,
       ARRAY_AGG(DISTINCT attrkag.attribute_definition_id) as attribute_grant_ids,
       ARRAY_AGG(DISTINCT valkag.attribute_value_id) as value_grant_ids
FROM key_access_servers kas
LEFT JOIN attribute_definition_key_access_grants attrkag ON kas.id = attrkag.key_access_server_id
LEFT JOIN attribute_value_key_access_grants valkag ON kas.id = valkag.key_access_server_id
WHERE kas.id = $1
GROUP BY kas.id;

-- name: ListAllKeyAccessServerGrants :many
SELECT kas.id AS kas_id, kas.uri AS kas_uri, kas.public_key AS kas_public_key,
       JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', kas.metadata -> 'labels', 'created_at', kas.created_at, 'updated_at', kas.updated_at)) as kas_metadata,
       ARRAY_AGG(DISTINCT attrkag.attribute_definition_id) as attribute_grant_ids,
       ARRAY_AGG(DISTINCT valkag.attribute_value_id) as value_grant_ids
FROM key_access_servers kas
LEFT JOIN attribute_definition_key_access_grants attrkag ON kas.id = attrkag.key_access_server_id
LEFT JOIN attribute_value_key_access_grants valkag ON kas.id = valkag.key_access_server_id
GROUP BY kas.id;

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
