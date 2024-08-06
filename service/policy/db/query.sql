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

-- name: CreateResourceMappingGroup :one
INSERT INTO resource_mapping_groups (namespace_id, name)
VALUES ($1, $2)
RETURNING id;

-- name: UpdateResourceMappingGroup :one
UPDATE resource_mapping_groups
SET
    -- assuming name is the only modifiable field
    name = coalesce(sqlc.narg('name'), name)
WHERE id = $1
RETURNING id;

-- name: DeleteResourceMappingGroup :execrows
DELETE FROM resource_mapping_groups WHERE id = $1;
