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

-- name: ListKeyAccessServerGrants :many
SELECT 
    kas.id AS kas_id, 
    kas.uri AS kas_uri, 
    kas.public_key AS kas_public_key,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT(
        'labels', kas.metadata -> 'labels', 
        'created_at', kas.created_at, 
        'updated_at', kas.updated_at
    )) AS kas_metadata,
    json_agg(DISTINCT jsonb_build_object(
        'id', attrkag.attribute_definition_id, 
        'fqn', fqns_on_attr.fqn
    )) FILTER (WHERE attrkag.attribute_definition_id IS NOT NULL) AS attributes_grants,
    json_agg(DISTINCT jsonb_build_object(
        'id', valkag.attribute_value_id, 
        'fqn', fqns_on_vals.fqn
    )) FILTER (WHERE valkag.attribute_value_id IS NOT NULL) AS values_grants,
    json_agg(DISTINCT jsonb_build_object(
        'id', nskag.namespace_id, 
        'fqn', fqns_on_ns.fqn
    )) FILTER (WHERE nskag.namespace_id IS NOT NULL) AS namespace_grants
FROM 
    key_access_servers kas
LEFT JOIN 
    attribute_definition_key_access_grants attrkag 
    ON kas.id = attrkag.key_access_server_id
LEFT JOIN 
    attribute_fqns fqns_on_attr 
    ON attrkag.attribute_definition_id = fqns_on_attr.attribute_id 
    AND fqns_on_attr.value_id IS NULL
LEFT JOIN 
    attribute_value_key_access_grants valkag 
    ON kas.id = valkag.key_access_server_id
LEFT JOIN 
    attribute_fqns fqns_on_vals 
    ON valkag.attribute_value_id = fqns_on_vals.value_id
LEFT JOIN
    attribute_namespace_key_access_grants nskag
    ON kas.id = nskag.key_access_server_id
LEFT JOIN 
    attribute_fqns fqns_on_ns
    ON nskag.namespace_id = fqns_on_ns.namespace_id
WHERE (NULLIF(@kas_id, '') IS NULL OR kas.id = @kas_id::uuid)
    AND (NULLIF(@kas_uri, '') IS NULL OR kas.uri = @kas_uri::varchar)
GROUP BY 
    kas.id;


---------------------------------------------------------------- 
-- RESOURCE MAPPING GROUPS
----------------------------------------------------------------

-- name: ListResourceMappingGroups :many
SELECT id, namespace_id, name
FROM resource_mapping_groups;

-- name: ListResourceMappingGroupsByAttrFQN :many
SELECT g.id, g.namespace_id, g.name
FROM resource_mapping_groups g
LEFT JOIN attribute_fqns fqns ON g.namespace_id = fqns.namespace_id
WHERE fqns.fqn = LOWER(@fqn);

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
    JSONB_AGG(DISTINCT JSONB_BUILD_OBJECT(
        'id', kas.id, 
        'uri', kas.uri, 
        'public_key', kas.public_key
    )) FILTER (WHERE kas_ns_grants.namespace_id IS NOT NULL) as grants
FROM attribute_namespaces ns
LEFT JOIN attribute_namespace_key_access_grants kas_ns_grants ON kas_ns_grants.namespace_id = ns.id
LEFT JOIN key_access_servers kas ON kas.id = kas_ns_grants.key_access_server_id
LEFT JOIN attribute_fqns ON attribute_fqns.namespace_id = ns.id
WHERE ns.id = $1
AND attribute_fqns.attribute_id IS NULL AND attribute_fqns.value_id IS NULL
GROUP BY ns.id, 
attribute_fqns.fqn;

-- name: AssignKeyAccessServerToNamespace :execrows
INSERT INTO attribute_namespace_key_access_grants
(namespace_id, key_access_server_id)
VALUES ($1, $2);

-- name: RemoveKeyAccessServerFromNamespace :execrows
DELETE FROM attribute_namespace_key_access_grants
WHERE namespace_id = $1 AND key_access_server_id = $2;