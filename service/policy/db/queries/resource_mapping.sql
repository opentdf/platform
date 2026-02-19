---------------------------------------------------------------- 
-- RESOURCE MAPPING GROUPS
----------------------------------------------------------------

-- name: listResourceMappingGroups :many
SELECT rmg.id,
    rmg.namespace_id,
    rmg.name,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', rmg.metadata -> 'labels', 'created_at', rmg.created_at, 'updated_at', rmg.updated_at)) as metadata,
    COUNT(*) OVER() AS total
FROM resource_mapping_groups rmg
WHERE (sqlc.narg('namespace_id')::uuid IS NULL OR rmg.namespace_id = sqlc.narg('namespace_id')::uuid) 
ORDER BY rmg.created_at DESC
LIMIT @limit_ 
OFFSET @offset_; 

-- name: getResourceMappingGroup :one
SELECT id, namespace_id, name,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', metadata -> 'labels', 'created_at', created_at, 'updated_at', updated_at)) as metadata
FROM resource_mapping_groups
WHERE id = $1;

-- name: createResourceMappingGroup :one
INSERT INTO resource_mapping_groups (namespace_id, name, metadata)
VALUES ($1, $2, $3)
RETURNING id;

-- name: updateResourceMappingGroup :execrows
UPDATE resource_mapping_groups
SET
    namespace_id = COALESCE(sqlc.narg('namespace_id'), namespace_id),
    name = COALESCE(sqlc.narg('name'), name),
    metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE id = $1;

-- name: deleteResourceMappingGroup :execrows
DELETE FROM resource_mapping_groups WHERE id = $1;

---------------------------------------------------------------- 
-- RESOURCE MAPPING
----------------------------------------------------------------

-- name: listResourceMappings :many
SELECT
    m.id,
    JSON_BUILD_OBJECT('id', av.id, 'value', av.value, 'fqn', fqns.fqn) as attribute_value,
    m.terms,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', m.metadata -> 'labels', 'created_at', m.created_at, 'updated_at', m.updated_at)) as metadata,
    JSON_STRIP_NULLS(
        JSON_BUILD_OBJECT(
            'id', rmg.id,
            'name', rmg.name,
            'namespace_id', rmg.namespace_id
        )
    ) AS group,
    COUNT(*) OVER() AS total
FROM resource_mappings m
LEFT JOIN attribute_values av on m.attribute_value_id = av.id
LEFT JOIN attribute_fqns fqns on av.id = fqns.value_id
LEFT JOIN resource_mapping_groups rmg ON m.group_id = rmg.id
WHERE (sqlc.narg('group_id')::uuid IS NULL OR m.group_id = sqlc.narg('group_id')::uuid)
GROUP BY av.id, m.id, fqns.fqn, rmg.id, rmg.name, rmg.namespace_id
ORDER BY m.created_at DESC
LIMIT @limit_ 
OFFSET @offset_; 

-- name: listResourceMappingsByFullyQualifiedGroup :many
-- CTE to cache the group JSON build since it will be the same for all mappings of the group
WITH groups_cte AS (
    SELECT
        g.id,
        JSON_BUILD_OBJECT(
            'id', g.id,
            'namespace_id', g.namespace_id,
            'name', g.name,
            'metadata', JSON_STRIP_NULLS(JSON_BUILD_OBJECT(
                'labels', g.metadata -> 'labels',
                'created_at', g.created_at,
                'updated_at', g.updated_at
            ))
        ) as group
    FROM resource_mapping_groups g
    JOIN attribute_namespaces ns on g.namespace_id = ns.id
    WHERE ns.name = @namespace_name AND g.name = @group_name 
)
SELECT
    m.id,
    JSON_BUILD_OBJECT('id', av.id, 'value', av.value, 'fqn', fqns.fqn) as attribute_value,
    m.terms,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', m.metadata -> 'labels', 'created_at', m.created_at, 'updated_at', m.updated_at)) as metadata,
    g.group
FROM resource_mappings m
JOIN groups_cte g ON m.group_id = g.id
JOIN attribute_values av on m.attribute_value_id = av.id
JOIN attribute_fqns fqns on av.id = fqns.value_id
ORDER BY m.created_at DESC;

-- name: getResourceMapping :one
SELECT
    m.id,
    JSON_BUILD_OBJECT('id', av.id, 'value', av.value, 'fqn', fqns.fqn) as attribute_value,
    m.terms,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', m.metadata -> 'labels', 'created_at', m.created_at, 'updated_at', m.updated_at)) as metadata,
    COALESCE(m.group_id::TEXT, '')::TEXT as group_id
FROM resource_mappings m 
LEFT JOIN attribute_values av on m.attribute_value_id = av.id
LEFT JOIN attribute_fqns fqns on av.id = fqns.value_id
WHERE m.id = $1
GROUP BY av.id, m.id, fqns.fqn;

-- name: createResourceMapping :one
INSERT INTO resource_mappings (attribute_value_id, terms, metadata, group_id)
VALUES ($1, $2, $3, $4)
RETURNING id;

-- name: updateResourceMapping :execrows
UPDATE resource_mappings
SET
    attribute_value_id = COALESCE(sqlc.narg('attribute_value_id'), attribute_value_id),
    terms = COALESCE(sqlc.narg('terms'), terms),
    metadata = COALESCE(sqlc.narg('metadata'), metadata),
    group_id = COALESCE(sqlc.narg('group_id'), group_id)
WHERE id = $1;

-- name: deleteResourceMapping :execrows
DELETE FROM resource_mappings WHERE id = $1;
