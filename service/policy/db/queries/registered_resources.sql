----------------------------------------------------------------
-- REGISTERED RESOURCES
----------------------------------------------------------------

-- name: createRegisteredResource :one
WITH inserted AS (
    INSERT INTO registered_resources (namespace_id, name, metadata)
    SELECT
        COALESCE(sqlc.narg('namespace_id')::uuid, fqns.namespace_id),
        @name,
        @metadata
    FROM (
        SELECT
            sqlc.narg('namespace_id')::uuid as direct_namespace_id
    ) direct
    LEFT JOIN attribute_fqns fqns ON fqns.fqn = sqlc.narg('namespace_fqn')::text AND sqlc.narg('namespace_id')::text IS NULL
    WHERE
        (sqlc.narg('namespace_id')::text IS NOT NULL AND direct.direct_namespace_id IS NOT NULL) OR
        (sqlc.narg('namespace_fqn')::text IS NOT NULL AND fqns.namespace_id IS NOT NULL) OR
        (sqlc.narg('namespace_id')::text IS NULL AND sqlc.narg('namespace_fqn')::text IS NULL)
    RETURNING id, namespace_id, name, metadata
)
SELECT
    i.id,
    i.name,
    i.metadata,
    CASE WHEN n.id IS NOT NULL THEN
        JSON_BUILD_OBJECT(
            'id', n.id,
            'name', n.name,
            'fqn', fqns.fqn
        )
    ELSE NULL END as namespace
FROM inserted i
LEFT JOIN attribute_namespaces n ON i.namespace_id = n.id
LEFT JOIN attribute_fqns fqns ON fqns.namespace_id = n.id AND fqns.attribute_id IS NULL AND fqns.value_id IS NULL;

-- name: getRegisteredResource :one
SELECT
    r.id,
    r.name,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', r.metadata -> 'labels', 'created_at', r.created_at, 'updated_at', r.updated_at)) as metadata,
    CASE WHEN n.id IS NOT NULL THEN
        JSON_BUILD_OBJECT(
            'id', n.id,
            'name', n.name,
            'fqn', ns_fqns.fqn
        )
    ELSE NULL END as namespace,
    JSON_AGG(
        JSON_BUILD_OBJECT(
            'id', v.id,
            'value', v.value
        )
    ) FILTER (WHERE v.id IS NOT NULL) as values
FROM registered_resources r
LEFT JOIN attribute_namespaces n ON r.namespace_id = n.id
LEFT JOIN attribute_fqns ns_fqns ON ns_fqns.namespace_id = n.id AND ns_fqns.attribute_id IS NULL AND ns_fqns.value_id IS NULL
LEFT JOIN registered_resource_values v ON v.registered_resource_id = r.id
WHERE
    (sqlc.narg('id')::uuid IS NULL OR r.id = sqlc.narg('id')::uuid) AND
    (sqlc.narg('name')::text IS NULL OR r.name = sqlc.narg('name')::text) AND
    (sqlc.narg('namespace_id')::uuid IS NULL OR r.namespace_id = sqlc.narg('namespace_id')::uuid) AND
    (sqlc.narg('namespace_fqn')::text IS NULL OR ns_fqns.fqn = sqlc.narg('namespace_fqn')::text)
GROUP BY r.id, n.id, ns_fqns.fqn
-- prefer non-namespaced over namespaced results (to support legacy behavior)
ORDER BY r.namespace_id NULLS FIRST
LIMIT 1;

-- name: listRegisteredResources :many
WITH params AS (
    SELECT
        COALESCE(NULLIF(@sort_field::text, ''), 'created_at') AS resolved_field,
        CASE
            WHEN @sort_field::text = '' AND @sort_direction::text = '' THEN 'DESC'
            ELSE COALESCE(NULLIF(@sort_direction::text, ''), 'ASC')
        END AS resolved_direction
),
counted AS (
    SELECT COUNT(r.id) AS total
    FROM registered_resources r
    LEFT JOIN attribute_namespaces n ON r.namespace_id = n.id
    LEFT JOIN attribute_fqns ns_fqns ON ns_fqns.namespace_id = n.id AND ns_fqns.attribute_id IS NULL AND ns_fqns.value_id IS NULL
    WHERE
        (sqlc.narg('namespace_id')::uuid IS NULL OR r.namespace_id = sqlc.narg('namespace_id')::uuid) AND
        (sqlc.narg('namespace_fqn')::text IS NULL OR ns_fqns.fqn = sqlc.narg('namespace_fqn')::text)
)
SELECT
    r.id,
    r.name,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', r.metadata -> 'labels', 'created_at', r.created_at, 'updated_at', r.updated_at)) as metadata,
    CASE WHEN n.id IS NOT NULL THEN
        JSON_BUILD_OBJECT(
            'id', n.id,
            'name', n.name,
            'fqn', ns_fqns.fqn
        )
    ELSE NULL END as namespace,
    -- Aggregate all values for this resource into a JSON array, filtering NULL entries
    JSON_AGG(
        JSON_BUILD_OBJECT(
            'id', v.id,
            'value', v.value,
            'action_attribute_values', action_attrs.values
        )
    ) FILTER (WHERE v.id IS NOT NULL) as values,
    counted.total
FROM registered_resources r
LEFT JOIN attribute_namespaces n ON r.namespace_id = n.id
LEFT JOIN attribute_fqns ns_fqns ON ns_fqns.namespace_id = n.id AND ns_fqns.attribute_id IS NULL AND ns_fqns.value_id IS NULL
CROSS JOIN counted
CROSS JOIN params p
LEFT JOIN registered_resource_values v ON v.registered_resource_id = r.id
-- Build a JSON array of action/attribute pairs for each resource value
LEFT JOIN LATERAL (
    SELECT JSON_AGG(
        JSON_BUILD_OBJECT(
            'action', JSON_BUILD_OBJECT(
                'id', a.id,
                'name', a.name,
                'namespace', CASE WHEN a.namespace_id IS NULL THEN NULL
                    ELSE JSON_BUILD_OBJECT('id', ans.id, 'name', ans.name, 'fqn', ans_fqns.fqn)
                END
            ),
            'attribute_value', JSON_BUILD_OBJECT(
                'id', av.id,
                'value', av.value,
                'fqn', fqns.fqn
            )
        )
    ) AS values
    -- Join to get all action-attribute relationships for this resource value
    FROM registered_resource_action_attribute_values rav
    LEFT JOIN actions a on rav.action_id = a.id
    LEFT JOIN attribute_namespaces ans ON ans.id = a.namespace_id
    LEFT JOIN attribute_fqns ans_fqns ON ans_fqns.namespace_id = ans.id AND ans_fqns.attribute_id IS NULL AND ans_fqns.value_id IS NULL
    LEFT JOIN attribute_values av on rav.attribute_value_id = av.id
    LEFT JOIN attribute_fqns fqns on av.id = fqns.value_id
    -- Correlate to the outer query's resource value
    WHERE rav.registered_resource_value_id = v.id
) action_attrs ON true  -- required syntax for LATERAL joins
WHERE
    (sqlc.narg('namespace_id')::uuid IS NULL OR r.namespace_id = sqlc.narg('namespace_id')::uuid) AND
    (sqlc.narg('namespace_fqn')::text IS NULL OR ns_fqns.fqn = sqlc.narg('namespace_fqn')::text)
GROUP BY r.id, n.id, ns_fqns.fqn, counted.total, p.resolved_field, p.resolved_direction
ORDER BY
    CASE WHEN p.resolved_field = 'name' AND p.resolved_direction = 'ASC' THEN r.name END ASC,
    CASE WHEN p.resolved_field = 'name' AND p.resolved_direction = 'DESC' THEN r.name END DESC,
    CASE WHEN p.resolved_field = 'created_at' AND p.resolved_direction = 'ASC' THEN r.created_at END ASC,
    CASE WHEN p.resolved_field = 'created_at' AND p.resolved_direction = 'DESC' THEN r.created_at END DESC,
    CASE WHEN p.resolved_field = 'updated_at' AND p.resolved_direction = 'ASC' THEN r.updated_at END ASC,
    CASE WHEN p.resolved_field = 'updated_at' AND p.resolved_direction = 'DESC' THEN r.updated_at END DESC,
    r.id ASC
LIMIT @limit_
OFFSET @offset_;

-- name: updateRegisteredResource :execrows
UPDATE registered_resources
SET
    name = COALESCE(sqlc.narg('name'), name),
    metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE id = $1;

-- name: deleteRegisteredResource :execrows
DELETE FROM registered_resources WHERE id = $1;


----------------------------------------------------------------
-- REGISTERED RESOURCE VALUES
----------------------------------------------------------------

-- name: createRegisteredResourceValue :one
INSERT INTO registered_resource_values (registered_resource_id, value, metadata)
VALUES ($1, $2, $3)
RETURNING id;

-- name: getRegisteredResourceValue :one
SELECT
    v.id,
    v.registered_resource_id,
    v.value,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', v.metadata -> 'labels', 'created_at', v.created_at, 'updated_at', v.updated_at)) as metadata,
    CASE WHEN n.id IS NOT NULL THEN
        JSON_BUILD_OBJECT(
            'id', n.id,
            'name', n.name,
            'fqn', ns_fqns.fqn
        )
    ELSE NULL END as namespace,
    r.name as resource_name,
    JSON_AGG(
    	JSON_BUILD_OBJECT(
    		'action', JSON_BUILD_OBJECT(
    			'id', a.id,
    			'name', a.name
    		),
    		'attribute_value', JSON_BUILD_OBJECT(
    			'id', av.id,
    			'value', av.value,
    			'fqn', fqns.fqn
    		)
    	)
    ) FILTER (WHERE rav.id IS NOT NULL) as action_attribute_values
FROM registered_resource_values v
JOIN registered_resources r ON v.registered_resource_id = r.id
LEFT JOIN attribute_namespaces n ON r.namespace_id = n.id
LEFT JOIN attribute_fqns ns_fqns ON ns_fqns.namespace_id = n.id AND ns_fqns.attribute_id IS NULL AND ns_fqns.value_id IS NULL
LEFT JOIN registered_resource_action_attribute_values rav ON v.id = rav.registered_resource_value_id
LEFT JOIN actions a on rav.action_id = a.id
LEFT JOIN attribute_values av on rav.attribute_value_id = av.id
LEFT JOIN attribute_fqns fqns on av.id = fqns.value_id
WHERE
    (sqlc.narg('id')::uuid IS NULL OR v.id = sqlc.narg('id')::uuid) AND
    (sqlc.narg('name')::text IS NULL OR r.name = sqlc.narg('name')::text) AND
    (sqlc.narg('value')::text IS NULL OR v.value = sqlc.narg('value')::text) AND
    (sqlc.narg('namespace_fqn')::text IS NULL OR ns_fqns.fqn = sqlc.narg('namespace_fqn')::text)
GROUP BY v.id, r.name, n.id, ns_fqns.fqn;

-- name: listRegisteredResourceValues :many
WITH counted AS (
    SELECT COUNT(v.id) AS total
    FROM registered_resource_values v
    WHERE sqlc.narg('registered_resource_id')::uuid IS NULL OR v.registered_resource_id = sqlc.narg('registered_resource_id')::uuid
)
SELECT
    v.id,
    v.registered_resource_id,
    v.value,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', v.metadata -> 'labels', 'created_at', v.created_at, 'updated_at', v.updated_at)) as metadata,
    CASE WHEN n.id IS NOT NULL THEN
        JSON_BUILD_OBJECT(
            'id', n.id,
            'name', n.name,
            'fqn', ns_fqns.fqn
        )
    ELSE NULL END as namespace,
    r.name as resource_name,
    JSON_AGG(
    	JSON_BUILD_OBJECT(
    		'action', JSON_BUILD_OBJECT(
    			'id', a.id,
    			'name', a.name
    		),
    		'attribute_value', JSON_BUILD_OBJECT(
    			'id', av.id,
    			'value', av.value,
    			'fqn', fqns.fqn
    		)
    	)
    ) FILTER (WHERE rav.id IS NOT NULL) as action_attribute_values,
    counted.total
FROM registered_resource_values v
JOIN registered_resources r ON v.registered_resource_id = r.id
LEFT JOIN attribute_namespaces n ON r.namespace_id = n.id
LEFT JOIN attribute_fqns ns_fqns ON ns_fqns.namespace_id = n.id AND ns_fqns.attribute_id IS NULL AND ns_fqns.value_id IS NULL
LEFT JOIN registered_resource_action_attribute_values rav ON v.id = rav.registered_resource_value_id
LEFT JOIN actions a on rav.action_id = a.id
LEFT JOIN attribute_values av on rav.attribute_value_id = av.id
LEFT JOIN attribute_fqns fqns on av.id = fqns.value_id
CROSS JOIN counted
WHERE
    sqlc.narg('registered_resource_id')::uuid IS NULL OR v.registered_resource_id = sqlc.narg('registered_resource_id')::uuid
GROUP BY v.id, r.name, n.id, ns_fqns.fqn, counted.total
ORDER BY v.created_at DESC
LIMIT @limit_
OFFSET @offset_;

-- name: updateRegisteredResourceValue :execrows
UPDATE registered_resource_values
SET
    value = COALESCE(sqlc.narg('value'), value),
    metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE id = $1;

-- name: deleteRegisteredResourceValue :execrows
DELETE FROM registered_resource_values WHERE id = $1;

----------------------------------------------------------------
-- Registered Resource Action Attribute Values
----------------------------------------------------------------

-- name: getRegisteredResourceNamespaceIDByValueID :one
SELECT rr.namespace_id
FROM registered_resources rr
JOIN registered_resource_values rrv ON rrv.registered_resource_id = rr.id
WHERE rrv.id = $1;

-- name: createRegisteredResourceActionAttributeValues :copyfrom
INSERT INTO registered_resource_action_attribute_values (registered_resource_value_id, action_id, attribute_value_id)
VALUES ($1, $2, $3);

-- name: deleteRegisteredResourceActionAttributeValues :execrows
DELETE FROM registered_resource_action_attribute_values
WHERE registered_resource_value_id = $1;
