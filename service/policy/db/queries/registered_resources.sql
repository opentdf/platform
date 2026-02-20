----------------------------------------------------------------
-- REGISTERED RESOURCES
----------------------------------------------------------------

-- name: createRegisteredResource :one
INSERT INTO registered_resources (name, metadata)
VALUES ($1, $2)
RETURNING id;

-- name: getRegisteredResource :one
SELECT
    r.id,
    r.name,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', r.metadata -> 'labels', 'created_at', r.created_at, 'updated_at', r.updated_at)) as metadata,
    JSON_AGG(
        JSON_BUILD_OBJECT(
            'id', v.id,
            'value', v.value
        )
    ) FILTER (WHERE v.id IS NOT NULL) as values
FROM registered_resources r
LEFT JOIN registered_resource_values v ON v.registered_resource_id = r.id
WHERE
    (sqlc.narg('id')::uuid IS NULL OR r.id = sqlc.narg('id')::uuid) AND
    (sqlc.narg('name')::text IS NULL OR r.name = sqlc.narg('name')::text)
GROUP BY r.id;

-- name: listRegisteredResources :many
WITH counted AS (
    SELECT COUNT(id) AS total
    FROM registered_resources
)
SELECT
    r.id,
    r.name,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', r.metadata -> 'labels', 'created_at', r.created_at, 'updated_at', r.updated_at)) as metadata,
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
CROSS JOIN counted
LEFT JOIN registered_resource_values v ON v.registered_resource_id = r.id
-- Build a JSON array of action/attribute pairs for each resource value
LEFT JOIN LATERAL (
    SELECT JSON_AGG(
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
    ) AS values
    -- Join to get all action-attribute relationships for this resource value
    FROM registered_resource_action_attribute_values rav
    LEFT JOIN actions a on rav.action_id = a.id
    LEFT JOIN attribute_values av on rav.attribute_value_id = av.id
    LEFT JOIN attribute_fqns fqns on av.id = fqns.value_id
    -- Correlate to the outer query's resource value
    WHERE rav.registered_resource_value_id = v.id
) action_attrs ON true  -- required syntax for LATERAL joins
GROUP BY r.id, counted.total
ORDER BY r.created_at DESC
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
LEFT JOIN registered_resource_action_attribute_values rav ON v.id = rav.registered_resource_value_id
LEFT JOIN actions a on rav.action_id = a.id
LEFT JOIN attribute_values av on rav.attribute_value_id = av.id
LEFT JOIN attribute_fqns fqns on av.id = fqns.value_id
WHERE
    (sqlc.narg('id')::uuid IS NULL OR v.id = sqlc.narg('id')::uuid) AND
    (sqlc.narg('name')::text IS NULL OR r.name = sqlc.narg('name')::text) AND
    (sqlc.narg('value')::text IS NULL OR v.value = sqlc.narg('value')::text)
GROUP BY v.id;

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
LEFT JOIN registered_resource_action_attribute_values rav ON v.id = rav.registered_resource_value_id
LEFT JOIN actions a on rav.action_id = a.id
LEFT JOIN attribute_values av on rav.attribute_value_id = av.id
LEFT JOIN attribute_fqns fqns on av.id = fqns.value_id  
CROSS JOIN counted
WHERE
    sqlc.narg('registered_resource_id')::uuid IS NULL OR v.registered_resource_id = sqlc.narg('registered_resource_id')::uuid
GROUP BY v.id, counted.total
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

-- name: createRegisteredResourceActionAttributeValues :copyfrom
INSERT INTO registered_resource_action_attribute_values (registered_resource_value_id, action_id, attribute_value_id)
VALUES ($1, $2, $3);

-- name: deleteRegisteredResourceActionAttributeValues :execrows
DELETE FROM registered_resource_action_attribute_values
WHERE registered_resource_value_id = $1;
