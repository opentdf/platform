----------------------------------------------------------------
-- REGISTERED RESOURCES (SQLite)
----------------------------------------------------------------

-- name: createRegisteredResource :one
-- Note: ID generated in application layer before INSERT
INSERT INTO registered_resources (id, name, metadata)
VALUES (@id, @name, @metadata)
RETURNING id;

-- name: getRegisteredResource :one
SELECT
    r.id,
    r.name,
    json_object(
        'labels', json_extract(r.metadata, '$.labels'),
        'created_at', r.created_at,
        'updated_at', r.updated_at
    ) as metadata,
    -- Values as correlated subquery (replaces JSON_AGG with FILTER)
    (
        SELECT json_group_array(
            json_object(
                'id', v.id,
                'value', v.value
            )
        )
        FROM registered_resource_values v
        WHERE v.registered_resource_id = r.id
    ) as "values"
FROM registered_resources r
WHERE
    (NULLIF(@id, '') IS NULL OR r.id = @id) AND
    (NULLIF(@name, '') IS NULL OR r.name = @name);

-- name: listRegisteredResources :many
WITH counted AS (
    SELECT COUNT(id) AS total
    FROM registered_resources
)
SELECT
    r.id,
    r.name,
    json_object(
        'labels', json_extract(r.metadata, '$.labels'),
        'created_at', r.created_at,
        'updated_at', r.updated_at
    ) as metadata,
    -- Values with action_attribute_values as correlated subquery
    -- Note: SQLite doesn't support LATERAL, so we use a scalar subquery
    (
        SELECT json_group_array(
            json_object(
                'id', v.id,
                'value', v.value,
                'action_attribute_values', (
                    SELECT json_group_array(
                        json_object(
                            'action', json_object(
                                'id', a.id,
                                'name', a.name
                            ),
                            'attribute_value', json_object(
                                'id', av.id,
                                'value', av.value,
                                'fqn', fqns.fqn
                            )
                        )
                    )
                    FROM registered_resource_action_attribute_values rav
                    LEFT JOIN actions a on rav.action_id = a.id
                    LEFT JOIN attribute_values av on rav.attribute_value_id = av.id
                    LEFT JOIN attribute_fqns fqns on av.id = fqns.value_id
                    WHERE rav.registered_resource_value_id = v.id
                )
            )
        )
        FROM registered_resource_values v
        WHERE v.registered_resource_id = r.id
    ) as "values",
    counted.total
FROM registered_resources r
CROSS JOIN counted
GROUP BY r.id, counted.total
LIMIT @limit_
OFFSET @offset_;

-- name: updateRegisteredResource :execrows
UPDATE registered_resources
SET
    name = COALESCE(sqlc.narg('name'), name),
    metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE id = @id;

-- name: deleteRegisteredResource :execrows
DELETE FROM registered_resources WHERE id = @id;


----------------------------------------------------------------
-- REGISTERED RESOURCE VALUES (SQLite)
----------------------------------------------------------------

-- name: createRegisteredResourceValue :one
-- Note: ID generated in application layer before INSERT
INSERT INTO registered_resource_values (id, registered_resource_id, value, metadata)
VALUES (@id, @registered_resource_id, @value, @metadata)
RETURNING id;

-- name: getRegisteredResourceValue :one
SELECT
    v.id,
    v.registered_resource_id,
    v.value,
    json_object(
        'labels', json_extract(v.metadata, '$.labels'),
        'created_at', v.created_at,
        'updated_at', v.updated_at
    ) as metadata,
    -- Action attribute values as correlated subquery
    (
        SELECT json_group_array(
            json_object(
                'action', json_object(
                    'id', a.id,
                    'name', a.name
                ),
                'attribute_value', json_object(
                    'id', av.id,
                    'value', av.value,
                    'fqn', fqns.fqn
                )
            )
        )
        FROM registered_resource_action_attribute_values rav
        LEFT JOIN actions a on rav.action_id = a.id
        LEFT JOIN attribute_values av on rav.attribute_value_id = av.id
        LEFT JOIN attribute_fqns fqns on av.id = fqns.value_id
        WHERE rav.registered_resource_value_id = v.id
    ) as action_attribute_values
FROM registered_resource_values v
JOIN registered_resources r ON v.registered_resource_id = r.id
WHERE
    (NULLIF(@id, '') IS NULL OR v.id = @id) AND
    (NULLIF(@name, '') IS NULL OR r.name = @name) AND
    (NULLIF(@value, '') IS NULL OR v.value = @value);

-- name: listRegisteredResourceValues :many
WITH counted AS (
    SELECT COUNT(id) AS total
    FROM registered_resource_values
    WHERE
        NULLIF(@registered_resource_id, '') IS NULL OR registered_resource_id = @registered_resource_id
)
SELECT
    v.id,
    v.registered_resource_id,
    v.value,
    json_object(
        'labels', json_extract(v.metadata, '$.labels'),
        'created_at', v.created_at,
        'updated_at', v.updated_at
    ) as metadata,
    -- Action attribute values as correlated subquery
    (
        SELECT json_group_array(
            json_object(
                'action', json_object(
                    'id', a.id,
                    'name', a.name
                ),
                'attribute_value', json_object(
                    'id', av.id,
                    'value', av.value,
                    'fqn', fqns.fqn
                )
            )
        )
        FROM registered_resource_action_attribute_values rav
        LEFT JOIN actions a on rav.action_id = a.id
        LEFT JOIN attribute_values av on rav.attribute_value_id = av.id
        LEFT JOIN attribute_fqns fqns on av.id = fqns.value_id
        WHERE rav.registered_resource_value_id = v.id
    ) as action_attribute_values,
    counted.total
FROM registered_resource_values v
JOIN registered_resources r ON v.registered_resource_id = r.id
CROSS JOIN counted
WHERE
    NULLIF(@registered_resource_id, '') IS NULL OR v.registered_resource_id = @registered_resource_id
GROUP BY v.id, counted.total
LIMIT @limit_
OFFSET @offset_;

-- name: updateRegisteredResourceValue :execrows
UPDATE registered_resource_values
SET
    value = COALESCE(sqlc.narg('value'), value),
    metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE id = @id;

-- name: deleteRegisteredResourceValue :execrows
DELETE FROM registered_resource_values WHERE id = @id;

----------------------------------------------------------------
-- Registered Resource Action Attribute Values (SQLite)
----------------------------------------------------------------

-- name: createRegisteredResourceActionAttributeValue :one
-- Note: ID generated in application layer before INSERT
INSERT INTO registered_resource_action_attribute_values (id, registered_resource_value_id, action_id, attribute_value_id)
VALUES (@id, @registered_resource_value_id, @action_id, @attribute_value_id)
RETURNING id;

-- name: deleteRegisteredResourceActionAttributeValues :execrows
DELETE FROM registered_resource_action_attribute_values
WHERE registered_resource_value_id = @registered_resource_value_id;
