----------------------------------------------------------------
-- OBLIGATIONS
----------------------------------------------------------------

-- name: createObligationByNamespaceID :one
WITH inserted_obligation AS (
    INSERT INTO obligation_definitions (namespace_id, name, metadata)
    VALUES ($1, $2, $3)
    RETURNING id, namespace_id, name, metadata
),
inserted_values AS (
    INSERT INTO obligation_values_standard (obligation_definition_id, value)
    SELECT io.id, UNNEST($4::VARCHAR[])
    FROM inserted_obligation io
    WHERE $4::VARCHAR[] IS NOT NULL AND array_length($4::VARCHAR[], 1) > 0
    RETURNING id, obligation_definition_id, value
)
SELECT
    io.id,
    io.name,
    io.metadata,
    COALESCE(
        JSON_AGG(
            JSON_BUILD_OBJECT(
                'id', iv.id,
                'value', iv.value
            )
        ) FILTER (WHERE iv.id IS NOT NULL),
        '[]'::JSON
    ) as values
FROM inserted_obligation io
LEFT JOIN inserted_values iv ON iv.obligation_definition_id = io.id
GROUP BY io.id, io.name, io.metadata;

-- name: createObligationByNamespaceFQN :one
WITH inserted_obligation AS (
    INSERT INTO obligation_definitions (namespace_id, name, metadata)
    SELECT fqns.namespace_id, $2, $3
    FROM attribute_fqns fqns
    WHERE fqns.fqn = $1
    RETURNING id, namespace_id, name, metadata
),
inserted_values AS (
    INSERT INTO obligation_values_standard (obligation_definition_id, value)
    SELECT io.id, UNNEST($4::VARCHAR[])
    FROM inserted_obligation io
    WHERE $4::VARCHAR[] IS NOT NULL AND array_length($4::VARCHAR[], 1) > 0
    RETURNING id, obligation_definition_id, value
)
SELECT
    io.id,
    io.name,
    io.metadata,
    COALESCE(
        JSON_AGG(
            JSON_BUILD_OBJECT(
                'id', iv.id,
                'value', iv.value
            )
        ) FILTER (WHERE iv.id IS NOT NULL),
        '[]'::JSON
    ) as values
FROM inserted_obligation io
LEFT JOIN inserted_values iv ON iv.obligation_definition_id = io.id
GROUP BY io.id, io.name, io.metadata;

-- name: getObligationDefinition :one
SELECT
    od.id,
    od.name,
    JSON_BUILD_OBJECT(
        'id', n.id,
        'name', n.name
    ) as namespace,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', od.metadata -> 'labels', 'created_at', od.created_at,'updated_at', od.updated_at)) as metadata,
    JSON_AGG(
        JSON_BUILD_OBJECT(
            'id', ov.id,
            'value', ov.value
        )
    ) FILTER (WHERE ov.id IS NOT NULL) as values
    -- todo: add triggers and fulfillers
FROM obligation_definitions od
JOIN attribute_namespaces n on od.namespace_id = n.id
LEFT JOIN obligation_values_standard ov on od.id = ov.obligation_definition_id
WHERE
    -- handles by id or fqn queries
    (NULLIF(@id, '') IS NULL OR id = @id::UUID) AND
    (NULLIF(@namespace_id, '') IS NULL OR od.namespace_id = @namespace_id::UUID) AND
    (NULLIF(@name, '') IS NULL OR name = @name::VARCHAR)
GROUP BY od.id, n.id;

-- name: listObligationDefinitions :many
WITH counted AS (
    SELECT COUNT(id) AS total
    FROM obligation_definitions
    WHERE
        (NULLIF(@namespace_id, '') IS NULL OR od.namespace_id = @namespace_id::UUID)
)
SELECT
    od.id,
    od.name,
    JSON_BUILD_OBJECT(
        'id', n.id,
        'name', n.name
    ) as namespace,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', od.metadata -> 'labels', 'created_at', od.created_at,'updated_at', od.updated_at)) as metadata,
    JSON_AGG(
        JSON_BUILD_OBJECT(
            'id', ov.id,
            'value', ov.value
        )
    ) FILTER (WHERE ov.id IS NOT NULL) as values,
    -- todo: add triggers and fulfillers
    counted.total
FROM obligation_definitions od
JOIN attribute_namespaces n on od.namespace_id = n.id
CROSS JOIN counted
LEFT JOIN obligation_values_standard ov on od.id = ov.obligation_definition_id
WHERE
    (NULLIF(@namespace_id, '') IS NULL OR od.namespace_id = @namespace_id::UUID)
GROUP BY od.id, n.id, counted.total
LIMIT @limit_
OFFSET @offset_;

-- name: updateObligationDefinition :execrows
UPDATE obligation_definitions
SET
    name = COALESCE(sqlc.narg('name'), name),
    metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE id = $1;

-- name: deleteObligationDefinition :execrows
DELETE FROM obligation_definitions WHERE id = $1;
