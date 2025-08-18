----------------------------------------------------------------
-- OBLIGATIONS
----------------------------------------------------------------

-- name: createObligation :one
WITH inserted_obligation AS (
    INSERT INTO obligation_definitions (namespace_id, name, metadata)
    SELECT 
        CASE 
            WHEN @namespace_id::TEXT != '' THEN @namespace_id::UUID
            ELSE fqns.namespace_id
        END,
        @name, 
        @metadata
    FROM (
        SELECT 
            CASE 
                WHEN @namespace_id::TEXT != '' THEN @namespace_id::UUID
                ELSE NULL
            END as direct_namespace_id
    ) direct
    LEFT JOIN attribute_fqns fqns ON fqns.fqn = @namespace_fqn AND @namespace_id::TEXT = ''
    WHERE 
        (@namespace_id::TEXT != '' AND direct.direct_namespace_id IS NOT NULL) OR
        (@namespace_fqn::TEXT != '' AND fqns.namespace_id IS NOT NULL)
    RETURNING id, namespace_id, name, metadata
),
inserted_values AS (
    INSERT INTO obligation_values_standard (obligation_definition_id, value)
    SELECT io.id, UNNEST(@values::VARCHAR[])
    FROM inserted_obligation io
    WHERE @values::VARCHAR[] IS NOT NULL AND array_length(@values::VARCHAR[], 1) > 0
    RETURNING id, obligation_definition_id, value
)
SELECT
    io.id,
    io.name,
    io.metadata,
    JSON_BUILD_OBJECT(
        'id', n.id,
        'name', n.name,
        'fqn', fqns.fqn
    ) as namespace,
    COALESCE(
        JSON_AGG(
            JSON_BUILD_OBJECT(
                'id', iv.id,
                'value', iv.value
            )
        ) FILTER (WHERE iv.id IS NOT NULL),
        '[]'::JSON
    )::JSONB as values
FROM inserted_obligation io
JOIN attribute_namespaces n ON io.namespace_id = n.id
LEFT JOIN attribute_fqns fqns ON fqns.namespace_id = n.id AND fqns.attribute_id IS NULL AND fqns.value_id IS NULL
LEFT JOIN inserted_values iv ON iv.obligation_definition_id = io.id
GROUP BY io.id, io.name, io.metadata, n.id, fqns.fqn;

-- name: getObligation :one
SELECT
    od.id,
    od.name,
    JSON_BUILD_OBJECT(
        'id', n.id,
        'name', n.name,
        'fqn', fqns.fqn
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
LEFT JOIN attribute_fqns fqns ON fqns.namespace_id = n.id AND fqns.attribute_id IS NULL AND fqns.value_id IS NULL
LEFT JOIN obligation_values_standard ov on od.id = ov.obligation_definition_id
WHERE
    -- lookup by obligation id OR by namespace fqn + obligation name
    (
        -- lookup by obligation id
        (NULLIF(@id::TEXT, '') IS NOT NULL AND od.id = @id::UUID)
        OR
        -- lookup by namespace fqn + obligation name
        (NULLIF(@namespace_fqn::TEXT, '') IS NOT NULL AND NULLIF(@name::TEXT, '') IS NOT NULL 
         AND fqns.fqn = @namespace_fqn::VARCHAR AND od.name = @name::VARCHAR)
    )
GROUP BY od.id, n.id, fqns.fqn;

-- name: listObligations :many
WITH counted AS (
    SELECT COUNT(od.id) AS total
    FROM obligation_definitions od
    LEFT JOIN attribute_namespaces n ON od.namespace_id = n.id
    LEFT JOIN attribute_fqns fqns ON fqns.namespace_id = n.id AND fqns.attribute_id IS NULL AND fqns.value_id IS NULL
    WHERE
        (NULLIF(@namespace_id::TEXT, '') IS NULL OR od.namespace_id = @namespace_id::UUID) AND
        (NULLIF(@namespace_fqn::TEXT, '') IS NULL OR fqns.fqn = @namespace_fqn::VARCHAR)
)
SELECT
    od.id,
    od.name,
    JSON_BUILD_OBJECT(
        'id', n.id,
        'name', n.name,
        'fqn', fqns.fqn
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
LEFT JOIN attribute_fqns fqns ON fqns.namespace_id = n.id AND fqns.attribute_id IS NULL AND fqns.value_id IS NULL
CROSS JOIN counted
LEFT JOIN obligation_values_standard ov on od.id = ov.obligation_definition_id
WHERE
    (NULLIF(@namespace_id::TEXT, '') IS NULL OR od.namespace_id = @namespace_id::UUID) AND
    (NULLIF(@namespace_fqn::TEXT, '') IS NULL OR fqns.fqn = @namespace_fqn::VARCHAR)
GROUP BY od.id, n.id, fqns.fqn, counted.total
LIMIT @limit_
OFFSET @offset_;

-- name: updateObligation :execrows
UPDATE obligation_definitions
SET
    name = COALESCE(NULLIF(@name::TEXT, ''), name),
    metadata = COALESCE(@metadata, metadata)
WHERE id = @id;

-- name: deleteObligation :one
DELETE FROM obligation_definitions 
WHERE id IN (
    SELECT od.id
    FROM obligation_definitions od
    LEFT JOIN attribute_namespaces n ON od.namespace_id = n.id
    LEFT JOIN attribute_fqns fqns ON fqns.namespace_id = n.id AND fqns.attribute_id IS NULL AND fqns.value_id IS NULL
    WHERE
        -- lookup by obligation id OR by namespace fqn + obligation name
        (
            -- lookup by obligation id
            (NULLIF(@id::TEXT, '') IS NOT NULL AND od.id = @id::UUID)
            OR
            -- lookup by namespace fqn + obligation name
            (NULLIF(@namespace_fqn::TEXT, '') IS NOT NULL AND NULLIF(@name::TEXT, '') IS NOT NULL 
             AND fqns.fqn = @namespace_fqn::VARCHAR AND od.name = @name::VARCHAR)
        )
)
RETURNING id;

-- name: getObligationsByFQNs :many
SELECT
    od.id,
    od.name,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', od.metadata -> 'labels', 'created_at', od.created_at,'updated_at', od.updated_at)) as metadata,
    JSON_BUILD_OBJECT(
        'id', n.id,
        'name', n.name,
        'fqn', fqns.fqn
    ) as namespace,
    COALESCE(
        JSON_AGG(
            JSON_BUILD_OBJECT(
                'id', ov.id,
                'value', ov.value
            )
        ) FILTER (WHERE ov.id IS NOT NULL),
        '[]'::JSON
    )::JSONB as values
FROM
    obligation_definitions od
JOIN
    attribute_namespaces n on od.namespace_id = n.id
JOIN
    attribute_fqns fqns ON fqns.namespace_id = n.id AND fqns.attribute_id IS NULL AND fqns.value_id IS NULL
JOIN
    (SELECT unnest(@namespace_fqns::text[]) as ns_fqn, unnest(@obligation_names::text[]) as obl_name) as fqn_pairs
ON
    fqns.fqn = fqn_pairs.ns_fqn AND od.name = fqn_pairs.obl_name
LEFT JOIN
    obligation_values_standard ov on od.id = ov.obligation_definition_id
GROUP BY
    od.id, n.id, fqns.fqn;
