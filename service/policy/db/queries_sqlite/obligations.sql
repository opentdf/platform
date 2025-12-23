----------------------------------------------------------------
-- OBLIGATIONS (SQLite)
-- Note: Some complex multi-table inserts with UNNEST simplified
-- App layer handles value insertion separately
----------------------------------------------------------------

-- name: createObligation :one
-- Note: ID generated in application layer. Values created separately via createObligationValue
INSERT INTO obligation_definitions (id, namespace_id, name, metadata)
VALUES (@id, @namespace_id, @name, @metadata)
RETURNING id;

-- name: getObligation :one
SELECT
    od.id,
    od.name,
    json_object(
        'id', n.id,
        'name', n.name,
        'fqn', fqns.fqn
    ) as namespace,
    json_object(
        'labels', json_extract(od.metadata, '$.labels'),
        'created_at', od.created_at,
        'updated_at', od.updated_at
    ) as metadata,
    -- Values with triggers as subquery
    (
        SELECT json_group_array(
            json_object(
                'id', ov.id,
                'value', ov.value,
                'triggers', (
                    SELECT json_group_array(
                        json_object(
                            'id', ot.id,
                            'action', json_object('id', a.id, 'name', a.name),
                            'attribute_value', json_object(
                                'id', av.id,
                                'value', av.value,
                                'fqn', COALESCE(av_fqns.fqn, '')
                            ),
                            'context', CASE
                                WHEN ot.client_id IS NOT NULL THEN json_array(
                                    json_object('pep', json_object('client_id', ot.client_id))
                                )
                                ELSE json_array()
                            END
                        )
                    )
                    FROM obligation_triggers ot
                    JOIN actions a ON ot.action_id = a.id
                    JOIN attribute_values av ON ot.attribute_value_id = av.id
                    LEFT JOIN attribute_fqns av_fqns ON av_fqns.value_id = av.id
                    WHERE ot.obligation_value_id = ov.id
                )
            )
        )
        FROM obligation_values_standard ov
        WHERE ov.obligation_definition_id = od.id
    ) as "values"
FROM obligation_definitions od
JOIN attribute_namespaces n on od.namespace_id = n.id
LEFT JOIN attribute_fqns fqns ON fqns.namespace_id = n.id AND fqns.attribute_id IS NULL AND fqns.value_id IS NULL
WHERE
    (NULLIF(@id, '') IS NULL OR od.id = @id)
    OR
    (NULLIF(@namespace_fqn, '') IS NOT NULL AND NULLIF(@name, '') IS NOT NULL
     AND fqns.fqn = @namespace_fqn AND od.name = @name);

-- name: listObligations :many
WITH counted AS (
    SELECT COUNT(od.id) AS total
    FROM obligation_definitions od
    LEFT JOIN attribute_namespaces n ON od.namespace_id = n.id
    LEFT JOIN attribute_fqns fqns ON fqns.namespace_id = n.id AND fqns.attribute_id IS NULL AND fqns.value_id IS NULL
    WHERE
        (NULLIF(@namespace_id, '') IS NULL OR od.namespace_id = @namespace_id) AND
        (NULLIF(@namespace_fqn, '') IS NULL OR fqns.fqn = @namespace_fqn)
)
SELECT
    od.id,
    od.name,
    json_object(
        'id', n.id,
        'name', n.name,
        'fqn', fqns.fqn
    ) as namespace,
    json_object(
        'labels', json_extract(od.metadata, '$.labels'),
        'created_at', od.created_at,
        'updated_at', od.updated_at
    ) as metadata,
    -- Values as subquery
    (
        SELECT json_group_array(
            json_object(
                'id', ov.id,
                'value', ov.value
            )
        )
        FROM obligation_values_standard ov
        WHERE ov.obligation_definition_id = od.id
    ) as "values",
    counted.total
FROM obligation_definitions od
JOIN attribute_namespaces n on od.namespace_id = n.id
LEFT JOIN attribute_fqns fqns ON fqns.namespace_id = n.id AND fqns.attribute_id IS NULL AND fqns.value_id IS NULL
CROSS JOIN counted
WHERE
    (NULLIF(@namespace_id, '') IS NULL OR od.namespace_id = @namespace_id) AND
    (NULLIF(@namespace_fqn, '') IS NULL OR fqns.fqn = @namespace_fqn)
GROUP BY od.id, n.id, fqns.fqn, counted.total
LIMIT @limit_
OFFSET @offset_;

-- name: updateObligation :execrows
UPDATE obligation_definitions
SET
    name = COALESCE(NULLIF(@name, ''), name),
    metadata = COALESCE(@metadata, metadata)
WHERE id = @id;

-- name: deleteObligation :execrows
DELETE FROM obligation_definitions
WHERE id = @id;

-- name: getObligationsByFQNs :many
-- Note: Uses json_each instead of unnest for array matching
SELECT
    od.id,
    od.name,
    json_object(
        'labels', json_extract(od.metadata, '$.labels'),
        'created_at', od.created_at,
        'updated_at', od.updated_at
    ) as metadata,
    json_object(
        'id', n.id,
        'name', n.name,
        'fqn', fqns.fqn
    ) as namespace,
    (
        SELECT json_group_array(
            json_object('id', ov.id, 'value', ov.value)
        )
        FROM obligation_values_standard ov
        WHERE ov.obligation_definition_id = od.id
    ) as "values"
FROM obligation_definitions od
JOIN attribute_namespaces n on od.namespace_id = n.id
JOIN attribute_fqns fqns ON fqns.namespace_id = n.id AND fqns.attribute_id IS NULL AND fqns.value_id IS NULL
WHERE EXISTS (
    SELECT 1
    FROM json_each(@namespace_fqns) nf, json_each(@names) nm
    WHERE nf.key = nm.key AND fqns.fqn = nf.value AND od.name = nm.value
);

----------------------------------------------------------------
-- OBLIGATION VALUES (SQLite)
----------------------------------------------------------------

-- name: createObligationValue :one
-- Note: ID generated in application layer before INSERT
INSERT INTO obligation_values_standard (id, obligation_definition_id, value, metadata)
VALUES (@id, @obligation_definition_id, @value, @metadata)
RETURNING id;

-- name: getObligationValue :one
SELECT
    ov.id,
    ov.value,
    od.id as obligation_id,
    od.name,
    json_object(
        'id', n.id,
        'name', n.name,
        'fqn', fqns.fqn
    ) as namespace,
    json_object(
        'labels', json_extract(ov.metadata, '$.labels'),
        'created_at', ov.created_at,
        'updated_at', ov.updated_at
    ) as metadata,
    -- Triggers as subquery
    (
        SELECT json_group_array(
            json_object(
                'id', ot.id,
                'action', json_object('id', a.id, 'name', a.name),
                'attribute_value', json_object(
                    'id', av.id,
                    'value', av.value,
                    'fqn', COALESCE(av_fqns.fqn, '')
                ),
                'context', CASE
                    WHEN ot.client_id IS NOT NULL THEN json_array(
                        json_object('pep', json_object('client_id', ot.client_id))
                    )
                    ELSE json_array()
                END
            )
        )
        FROM obligation_triggers ot
        JOIN actions a ON ot.action_id = a.id
        JOIN attribute_values av ON ot.attribute_value_id = av.id
        LEFT JOIN attribute_fqns av_fqns ON av_fqns.value_id = av.id
        WHERE ot.obligation_value_id = ov.id
    ) as triggers
FROM obligation_values_standard ov
JOIN obligation_definitions od ON ov.obligation_definition_id = od.id
JOIN attribute_namespaces n ON od.namespace_id = n.id
LEFT JOIN attribute_fqns fqns ON fqns.namespace_id = n.id AND fqns.attribute_id IS NULL AND fqns.value_id IS NULL
WHERE
    (NULLIF(@id, '') IS NOT NULL AND ov.id = @id)
    OR
    (NULLIF(@namespace_fqn, '') IS NOT NULL AND NULLIF(@name, '') IS NOT NULL AND NULLIF(@value, '') IS NOT NULL
     AND fqns.fqn = @namespace_fqn AND od.name = @name AND ov.value = @value);

-- name: updateObligationValue :execrows
UPDATE obligation_values_standard
SET
    value = COALESCE(NULLIF(@value, ''), value),
    metadata = COALESCE(@metadata, metadata)
WHERE id = @id;

-- name: deleteObligationValue :execrows
DELETE FROM obligation_values_standard
WHERE id = @id;

-- name: getObligationValuesByFQNs :many
-- Note: Uses json_each instead of unnest for array matching
SELECT
    ov.id,
    ov.value,
    json_object(
        'labels', json_extract(ov.metadata, '$.labels'),
        'created_at', ov.created_at,
        'updated_at', ov.updated_at
    ) as metadata,
    od.id as obligation_id,
    od.name as name,
    json_object(
        'id', n.id,
        'name', n.name,
        'fqn', fqns.fqn
    ) as namespace
FROM obligation_values_standard ov
JOIN obligation_definitions od ON ov.obligation_definition_id = od.id
JOIN attribute_namespaces n ON od.namespace_id = n.id
JOIN attribute_fqns fqns ON fqns.namespace_id = n.id AND fqns.attribute_id IS NULL AND fqns.value_id IS NULL
WHERE EXISTS (
    SELECT 1
    FROM json_each(@namespace_fqns) nf, json_each(@names) nm, json_each(@values) vv
    WHERE nf.key = nm.key AND nm.key = vv.key
      AND fqns.fqn = nf.value AND od.name = nm.value AND ov.value = vv.value
);

----------------------------------------------------------------
-- OBLIGATION TRIGGERS (SQLite)
----------------------------------------------------------------

-- name: createObligationTrigger :one
-- Note: ID generated in application layer before INSERT
INSERT INTO obligation_triggers (id, obligation_value_id, action_id, attribute_value_id, metadata, client_id)
VALUES (@id, @obligation_value_id, @action_id, @attribute_value_id, @metadata, NULLIF(@client_id, ''))
RETURNING id;

-- name: getObligationTrigger :one
SELECT
    ot.id,
    ot.obligation_value_id,
    ot.action_id,
    ot.attribute_value_id,
    ot.client_id,
    json_object(
        'labels', json_extract(ot.metadata, '$.labels'),
        'created_at', ot.created_at,
        'updated_at', ot.updated_at
    ) as metadata
FROM obligation_triggers ot
WHERE ot.id = @id;

-- name: deleteAllObligationTriggersForValue :execrows
DELETE FROM obligation_triggers
WHERE obligation_value_id = @obligation_value_id;

-- name: deleteObligationTrigger :execrows
DELETE FROM obligation_triggers
WHERE id = @id;

-- name: listObligationTriggers :many
-- Note: Flattened structure - app layer assembles JSON response
SELECT
    ot.id,
    ot.obligation_value_id,
    ov.value as obligation_value_value,
    od.id as obligation_id,
    od.name as obligation_name,
    n.id as namespace_id,
    n.name as namespace_name,
    COALESCE(ns_fqns.fqn, '') as namespace_fqn,
    a.id as action_id,
    a.name as action_name,
    av.id as attribute_value_id,
    av.value as attribute_value_value,
    COALESCE(av_fqns.fqn, '') as attribute_value_fqn,
    ot.client_id,
    ot.metadata,
    ot.created_at,
    ot.updated_at,
    COUNT(*) OVER() as total
FROM obligation_triggers ot
JOIN obligation_values_standard ov ON ot.obligation_value_id = ov.id
JOIN obligation_definitions od ON ov.obligation_definition_id = od.id
JOIN attribute_namespaces n ON od.namespace_id = n.id
LEFT JOIN attribute_fqns ns_fqns ON ns_fqns.namespace_id = n.id AND ns_fqns.attribute_id IS NULL AND ns_fqns.value_id IS NULL
JOIN actions a ON ot.action_id = a.id
JOIN attribute_values av ON ot.attribute_value_id = av.id
LEFT JOIN attribute_fqns av_fqns ON av_fqns.value_id = av.id
WHERE
    (NULLIF(@namespace_id, '') IS NULL OR od.namespace_id = @namespace_id) AND
    (NULLIF(@namespace_fqn, '') IS NULL OR ns_fqns.fqn = @namespace_fqn)
ORDER BY ot.created_at DESC
LIMIT @limit_
OFFSET @offset_;
