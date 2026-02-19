---------------------------------------------------------------- 
-- SUBJECT CONDITION SETS
----------------------------------------------------------------

-- name: listSubjectConditionSets :many
WITH counted AS (
    SELECT COUNT(scs.id) AS total
    FROM subject_condition_set scs
)
SELECT
    scs.id,
    scs.condition,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', scs.metadata -> 'labels', 'created_at', scs.created_at, 'updated_at', scs.updated_at)) as metadata,
    counted.total
FROM subject_condition_set scs
CROSS JOIN counted
ORDER BY scs.created_at DESC
LIMIT @limit_ 
OFFSET @offset_; 

-- name: getSubjectConditionSet :one
SELECT
    id,
    condition,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', metadata -> 'labels', 'created_at', created_at, 'updated_at', updated_at)) as metadata
FROM subject_condition_set
WHERE id = $1;

-- name: createSubjectConditionSet :one
INSERT INTO subject_condition_set (condition, metadata)
VALUES ($1, $2)
RETURNING id;

-- name: updateSubjectConditionSet :execrows
UPDATE subject_condition_set
SET
    condition = COALESCE(sqlc.narg('condition'), condition),
    metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE id = $1;

-- name: deleteSubjectConditionSet :execrows
DELETE FROM subject_condition_set WHERE id = $1;

-- name: deleteAllUnmappedSubjectConditionSets :many
DELETE FROM subject_condition_set
WHERE id NOT IN (SELECT DISTINCT sm.subject_condition_set_id FROM subject_mappings sm)
RETURNING id;

---------------------------------------------------------------- 
-- SUBJECT MAPPINGS
----------------------------------------------------------------

-- name: listSubjectMappings :many
WITH subject_actions AS (
    SELECT
        sma.subject_mapping_id,
        COALESCE(
            JSONB_AGG(JSONB_BUILD_OBJECT('id', a.id, 'name', a.name)) FILTER (WHERE a.is_standard = TRUE),
            '[]'::JSONB
        ) AS standard_actions,
        COALESCE(
            JSONB_AGG(JSONB_BUILD_OBJECT('id', a.id, 'name', a.name)) FILTER (WHERE a.is_standard = FALSE),
            '[]'::JSONB
        ) AS custom_actions
    FROM subject_mapping_actions sma
    JOIN actions a ON sma.action_id = a.id
    GROUP BY sma.subject_mapping_id
), counted AS (
    SELECT COUNT(sm.id) AS total
    FROM subject_mappings sm
)
SELECT
    sm.id,
    sa.standard_actions,
    sa.custom_actions,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', sm.metadata -> 'labels', 'created_at', sm.created_at, 'updated_at', sm.updated_at)) AS metadata,
    JSON_BUILD_OBJECT(
        'id', scs.id,
        'metadata', JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', scs.metadata->'labels', 'created_at', scs.created_at, 'updated_at', scs.updated_at)),
        'subject_sets', scs.condition
    ) AS subject_condition_set,
    JSON_BUILD_OBJECT(
        'id', av.id,
        'value', av.value,
        'active', av.active,
        'fqn', fqns.fqn
    ) AS attribute_value,
    counted.total
FROM subject_mappings sm
CROSS JOIN counted
LEFT JOIN subject_actions sa ON sm.id = sa.subject_mapping_id
LEFT JOIN attribute_values av ON sm.attribute_value_id = av.id
LEFT JOIN attribute_fqns fqns ON av.id = fqns.value_id
LEFT JOIN subject_condition_set scs ON scs.id = sm.subject_condition_set_id
GROUP BY
    sm.id,
    sa.standard_actions,
    sa.custom_actions,
    sm.metadata, sm.created_at, sm.updated_at, -- for metadata object
    scs.id, scs.metadata, scs.created_at, scs.updated_at, scs.condition, -- for subject_condition_set object
    av.id, av.value, av.active, -- for attribute_value object
    fqns.fqn,
    counted.total
ORDER BY sm.created_at DESC
LIMIT @limit_
OFFSET @offset_;

-- name: getSubjectMapping :one
SELECT
    sm.id,
    (
        SELECT JSONB_AGG(JSONB_BUILD_OBJECT('id', a.id, 'name', a.name))
        FROM actions a
        JOIN subject_mapping_actions sma ON sma.action_id = a.id
        WHERE sma.subject_mapping_id = sm.id AND a.is_standard = TRUE
    ) AS standard_actions,
    (
        SELECT JSONB_AGG(JSONB_BUILD_OBJECT('id', a.id, 'name', a.name))
        FROM actions a
        JOIN subject_mapping_actions sma ON sma.action_id = a.id
        WHERE sma.subject_mapping_id = sm.id AND a.is_standard = FALSE
    ) AS custom_actions,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', sm.metadata -> 'labels', 'created_at', sm.created_at, 'updated_at', sm.updated_at)) AS metadata,
    JSON_BUILD_OBJECT(
        'id', scs.id,
        'metadata', JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', scs.metadata -> 'labels', 'created_at', scs.created_at, 'updated_at', scs.updated_at)),
        'subject_sets', scs.condition
    ) AS subject_condition_set,
    JSON_BUILD_OBJECT('id', av.id,'value', av.value,'active', av.active) AS attribute_value
FROM subject_mappings sm
LEFT JOIN attribute_values av ON sm.attribute_value_id = av.id
LEFT JOIN subject_condition_set scs ON scs.id = sm.subject_condition_set_id
WHERE sm.id = $1
GROUP BY av.id, sm.id, scs.id;

-- name: matchSubjectMappings :many
WITH subject_actions AS (
    SELECT
        sma.subject_mapping_id,
        COALESCE(
            JSONB_AGG(JSONB_BUILD_OBJECT('id', a.id, 'name', a.name)) FILTER (WHERE a.is_standard = TRUE),
            '[]'::JSONB
        ) AS standard_actions,
        COALESCE(
            JSONB_AGG(JSONB_BUILD_OBJECT('id', a.id, 'name', a.name)) FILTER (WHERE a.is_standard = FALSE),
            '[]'::JSONB
        ) AS custom_actions
    FROM subject_mapping_actions sma
    JOIN actions a ON sma.action_id = a.id
    GROUP BY sma.subject_mapping_id
)
SELECT
    sm.id,
    sa.standard_actions,
    sa.custom_actions,
    JSON_BUILD_OBJECT(
        'id', scs.id,
        'subject_sets', scs.condition
    ) AS subject_condition_set,
    JSON_BUILD_OBJECT(
        'id', av.id,
        'value', av.value,
        'active', av.active,
        'fqn', fqns.fqn
    ) AS attribute_value
FROM subject_mappings sm
LEFT JOIN subject_actions sa ON sm.id = sa.subject_mapping_id
LEFT JOIN attribute_values av ON sm.attribute_value_id = av.id
LEFT JOIN attribute_definitions ad ON av.attribute_definition_id = ad.id
LEFT JOIN attribute_namespaces ns ON ad.namespace_id = ns.id
LEFT JOIN attribute_fqns fqns ON av.id = fqns.value_id
LEFT JOIN subject_condition_set scs ON scs.id = sm.subject_condition_set_id
WHERE
    ns.active = TRUE
    AND ad.active = TRUE
    AND av.active = TRUE
    AND scs.selector_values && @selectors::TEXT[]
GROUP BY
    sm.id,
    sa.standard_actions,
    sa.custom_actions,
    scs.id, scs.condition,
    av.id, av.value, av.active, fqns.fqn;

-- name: createSubjectMapping :one
WITH inserted_mapping AS (
    INSERT INTO subject_mappings (
        attribute_value_id,
        metadata,
        subject_condition_set_id
    )
    VALUES ($1, $2, $3)
    RETURNING id
),
inserted_actions AS (
    INSERT INTO subject_mapping_actions (subject_mapping_id, action_id)
    SELECT 
        (SELECT id FROM inserted_mapping),
        unnest(sqlc.arg('action_ids')::uuid[])
)
SELECT id FROM inserted_mapping;

-- name: updateSubjectMapping :execrows
WITH
    subject_mapping_update AS (
        UPDATE subject_mappings
        SET
            metadata = COALESCE(sqlc.narg('metadata')::JSONB, metadata),
            subject_condition_set_id = COALESCE(sqlc.narg('subject_condition_set_id')::UUID, subject_condition_set_id)
        WHERE id = sqlc.arg('id')
        RETURNING id
    ),
    -- Delete any actions that are NOT in the new list
    action_delete AS (
        DELETE FROM subject_mapping_actions
        WHERE
            subject_mapping_id = sqlc.arg('id')
            AND sqlc.narg('action_ids')::UUID[] IS NOT NULL
            AND action_id NOT IN (SELECT unnest(sqlc.narg('action_ids')::UUID[]))
    ),
    -- Insert actions that are not already related to the mapping
    action_insert AS (
        INSERT INTO
            subject_mapping_actions (subject_mapping_id, action_id)
        SELECT
            sqlc.arg('id'),
            a
        FROM unnest(sqlc.narg('action_ids')::UUID[]) AS a
        WHERE
            sqlc.narg('action_ids')::UUID[] IS NOT NULL
            AND NOT EXISTS (
                SELECT 1
                FROM subject_mapping_actions
                WHERE subject_mapping_id = sqlc.arg('id') AND action_id = a
            )
    ),
    update_count AS (
        SELECT COUNT(*) AS cnt
        FROM subject_mapping_update
    )
SELECT cnt
FROM update_count;

-- name: deleteSubjectMapping :execrows
DELETE FROM subject_mappings WHERE id = $1;
