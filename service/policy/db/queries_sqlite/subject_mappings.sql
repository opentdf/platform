----------------------------------------------------------------
-- SUBJECT CONDITION SETS (SQLite)
----------------------------------------------------------------

-- name: listSubjectConditionSets :many
WITH counted AS (
    SELECT COUNT(scs.id) AS total
    FROM subject_condition_set scs
)
SELECT
    scs.id,
    scs.condition,
    json_object(
        'labels', json_extract(scs.metadata, '$.labels'),
        'created_at', scs.created_at,
        'updated_at', scs.updated_at
    ) as metadata,
    counted.total
FROM subject_condition_set scs
CROSS JOIN counted
LIMIT @limit_
OFFSET @offset_;

-- name: getSubjectConditionSet :one
SELECT
    id,
    condition,
    json_object(
        'labels', json_extract(metadata, '$.labels'),
        'created_at', created_at,
        'updated_at', updated_at
    ) as metadata
FROM subject_condition_set
WHERE id = @id;

-- name: createSubjectConditionSet :one
-- Note: ID generated in application layer before INSERT
INSERT INTO subject_condition_set (id, condition, metadata)
VALUES (@id, @condition, @metadata)
RETURNING id;

-- name: updateSubjectConditionSet :execrows
UPDATE subject_condition_set
SET
    condition = COALESCE(sqlc.narg('condition'), condition),
    metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE id = @id;

-- name: deleteSubjectConditionSet :execrows
DELETE FROM subject_condition_set WHERE id = @id;

-- name: deleteAllUnmappedSubjectConditionSets :many
DELETE FROM subject_condition_set
WHERE id NOT IN (SELECT DISTINCT sm.subject_condition_set_id FROM subject_mappings sm WHERE sm.subject_condition_set_id IS NOT NULL)
RETURNING id;

----------------------------------------------------------------
-- SUBJECT MAPPINGS (SQLite)
----------------------------------------------------------------

-- name: listSubjectMappings :many
WITH counted AS (
    SELECT COUNT(sm.id) AS total
    FROM subject_mappings sm
)
SELECT
    sm.id,
    -- Standard actions as subquery
    (
        SELECT json_group_array(json_object('id', a.id, 'name', a.name))
        FROM subject_mapping_actions sma
        JOIN actions a ON sma.action_id = a.id
        WHERE sma.subject_mapping_id = sm.id AND a.is_standard = 1
    ) AS standard_actions,
    -- Custom actions as subquery
    (
        SELECT json_group_array(json_object('id', a.id, 'name', a.name))
        FROM subject_mapping_actions sma
        JOIN actions a ON sma.action_id = a.id
        WHERE sma.subject_mapping_id = sm.id AND a.is_standard = 0
    ) AS custom_actions,
    json_object(
        'labels', json_extract(sm.metadata, '$.labels'),
        'created_at', sm.created_at,
        'updated_at', sm.updated_at
    ) AS metadata,
    json_object(
        'id', scs.id,
        'metadata', json_object(
            'labels', json_extract(scs.metadata, '$.labels'),
            'created_at', scs.created_at,
            'updated_at', scs.updated_at
        ),
        'subject_sets', scs.condition
    ) AS subject_condition_set,
    json_object(
        'id', av.id,
        'value', av.value,
        'active', av.active,
        'fqn', fqns.fqn
    ) AS attribute_value,
    counted.total
FROM subject_mappings sm
CROSS JOIN counted
LEFT JOIN attribute_values av ON sm.attribute_value_id = av.id
LEFT JOIN attribute_fqns fqns ON av.id = fqns.value_id
LEFT JOIN subject_condition_set scs ON scs.id = sm.subject_condition_set_id
GROUP BY sm.id, av.id, scs.id, fqns.fqn, counted.total
LIMIT @limit_
OFFSET @offset_;

-- name: getSubjectMapping :one
SELECT
    sm.id,
    (
        SELECT json_group_array(json_object('id', a.id, 'name', a.name))
        FROM actions a
        JOIN subject_mapping_actions sma ON sma.action_id = a.id
        WHERE sma.subject_mapping_id = sm.id AND a.is_standard = 1
    ) AS standard_actions,
    (
        SELECT json_group_array(json_object('id', a.id, 'name', a.name))
        FROM actions a
        JOIN subject_mapping_actions sma ON sma.action_id = a.id
        WHERE sma.subject_mapping_id = sm.id AND a.is_standard = 0
    ) AS custom_actions,
    json_object(
        'labels', json_extract(sm.metadata, '$.labels'),
        'created_at', sm.created_at,
        'updated_at', sm.updated_at
    ) AS metadata,
    json_object(
        'id', scs.id,
        'metadata', json_object(
            'labels', json_extract(scs.metadata, '$.labels'),
            'created_at', scs.created_at,
            'updated_at', scs.updated_at
        ),
        'subject_sets', scs.condition
    ) AS subject_condition_set,
    json_object('id', av.id,'value', av.value,'active', av.active) AS attribute_value
FROM subject_mappings sm
LEFT JOIN attribute_values av ON sm.attribute_value_id = av.id
LEFT JOIN subject_condition_set scs ON scs.id = sm.subject_condition_set_id
WHERE sm.id = @id
GROUP BY av.id, sm.id, scs.id;

-- name: matchSubjectMappings :many
-- Note: Array overlap (&&) not supported in SQLite, using json_each for selector matching
-- The selector_values column contains a JSON array, we check if any selector matches
SELECT
    sm.id,
    (
        SELECT json_group_array(json_object('id', a.id, 'name', a.name))
        FROM subject_mapping_actions sma
        JOIN actions a ON sma.action_id = a.id
        WHERE sma.subject_mapping_id = sm.id AND a.is_standard = 1
    ) AS standard_actions,
    (
        SELECT json_group_array(json_object('id', a.id, 'name', a.name))
        FROM subject_mapping_actions sma
        JOIN actions a ON sma.action_id = a.id
        WHERE sma.subject_mapping_id = sm.id AND a.is_standard = 0
    ) AS custom_actions,
    json_object(
        'id', scs.id,
        'subject_sets', scs.condition
    ) AS subject_condition_set,
    json_object(
        'id', av.id,
        'value', av.value,
        'active', av.active,
        'fqn', fqns.fqn
    ) AS attribute_value
FROM subject_mappings sm
LEFT JOIN attribute_values av ON sm.attribute_value_id = av.id
LEFT JOIN attribute_definitions ad ON av.attribute_definition_id = ad.id
LEFT JOIN attribute_namespaces ns ON ad.namespace_id = ns.id
LEFT JOIN attribute_fqns fqns ON av.id = fqns.value_id
LEFT JOIN subject_condition_set scs ON scs.id = sm.subject_condition_set_id
WHERE
    ns.active = 1
    AND ad.active = 1
    AND av.active = 1
    -- Array overlap emulation: check if any selector from input matches any in selector_values
    AND EXISTS (
        SELECT 1
        FROM json_each(scs.selector_values) sv
        WHERE sv.value IN (SELECT value FROM json_each(@selectors))
    )
GROUP BY sm.id, scs.id, scs.condition, av.id, av.value, av.active, fqns.fqn;

-- name: createSubjectMapping :one
-- Note: Action insertion handled separately in app layer for SQLite
-- Note: ID generated in application layer before INSERT
INSERT INTO subject_mappings (
    id,
    attribute_value_id,
    metadata,
    subject_condition_set_id
)
VALUES (@id, @attribute_value_id, @metadata, @subject_condition_set_id)
RETURNING id;

-- name: addActionToSubjectMapping :exec
-- Helper to add actions to subject mapping (called from app layer)
INSERT INTO subject_mapping_actions (subject_mapping_id, action_id)
VALUES (@subject_mapping_id, @action_id)
ON CONFLICT (subject_mapping_id, action_id) DO NOTHING;

-- name: removeActionFromSubjectMapping :execrows
DELETE FROM subject_mapping_actions
WHERE subject_mapping_id = @subject_mapping_id AND action_id = @action_id;

-- name: removeAllActionsFromSubjectMapping :execrows
DELETE FROM subject_mapping_actions
WHERE subject_mapping_id = @subject_mapping_id;

-- name: updateSubjectMapping :execrows
-- Note: Action updates handled separately in app layer for SQLite
UPDATE subject_mappings
SET
    metadata = COALESCE(sqlc.narg('metadata'), metadata),
    subject_condition_set_id = COALESCE(sqlc.narg('subject_condition_set_id'), subject_condition_set_id)
WHERE id = @id;

-- name: deleteSubjectMapping :execrows
DELETE FROM subject_mappings WHERE id = @id;
