----------------------------------------------------------------
-- SUBJECT CONDITION SETS
----------------------------------------------------------------

-- name: listSubjectConditionSets :many
SELECT
    scs.id,
    scs.condition,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', scs.metadata -> 'labels', 'created_at', scs.created_at, 'updated_at', scs.updated_at)) as metadata,
    CASE
        WHEN scs.namespace_id IS NULL THEN NULL
        ELSE JSON_BUILD_OBJECT('id', n.id, 'name', n.name, 'fqn', ns_fqns.fqn)
    END AS namespace,
    COUNT(*) OVER() as total
FROM subject_condition_set scs
LEFT JOIN attribute_namespaces n ON n.id = scs.namespace_id
LEFT JOIN attribute_fqns ns_fqns ON ns_fqns.namespace_id = n.id AND ns_fqns.attribute_id IS NULL AND ns_fqns.value_id IS NULL
WHERE
    (sqlc.narg('namespace_id')::uuid IS NULL AND sqlc.narg('namespace_fqn')::text IS NULL)
    OR scs.namespace_id = sqlc.narg('namespace_id')::uuid
    OR ns_fqns.fqn = sqlc.narg('namespace_fqn')::text
ORDER BY scs.created_at DESC
LIMIT @limit_
OFFSET @offset_;

-- name: getSubjectConditionSet :one
SELECT
    scs.id,
    scs.condition,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', scs.metadata -> 'labels', 'created_at', scs.created_at, 'updated_at', scs.updated_at)) as metadata,
    CASE
        WHEN scs.namespace_id IS NULL THEN NULL
        ELSE JSON_BUILD_OBJECT('id', n.id, 'name', n.name, 'fqn', ns_fqns.fqn)
    END AS namespace
FROM subject_condition_set scs
LEFT JOIN attribute_namespaces n ON n.id = scs.namespace_id
LEFT JOIN attribute_fqns ns_fqns ON ns_fqns.namespace_id = n.id AND ns_fqns.attribute_id IS NULL AND ns_fqns.value_id IS NULL
WHERE scs.id = $1;

-- name: createSubjectConditionSet :one
INSERT INTO subject_condition_set (condition, metadata, namespace_id)
VALUES (
    @condition,
    @metadata,
    COALESCE(
        sqlc.narg('namespace_id')::uuid,
        (
            SELECT namespace_id FROM attribute_fqns
            WHERE fqn = sqlc.narg('namespace_fqn')::text
                AND attribute_id IS NULL AND value_id IS NULL
            LIMIT 1
        )
    )
)
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
            JSONB_AGG(JSONB_BUILD_OBJECT('id', a.id, 'name', a.name,
                'namespace', CASE WHEN a.namespace_id IS NULL THEN NULL
                    ELSE JSONB_BUILD_OBJECT('id', ans.id, 'name', ans.name, 'fqn', ans_fqns.fqn)
                END
            )) FILTER (WHERE a.is_standard = TRUE),
            '[]'::JSONB
        ) AS standard_actions,
        COALESCE(
            JSONB_AGG(JSONB_BUILD_OBJECT('id', a.id, 'name', a.name,
                'namespace', CASE WHEN a.namespace_id IS NULL THEN NULL
                    ELSE JSONB_BUILD_OBJECT('id', ans.id, 'name', ans.name, 'fqn', ans_fqns.fqn)
                END
            )) FILTER (WHERE a.is_standard = FALSE),
            '[]'::JSONB
        ) AS custom_actions
    FROM subject_mapping_actions sma
    JOIN actions a ON sma.action_id = a.id
    LEFT JOIN attribute_namespaces ans ON ans.id = a.namespace_id
    LEFT JOIN attribute_fqns ans_fqns ON ans_fqns.namespace_id = ans.id AND ans_fqns.attribute_id IS NULL AND ans_fqns.value_id IS NULL
    GROUP BY sma.subject_mapping_id
), counted AS (
    SELECT COUNT(sm.id) AS total
    FROM subject_mappings sm
    LEFT JOIN attribute_namespaces sm_ns ON sm_ns.id = sm.namespace_id
    LEFT JOIN attribute_fqns sm_ns_fqns ON sm_ns_fqns.namespace_id = sm_ns.id AND sm_ns_fqns.attribute_id IS NULL AND sm_ns_fqns.value_id IS NULL
    WHERE
        (sqlc.narg('namespace_id')::uuid IS NULL AND sqlc.narg('namespace_fqn')::text IS NULL)
        OR sm.namespace_id = sqlc.narg('namespace_id')::uuid
        OR sm_ns_fqns.fqn = sqlc.narg('namespace_fqn')::text
)
SELECT
    sm.id,
    sa.standard_actions,
    sa.custom_actions,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', sm.metadata -> 'labels', 'created_at', sm.created_at, 'updated_at', sm.updated_at)) AS metadata,
    JSON_BUILD_OBJECT(
        'id', scs.id,
        'metadata', JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', scs.metadata->'labels', 'created_at', scs.created_at, 'updated_at', scs.updated_at)),
        'subject_sets', scs.condition,
        'namespace', CASE
            WHEN scs.namespace_id IS NULL THEN NULL
            ELSE JSON_BUILD_OBJECT('id', scs_ns.id, 'name', scs_ns.name, 'fqn', scs_ns_fqns.fqn)
        END
    ) AS subject_condition_set,
    JSON_BUILD_OBJECT(
        'id', av.id,
        'value', av.value,
        'active', av.active,
        'fqn', fqns.fqn
    ) AS attribute_value,
    CASE
        WHEN sm.namespace_id IS NULL THEN NULL
        ELSE JSON_BUILD_OBJECT('id', sm_ns.id, 'name', sm_ns.name, 'fqn', sm_ns_fqns.fqn)
    END AS namespace,
    counted.total
FROM subject_mappings sm
CROSS JOIN counted
LEFT JOIN subject_actions sa ON sm.id = sa.subject_mapping_id
LEFT JOIN attribute_values av ON sm.attribute_value_id = av.id
LEFT JOIN attribute_fqns fqns ON av.id = fqns.value_id
LEFT JOIN subject_condition_set scs ON scs.id = sm.subject_condition_set_id
LEFT JOIN attribute_namespaces scs_ns ON scs_ns.id = scs.namespace_id
LEFT JOIN attribute_fqns scs_ns_fqns ON scs_ns_fqns.namespace_id = scs_ns.id AND scs_ns_fqns.attribute_id IS NULL AND scs_ns_fqns.value_id IS NULL
LEFT JOIN attribute_namespaces sm_ns ON sm_ns.id = sm.namespace_id
LEFT JOIN attribute_fqns sm_ns_fqns ON sm_ns_fqns.namespace_id = sm_ns.id AND sm_ns_fqns.attribute_id IS NULL AND sm_ns_fqns.value_id IS NULL
WHERE
    (sqlc.narg('namespace_id')::uuid IS NULL AND sqlc.narg('namespace_fqn')::text IS NULL)
    OR sm.namespace_id = sqlc.narg('namespace_id')::uuid
    OR sm_ns_fqns.fqn = sqlc.narg('namespace_fqn')::text
GROUP BY
    sm.id,
    sa.standard_actions,
    sa.custom_actions,
    sm.metadata, sm.created_at, sm.updated_at,
    scs.id, scs.metadata, scs.created_at, scs.updated_at, scs.condition, scs.namespace_id,
    scs_ns.id, scs_ns.name, scs_ns_fqns.fqn,
    sm_ns.id, sm_ns.name, sm_ns_fqns.fqn,
    av.id, av.value, av.active,
    fqns.fqn,
    counted.total
ORDER BY sm.created_at DESC
LIMIT @limit_
OFFSET @offset_;

-- name: getSubjectMapping :one
SELECT
    sm.id,
    (
        SELECT JSONB_AGG(JSONB_BUILD_OBJECT('id', a.id, 'name', a.name,
            'namespace', CASE WHEN a.namespace_id IS NULL THEN NULL
                ELSE JSONB_BUILD_OBJECT('id', ans.id, 'name', ans.name, 'fqn', ans_fqns.fqn)
            END
        ))
        FROM actions a
        JOIN subject_mapping_actions sma ON sma.action_id = a.id
        LEFT JOIN attribute_namespaces ans ON ans.id = a.namespace_id
        LEFT JOIN attribute_fqns ans_fqns ON ans_fqns.namespace_id = ans.id AND ans_fqns.attribute_id IS NULL AND ans_fqns.value_id IS NULL
        WHERE sma.subject_mapping_id = sm.id AND a.is_standard = TRUE
    ) AS standard_actions,
    (
        SELECT JSONB_AGG(JSONB_BUILD_OBJECT('id', a.id, 'name', a.name,
            'namespace', CASE WHEN a.namespace_id IS NULL THEN NULL
                ELSE JSONB_BUILD_OBJECT('id', ans.id, 'name', ans.name, 'fqn', ans_fqns.fqn)
            END
        ))
        FROM actions a
        JOIN subject_mapping_actions sma ON sma.action_id = a.id
        LEFT JOIN attribute_namespaces ans ON ans.id = a.namespace_id
        LEFT JOIN attribute_fqns ans_fqns ON ans_fqns.namespace_id = ans.id AND ans_fqns.attribute_id IS NULL AND ans_fqns.value_id IS NULL
        WHERE sma.subject_mapping_id = sm.id AND a.is_standard = FALSE
    ) AS custom_actions,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', sm.metadata -> 'labels', 'created_at', sm.created_at, 'updated_at', sm.updated_at)) AS metadata,
    JSON_BUILD_OBJECT(
        'id', scs.id,
        'metadata', JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', scs.metadata -> 'labels', 'created_at', scs.created_at, 'updated_at', scs.updated_at)),
        'subject_sets', scs.condition,
        'namespace', CASE
            WHEN scs.namespace_id IS NULL THEN NULL
            ELSE JSON_BUILD_OBJECT('id', scs_ns.id, 'name', scs_ns.name, 'fqn', scs_ns_fqns.fqn)
        END
    ) AS subject_condition_set,
    JSON_BUILD_OBJECT('id', av.id,'value', av.value,'active', av.active) AS attribute_value,
    CASE
        WHEN sm.namespace_id IS NULL THEN NULL
        ELSE JSON_BUILD_OBJECT('id', sm_ns.id, 'name', sm_ns.name, 'fqn', sm_ns_fqns.fqn)
    END AS namespace
FROM subject_mappings sm
LEFT JOIN attribute_values av ON sm.attribute_value_id = av.id
LEFT JOIN subject_condition_set scs ON scs.id = sm.subject_condition_set_id
LEFT JOIN attribute_namespaces scs_ns ON scs_ns.id = scs.namespace_id
LEFT JOIN attribute_fqns scs_ns_fqns ON scs_ns_fqns.namespace_id = scs_ns.id AND scs_ns_fqns.attribute_id IS NULL AND scs_ns_fqns.value_id IS NULL
LEFT JOIN attribute_namespaces sm_ns ON sm_ns.id = sm.namespace_id
LEFT JOIN attribute_fqns sm_ns_fqns ON sm_ns_fqns.namespace_id = sm_ns.id AND sm_ns_fqns.attribute_id IS NULL AND sm_ns_fqns.value_id IS NULL
WHERE sm.id = $1
GROUP BY av.id, sm.id, scs.id, scs.namespace_id, scs_ns.id, scs_ns.name, scs_ns_fqns.fqn, sm_ns.id, sm_ns.name, sm_ns_fqns.fqn;

-- name: matchSubjectMappings :many
WITH subject_actions AS (
    SELECT
        sma.subject_mapping_id,
        COALESCE(
            JSONB_AGG(JSONB_BUILD_OBJECT('id', a.id, 'name', a.name,
                'namespace', CASE WHEN a.namespace_id IS NULL THEN NULL
                    ELSE JSONB_BUILD_OBJECT('id', ans.id, 'name', ans.name, 'fqn', ans_fqns.fqn)
                END
            )) FILTER (WHERE a.is_standard = TRUE),
            '[]'::JSONB
        ) AS standard_actions,
        COALESCE(
            JSONB_AGG(JSONB_BUILD_OBJECT('id', a.id, 'name', a.name,
                'namespace', CASE WHEN a.namespace_id IS NULL THEN NULL
                    ELSE JSONB_BUILD_OBJECT('id', ans.id, 'name', ans.name, 'fqn', ans_fqns.fqn)
                END
            )) FILTER (WHERE a.is_standard = FALSE),
            '[]'::JSONB
        ) AS custom_actions
    FROM subject_mapping_actions sma
    JOIN actions a ON sma.action_id = a.id
    LEFT JOIN attribute_namespaces ans ON ans.id = a.namespace_id
    LEFT JOIN attribute_fqns ans_fqns ON ans_fqns.namespace_id = ans.id AND ans_fqns.attribute_id IS NULL AND ans_fqns.value_id IS NULL
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
        subject_condition_set_id,
        namespace_id
    )
    VALUES (
        @attribute_value_id,
        @metadata,
        @subject_condition_set_id,
        COALESCE(
            sqlc.narg('namespace_id')::uuid,
            (
                SELECT namespace_id FROM attribute_fqns
                WHERE fqn = sqlc.narg('namespace_fqn')::text
                    AND attribute_id IS NULL AND value_id IS NULL
                LIMIT 1
            )
        )
    )
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
