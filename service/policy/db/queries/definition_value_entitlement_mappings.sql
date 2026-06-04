----------------------------------------------------------------
-- DEFINITION VALUE ENTITLEMENT MAPPINGS
----------------------------------------------------------------

-- name: listDefinitionValueEntitlementMappings :many
WITH params AS (
    SELECT
        COALESCE(NULLIF(@sort_field::text, ''), 'created_at') AS resolved_field,
        COALESCE(NULLIF(@sort_direction::text, ''), 'DESC') AS resolved_direction
),
mapping_actions AS (
    SELECT
        dvm.action_id,
        dvm.definition_value_entitlement_mapping_id,
        JSONB_BUILD_OBJECT(
            'id', a.id,
            'name', a.name,
            'namespace', CASE WHEN a.namespace_id IS NULL THEN NULL
                ELSE JSONB_BUILD_OBJECT('id', ans.id, 'name', ans.name, 'fqn', ans_fqns.fqn)
            END
        ) AS action
    FROM definition_value_entitlement_mapping_actions dvm
    JOIN actions a ON dvm.action_id = a.id
    LEFT JOIN attribute_namespaces ans ON ans.id = a.namespace_id
    LEFT JOIN attribute_fqns ans_fqns ON ans_fqns.namespace_id = ans.id AND ans_fqns.attribute_id IS NULL AND ans_fqns.value_id IS NULL
),
definition_actions AS (
    SELECT
        definition_value_entitlement_mapping_id,
        COALESCE(JSONB_AGG(action), '[]'::JSONB) AS actions
    FROM mapping_actions
    GROUP BY definition_value_entitlement_mapping_id
),
counted AS (
    SELECT COUNT(dvem.id) AS total
    FROM definition_value_entitlement_mappings dvem
    LEFT JOIN attribute_namespaces m_ns ON m_ns.id = dvem.namespace_id
    LEFT JOIN attribute_fqns m_ns_fqns ON m_ns_fqns.namespace_id = m_ns.id AND m_ns_fqns.attribute_id IS NULL AND m_ns_fqns.value_id IS NULL
    WHERE
        (sqlc.narg('namespace_id')::uuid IS NULL OR dvem.namespace_id = sqlc.narg('namespace_id')::uuid)
        AND (sqlc.narg('namespace_fqn')::text IS NULL OR m_ns_fqns.fqn = sqlc.narg('namespace_fqn')::text)
        AND (sqlc.narg('attribute_definition_id')::uuid IS NULL OR dvem.attribute_definition_id = sqlc.narg('attribute_definition_id')::uuid)
)
SELECT
    dvem.id,
    dvem.attribute_definition_id,
    dvem.subject_external_selector_value,
    dvem.operator,
    dvem.subject_condition_set_id,
    COALESCE(da.actions, '[]'::JSONB) AS actions,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', dvem.metadata -> 'labels', 'created_at', dvem.created_at, 'updated_at', dvem.updated_at)) AS metadata,
    CASE
        WHEN dvem.namespace_id IS NULL THEN NULL
        ELSE JSON_BUILD_OBJECT('id', m_ns.id, 'name', m_ns.name, 'fqn', m_ns_fqns.fqn)
    END AS namespace,
    counted.total
FROM definition_value_entitlement_mappings dvem
CROSS JOIN counted
CROSS JOIN params p
LEFT JOIN definition_actions da ON dvem.id = da.definition_value_entitlement_mapping_id
LEFT JOIN attribute_namespaces m_ns ON m_ns.id = dvem.namespace_id
LEFT JOIN attribute_fqns m_ns_fqns ON m_ns_fqns.namespace_id = m_ns.id AND m_ns_fqns.attribute_id IS NULL AND m_ns_fqns.value_id IS NULL
WHERE
    (sqlc.narg('namespace_id')::uuid IS NULL OR dvem.namespace_id = sqlc.narg('namespace_id')::uuid)
    AND (sqlc.narg('namespace_fqn')::text IS NULL OR m_ns_fqns.fqn = sqlc.narg('namespace_fqn')::text)
    AND (sqlc.narg('attribute_definition_id')::uuid IS NULL OR dvem.attribute_definition_id = sqlc.narg('attribute_definition_id')::uuid)
GROUP BY
    dvem.id,
    da.actions,
    dvem.metadata, dvem.created_at, dvem.updated_at,
    m_ns.id, m_ns.name, m_ns_fqns.fqn,
    counted.total,
    p.resolved_field, p.resolved_direction
ORDER BY
    CASE WHEN p.resolved_field = 'created_at' AND p.resolved_direction = 'ASC' THEN dvem.created_at END ASC,
    CASE WHEN p.resolved_field = 'created_at' AND p.resolved_direction = 'DESC' THEN dvem.created_at END DESC,
    CASE WHEN p.resolved_field = 'updated_at' AND p.resolved_direction = 'ASC' THEN dvem.updated_at END ASC,
    CASE WHEN p.resolved_field = 'updated_at' AND p.resolved_direction = 'DESC' THEN dvem.updated_at END DESC,
    dvem.id ASC
LIMIT @limit_
OFFSET @offset_;

-- name: getDefinitionValueEntitlementMapping :one
WITH mapping_actions AS (
    SELECT
        dvm.action_id,
        dvm.definition_value_entitlement_mapping_id,
        JSONB_BUILD_OBJECT(
            'id', a.id,
            'name', a.name,
            'namespace', CASE WHEN a.namespace_id IS NULL THEN NULL
                ELSE JSONB_BUILD_OBJECT('id', ans.id, 'name', ans.name, 'fqn', ans_fqns.fqn)
            END
        ) AS action
    FROM definition_value_entitlement_mapping_actions dvm
    JOIN actions a ON dvm.action_id = a.id
    LEFT JOIN attribute_namespaces ans ON ans.id = a.namespace_id
    LEFT JOIN attribute_fqns ans_fqns ON ans_fqns.namespace_id = ans.id AND ans_fqns.attribute_id IS NULL AND ans_fqns.value_id IS NULL
    WHERE dvm.definition_value_entitlement_mapping_id = @id
),
definition_actions AS (
    SELECT
        definition_value_entitlement_mapping_id,
        COALESCE(JSONB_AGG(action), '[]'::JSONB) AS actions
    FROM mapping_actions
    GROUP BY definition_value_entitlement_mapping_id
)
SELECT
    dvem.id,
    dvem.attribute_definition_id,
    dvem.subject_external_selector_value,
    dvem.operator,
    dvem.subject_condition_set_id,
    COALESCE(da.actions, '[]'::JSONB) AS actions,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', dvem.metadata -> 'labels', 'created_at', dvem.created_at, 'updated_at', dvem.updated_at)) AS metadata,
    CASE
        WHEN dvem.namespace_id IS NULL THEN NULL
        ELSE JSON_BUILD_OBJECT('id', m_ns.id, 'name', m_ns.name, 'fqn', m_ns_fqns.fqn)
    END AS namespace
FROM definition_value_entitlement_mappings dvem
LEFT JOIN definition_actions da ON dvem.id = da.definition_value_entitlement_mapping_id
LEFT JOIN attribute_namespaces m_ns ON m_ns.id = dvem.namespace_id
LEFT JOIN attribute_fqns m_ns_fqns ON m_ns_fqns.namespace_id = m_ns.id AND m_ns_fqns.attribute_id IS NULL AND m_ns_fqns.value_id IS NULL
WHERE dvem.id = @id;

-- name: createDefinitionValueEntitlementMapping :one
WITH inserted_mapping AS (
    INSERT INTO definition_value_entitlement_mappings (
        attribute_definition_id,
        subject_external_selector_value,
        operator,
        metadata,
        subject_condition_set_id,
        namespace_id
    )
    VALUES (
        @attribute_definition_id,
        @subject_external_selector_value,
        @operator,
        @metadata,
        sqlc.narg('subject_condition_set_id')::uuid,
        sqlc.narg('namespace_id')::uuid
    )
    RETURNING id
),
inserted_actions AS (
    INSERT INTO definition_value_entitlement_mapping_actions (definition_value_entitlement_mapping_id, action_id)
    SELECT
        (SELECT id FROM inserted_mapping),
        unnest(sqlc.arg('action_ids')::uuid[])
)
SELECT id FROM inserted_mapping;

-- name: updateDefinitionValueEntitlementMapping :execrows
WITH
    mapping_update AS (
        UPDATE definition_value_entitlement_mappings
        SET
            metadata = COALESCE(sqlc.narg('metadata')::JSONB, metadata),
            subject_external_selector_value = COALESCE(sqlc.narg('subject_external_selector_value')::TEXT, subject_external_selector_value),
            operator = COALESCE(sqlc.narg('operator')::SMALLINT, operator),
            subject_condition_set_id = COALESCE(sqlc.narg('subject_condition_set_id')::UUID, subject_condition_set_id)
        WHERE id = sqlc.arg('id')
        RETURNING id
    ),
    action_delete AS (
        DELETE FROM definition_value_entitlement_mapping_actions
        WHERE
            definition_value_entitlement_mapping_id = sqlc.arg('id')
            AND sqlc.narg('action_ids')::UUID[] IS NOT NULL
            AND action_id NOT IN (SELECT unnest(sqlc.narg('action_ids')::UUID[]))
    ),
    action_insert AS (
        INSERT INTO definition_value_entitlement_mapping_actions (definition_value_entitlement_mapping_id, action_id)
        SELECT
            sqlc.arg('id'),
            a
        FROM unnest(sqlc.narg('action_ids')::UUID[]) AS a
        WHERE
            sqlc.narg('action_ids')::UUID[] IS NOT NULL
            AND NOT EXISTS (
                SELECT 1
                FROM definition_value_entitlement_mapping_actions
                WHERE definition_value_entitlement_mapping_id = sqlc.arg('id') AND action_id = a
            )
    ),
    update_count AS (
        SELECT COUNT(*) AS cnt
        FROM mapping_update
    )
SELECT cnt
FROM update_count;

-- name: deleteDefinitionValueEntitlementMapping :execrows
DELETE FROM definition_value_entitlement_mappings WHERE id = $1;

-- name: countValueSubjectMappingsByDefinitionID :one
-- Counts value-level subject mappings whose attribute value belongs to the given
-- definition. Used to enforce no-coexistence with dynamic value entitlement mappings.
SELECT COUNT(sm.id)
FROM subject_mappings sm
JOIN attribute_values av ON sm.attribute_value_id = av.id
WHERE av.attribute_definition_id = $1;

-- name: countDefinitionValueEntitlementMappingsByDefinitionID :one
-- Counts dynamic value entitlement mappings on the given definition. Used to enforce
-- no-coexistence from the subject-mapping create path.
SELECT COUNT(id)
FROM definition_value_entitlement_mappings
WHERE attribute_definition_id = $1;

-- name: getAttributeDefinitionIDByValueID :one
SELECT attribute_definition_id
FROM attribute_values
WHERE id = $1;
