---------------------------------------------------------------- 
-- ATTRIBUTE VALUES
----------------------------------------------------------------

-- name: getAttributeValue :one
WITH obligation_triggers_agg AS (
    SELECT
        ot.obligation_value_id,
        JSONB_AGG(
            DISTINCT JSONB_BUILD_OBJECT(
                'id', ot.id,
                'action', JSONB_BUILD_OBJECT(
                    'id', a.id,
                    'name', a.name
                ),
                'attribute_value', JSONB_BUILD_OBJECT(
                    'id', av.id,
                    'fqn', av_fqns.fqn
                ),
                'namespace', JSONB_BUILD_OBJECT(
                    'id', trigger_ns.id,
                    'name', trigger_ns.name,
                    'fqn', CONCAT('https://', trigger_ns.name)
                ),
                'context', CASE
                    WHEN ot.client_id IS NOT NULL THEN JSONB_BUILD_ARRAY(
                        JSONB_BUILD_OBJECT(
                            'pep', JSONB_BUILD_OBJECT(
                                'client_id', ot.client_id
                            )
                        )
                    )
                    ELSE '[]'::JSONB
                END
            )
        ) AS triggers
    FROM obligation_triggers ot
    JOIN actions a ON ot.action_id = a.id
    JOIN attribute_values av ON ot.attribute_value_id = av.id
    JOIN attribute_definitions ad ON av.attribute_definition_id = ad.id
    JOIN attribute_namespaces trigger_ns ON ad.namespace_id = trigger_ns.id
    LEFT JOIN attribute_fqns av_fqns ON av.id = av_fqns.value_id
    GROUP BY ot.obligation_value_id
),
obligation_values_agg AS (
    SELECT
        ov.obligation_definition_id,
        JSONB_AGG(
            DISTINCT JSONB_BUILD_OBJECT(
                'id', ov.id,
                'value', ov.value,
                'fqn', ns_fqns.fqn || '/obl/' || od.name || '/value/' || ov.value,
                'triggers', COALESCE(ota.triggers, '[]'::JSONB)
            )
        ) AS values
    FROM obligation_values_standard ov
    LEFT JOIN obligation_triggers_agg ota ON ov.id = ota.obligation_value_id
    JOIN obligation_definitions od ON ov.obligation_definition_id = od.id
    JOIN attribute_namespaces n ON od.namespace_id = n.id
    LEFT JOIN attribute_fqns ns_fqns ON n.id = ns_fqns.namespace_id AND ns_fqns.attribute_id IS NULL AND ns_fqns.value_id IS NULL
    GROUP BY ov.obligation_definition_id
),
attribute_obligations AS (
    SELECT
        ot.attribute_value_id,
        JSONB_AGG(
            DISTINCT JSONB_BUILD_OBJECT(
                'id', od.id,
                'name', od.name,
                'fqn', ns_fqns.fqn || '/obl/' || od.name,
                'namespace', JSONB_BUILD_OBJECT(
                    'id', n.id,
                    'name', n.name,
                    'fqn', ns_fqns.fqn
                ),
                'values', COALESCE(ova.values, '[]'::JSONB)
            )
        ) AS obligations
    FROM obligation_triggers ot
    JOIN obligation_values_standard ov ON ot.obligation_value_id = ov.id
    JOIN obligation_definitions od ON ov.obligation_definition_id = od.id
    JOIN attribute_namespaces n ON od.namespace_id = n.id
    LEFT JOIN attribute_fqns ns_fqns ON n.id = ns_fqns.namespace_id AND ns_fqns.attribute_id IS NULL AND ns_fqns.value_id IS NULL
    LEFT JOIN obligation_values_agg ova ON od.id = ova.obligation_definition_id
    GROUP BY ot.attribute_value_id
)
SELECT
    av.id,
    av.value,
    av.active,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', av.metadata -> 'labels', 'created_at', av.created_at, 'updated_at', av.updated_at)) as metadata,
    av.attribute_definition_id,
    fqns.fqn,
    grants.grants,
    value_keys.keys as keys,
    ao.obligations,
    asm.subject_mappings
FROM attribute_values av
LEFT JOIN attribute_fqns fqns ON av.id = fqns.value_id
LEFT JOIN LATERAL (
    SELECT JSONB_AGG(
        DISTINCT JSONB_BUILD_OBJECT(
            'id', kas.id,
            'uri', kas.uri,
            'name', kas.name,
            'public_key', kas.public_key
        )
    ) AS grants
    FROM attribute_value_key_access_grants avkag
    JOIN key_access_servers kas ON avkag.key_access_server_id = kas.id
    WHERE avkag.attribute_value_id = av.id
) grants ON TRUE
LEFT JOIN LATERAL (
    SELECT
        JSONB_AGG(
            DISTINCT JSONB_BUILD_OBJECT(
                'kas_uri', kas.uri,
                'kas_id', kas.id,
                'public_key', JSONB_BUILD_OBJECT(
                     'algorithm', kask.key_algorithm::INTEGER,
                     'kid', kask.key_id,
                     'pem', CONVERT_FROM(DECODE(kask.public_key_ctx ->> 'pem', 'base64'), 'UTF8')
                )
            )
        ) FILTER (WHERE kask.id IS NOT NULL) AS keys
    FROM attribute_value_public_key_map k
    INNER JOIN key_access_server_keys kask ON k.key_access_server_key_id = kask.id
    INNER JOIN key_access_servers kas ON kas.id = kask.key_access_server_id
    WHERE k.value_id = av.id
) value_keys ON TRUE
LEFT JOIN attribute_obligations ao ON av.id = ao.attribute_value_id
LEFT JOIN LATERAL (
    SELECT
        JSONB_AGG(
            JSONB_BUILD_OBJECT(
                'id', sm.id,
                'actions', COALESCE(actions.actions, '[]'::JSONB),
                'subject_condition_set', JSONB_BUILD_OBJECT(
                    'id', scs.id,
                    'subject_sets', scs.condition,
                    'namespace', CASE
                        WHEN scs.namespace_id IS NULL THEN NULL
                        ELSE JSONB_BUILD_OBJECT('id', scs_ns.id, 'name', scs_ns.name, 'fqn', scs_ns_fqns.fqn)
                    END
                ),
                'attribute_value', JSONB_BUILD_OBJECT(
                    'id', av.id,
                    'value', av.value,
                    'active', av.active,
                    'fqn', fqns.fqn
                ),
                'namespace', CASE
                    WHEN sm.namespace_id IS NULL THEN NULL
                    ELSE JSONB_BUILD_OBJECT('id', sm_ns.id, 'name', sm_ns.name, 'fqn', sm_ns_fqns.fqn)
                END
            )
            ORDER BY sm.created_at, sm.id
        ) AS subject_mappings
    FROM subject_mappings sm
    LEFT JOIN LATERAL (
        SELECT JSONB_AGG(
            JSONB_BUILD_OBJECT(
                'id', a.id,
                'name', a.name,
                'namespace', CASE
                    WHEN a.namespace_id IS NULL THEN NULL
                    ELSE JSONB_BUILD_OBJECT('id', action_ns.id, 'name', action_ns.name, 'fqn', action_ns_fqns.fqn)
                END
            )
            ORDER BY a.name, a.id
        ) AS actions
        FROM subject_mapping_actions sma
        JOIN actions a ON sma.action_id = a.id
        LEFT JOIN attribute_namespaces action_ns ON action_ns.id = a.namespace_id
        LEFT JOIN attribute_fqns action_ns_fqns ON action_ns_fqns.namespace_id = action_ns.id AND action_ns_fqns.attribute_id IS NULL AND action_ns_fqns.value_id IS NULL
        WHERE sma.subject_mapping_id = sm.id
    ) actions ON TRUE
    LEFT JOIN subject_condition_set scs ON scs.id = sm.subject_condition_set_id
    LEFT JOIN attribute_namespaces scs_ns ON scs_ns.id = scs.namespace_id
    LEFT JOIN attribute_fqns scs_ns_fqns ON scs_ns_fqns.namespace_id = scs_ns.id AND scs_ns_fqns.attribute_id IS NULL AND scs_ns_fqns.value_id IS NULL
    LEFT JOIN attribute_namespaces sm_ns ON sm_ns.id = sm.namespace_id
    LEFT JOIN attribute_fqns sm_ns_fqns ON sm_ns_fqns.namespace_id = sm_ns.id AND sm_ns_fqns.attribute_id IS NULL AND sm_ns_fqns.value_id IS NULL
    WHERE sm.attribute_value_id = av.id
) asm ON TRUE
WHERE (sqlc.narg('id')::uuid IS NULL OR av.id = sqlc.narg('id')::uuid)
  AND (sqlc.narg('fqn')::text IS NULL OR fqns.fqn = CONCAT('https://', REGEXP_REPLACE(sqlc.narg('fqn')::text, '^https://', '')));

-- name: createAttributeValue :one
INSERT INTO attribute_values (attribute_definition_id, value, metadata)
VALUES (@attribute_definition_id, @value, @metadata) 
RETURNING id;

-- updateAttributeValue: Safe and Unsafe Updates both
-- name: updateAttributeValue :execrows
UPDATE attribute_values
SET
    value = COALESCE(sqlc.narg('value'), value),
    active = COALESCE(sqlc.narg('active'), active),
    metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE id = $1;

-- name: deleteAttributeValue :execrows
DELETE FROM attribute_values WHERE id = $1;

-- name: removeKeyAccessServerFromAttributeValue :execrows
DELETE FROM attribute_value_key_access_grants
WHERE attribute_value_id = $1 AND key_access_server_id = $2;

-- name: assignPublicKeyToAttributeValue :one
INSERT INTO attribute_value_public_key_map (value_id, key_access_server_key_id)
VALUES ($1, $2)
RETURNING *;

-- name: removePublicKeyFromAttributeValue :execrows
DELETE FROM attribute_value_public_key_map
WHERE value_id = $1 AND key_access_server_key_id = $2;

-- name: rotatePublicKeyForAttributeValue :many
UPDATE attribute_value_public_key_map
SET key_access_server_key_id = sqlc.arg('new_key_id')::uuid
WHERE (key_access_server_key_id = sqlc.arg('old_key_id')::uuid)
RETURNING value_id;

-- name: getAttributeValueNamespaceIDs :many
SELECT av.id AS attribute_value_id, ad.namespace_id
FROM attribute_values av
JOIN attribute_definitions ad ON av.attribute_definition_id = ad.id
WHERE av.id = ANY(sqlc.arg('ids')::uuid[]);
