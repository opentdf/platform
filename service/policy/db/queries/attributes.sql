---------------------------------------------------------------- 
-- ATTRIBUTES
----------------------------------------------------------------

-- name: listAttributesDetail :many
SELECT
    ad.id,
    ad.name as attribute_name,
    ad.rule,
    ad.allow_traversal,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', ad.metadata -> 'labels', 'created_at', ad.created_at, 'updated_at', ad.updated_at)) AS metadata,
    ad.namespace_id,
    ad.active,
    n.name as namespace_name,
    JSON_AGG(
        JSON_BUILD_OBJECT(
            'id', avt.id,
            'value', avt.value,
            'active', avt.active,
            'fqn', CONCAT(fqns.fqn, '/value/', avt.value)
        ) ORDER BY ARRAY_POSITION(ad.values_order, avt.id)
    ) AS values,
    fqns.fqn,
    COUNT(*) OVER() AS total
FROM attribute_definitions ad
LEFT JOIN attribute_namespaces n ON n.id = ad.namespace_id
LEFT JOIN (
  SELECT
    av.id,
    av.value,
    av.active,
    av.attribute_definition_id
  FROM attribute_values av
  GROUP BY av.id
) avt ON avt.attribute_definition_id = ad.id
LEFT JOIN attribute_fqns fqns ON fqns.attribute_id = ad.id AND fqns.value_id IS NULL
WHERE
    (sqlc.narg('active')::BOOLEAN IS NULL OR ad.active = sqlc.narg('active')) AND
    (sqlc.narg('namespace_id')::uuid IS NULL OR ad.namespace_id = sqlc.narg('namespace_id')::uuid) AND 
    (sqlc.narg('namespace_name')::text IS NULL OR n.name = sqlc.narg('namespace_name')::text) 
GROUP BY ad.id, n.name, fqns.fqn
LIMIT @limit_ 
OFFSET @offset_; 

-- name: listAttributesSummary :many
SELECT
    ad.id,
    ad.name as attribute_name,
    ad.rule,
    ad.allow_traversal,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', ad.metadata -> 'labels', 'created_at', ad.created_at, 'updated_at', ad.updated_at)) AS metadata,
    ad.namespace_id,
    ad.active,
    n.name as namespace_name,
    COUNT(*) OVER() AS total
FROM attribute_definitions ad
LEFT JOIN attribute_namespaces n ON n.id = ad.namespace_id
WHERE ad.namespace_id = $1
GROUP BY ad.id, n.name
LIMIT @limit_ 
OFFSET @offset_; 

-- name: listAttributesByDefOrValueFqns :many
-- get the attribute definition for the provided value or definition fqn
WITH target_definition AS (
    SELECT DISTINCT
        ad.id,
        ad.namespace_id,
        ad.name,
        ad.rule,
        ad.allow_traversal,
        ad.active,
        ad.values_order,
        JSONB_AGG(
	        DISTINCT JSONB_BUILD_OBJECT(
	            'id', kas.id,
	            'uri', kas.uri,
                'name', kas.name,
	            'public_key', kas.public_key
	        )
	    ) FILTER (WHERE kas.id IS NOT NULL) AS grants,
        defk.keys AS keys
    FROM attribute_fqns fqns
    INNER JOIN attribute_definitions ad ON fqns.attribute_id = ad.id
    LEFT JOIN attribute_definition_key_access_grants adkag ON ad.id = adkag.attribute_definition_id
    LEFT JOIN key_access_servers kas ON adkag.key_access_server_id = kas.id
    LEFT JOIN (
        SELECT
            k.definition_id,
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
        FROM attribute_definition_public_key_map k
        INNER JOIN key_access_server_keys kask ON k.key_access_server_key_id = kask.id
        INNER JOIN key_access_servers kas ON kask.key_access_server_id = kas.id
        GROUP BY k.definition_id
    ) defk ON ad.id = defk.definition_id
    WHERE fqns.fqn = ANY(@fqns::TEXT[]) 
        AND ad.active = TRUE
    GROUP BY ad.id, defk.keys
),
namespaces AS (
	SELECT
		n.id,
		JSON_BUILD_OBJECT(
			'id', n.id,
			'name', n.name,
			'active', n.active,
	        'fqn', fqns.fqn,
            'grants', JSONB_AGG(
	            DISTINCT JSONB_BUILD_OBJECT(
	                'id', kas.id,
	                'uri', kas.uri,
                    'name', kas.name,
	                'public_key', kas.public_key
	            )
	        ) FILTER (WHERE kas.id IS NOT NULL),
            'kas_keys', nmp_keys.keys
    	) AS namespace
	FROM target_definition td
	INNER JOIN attribute_namespaces n ON td.namespace_id = n.id
	INNER JOIN attribute_fqns fqns ON n.id = fqns.namespace_id
    LEFT JOIN attribute_namespace_key_access_grants ankag ON n.id = ankag.namespace_id
	LEFT JOIN key_access_servers kas ON ankag.key_access_server_id = kas.id
    LEFT JOIN (
        SELECT
            k.namespace_id,
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
        FROM attribute_namespace_public_key_map k
        INNER JOIN key_access_server_keys kask ON k.key_access_server_key_id = kask.id
        INNER JOIN key_access_servers kas ON kask.key_access_server_id = kas.id
        GROUP BY k.namespace_id
    ) nmp_keys ON n.id = nmp_keys.namespace_id
	WHERE n.active = TRUE
		AND (fqns.attribute_id IS NULL AND fqns.value_id IS NULL)
	GROUP BY n.id, fqns.fqn, nmp_keys.keys
),
value_grants AS (
	SELECT
		av.id,
		JSON_AGG(
			DISTINCT JSONB_BUILD_OBJECT(
				'id', kas.id,
                'uri', kas.uri,
                'name', kas.name,
                'public_key', kas.public_key
            )
		) FILTER (WHERE kas.id IS NOT NULL) AS grants
	FROM target_definition td
	LEFT JOIN attribute_values av on td.id = av.attribute_definition_id
	LEFT JOIN attribute_value_key_access_grants avkag ON av.id = avkag.attribute_value_id
	LEFT JOIN key_access_servers kas ON avkag.key_access_server_id = kas.id
	GROUP BY av.id
),
value_subject_mappings AS (
	SELECT
		av.id,
		JSON_AGG(
            JSON_BUILD_OBJECT(
                'id', sm.id,
                'actions', (
                    SELECT COALESCE(
                        JSON_AGG(
                            JSON_BUILD_OBJECT(
                                'id', a.id,
                                'name', a.name
                            )
                        ) FILTER (WHERE a.id IS NOT NULL),
                        '[]'::JSON
                    )
                    FROM subject_mapping_actions sma
                    LEFT JOIN actions a ON sma.action_id = a.id
                    WHERE sma.subject_mapping_id = sm.id
                ),
                'subject_condition_set', JSON_BUILD_OBJECT(
                    'id', scs.id,
                    'subject_sets', scs.condition
                )
            )
        ) FILTER (WHERE sm.id IS NOT NULL) AS sub_maps
	FROM target_definition td
	LEFT JOIN attribute_values av ON td.id = av.attribute_definition_id
	LEFT JOIN subject_mappings sm ON av.id = sm.attribute_value_id
	LEFT JOIN subject_condition_set scs ON sm.subject_condition_set_id = scs.id
	GROUP BY av.id
),
value_resource_mappings AS (
    SELECT
        av.id,
        JSON_AGG(
            JSON_BUILD_OBJECT(
                'id', rm.id,
                'terms', rm.terms,
                'group', CASE 
                            WHEN rm.group_id IS NULL THEN NULL
                            ELSE JSON_BUILD_OBJECT(
                                'id', rmg.id,
                                'name', rmg.name,
                                'namespace_id', rmg.namespace_id
                            )
                         END
            )
        ) FILTER (WHERE rm.id IS NOT NULL) AS res_maps
    FROM target_definition td
    LEFT JOIN attribute_values av ON td.id = av.attribute_definition_id
    LEFT JOIN resource_mappings rm ON av.id = rm.attribute_value_id
    LEFT JOIN resource_mapping_groups rmg ON rm.group_id = rmg.id
    GROUP BY av.id
),
values AS (
    SELECT
		av.attribute_definition_id,
		JSON_AGG(
	        JSON_BUILD_OBJECT(
	            'id', av.id,
	            'value', av.value,
	            'active', av.active,
	            'fqn', fqns.fqn,
                'grants', avg.grants,
	            'subject_mappings', avsm.sub_maps,
                'resource_mappings', avrm.res_maps,
                'kas_keys', value_keys.keys
	        -- enforce order of values in response
	        ) ORDER BY ARRAY_POSITION(td.values_order, av.id)
	    ) AS values
	FROM target_definition td
	LEFT JOIN attribute_values av ON td.id = av.attribute_definition_id
	LEFT JOIN attribute_fqns fqns ON av.id = fqns.value_id
    LEFT JOIN value_grants avg ON av.id = avg.id
	LEFT JOIN value_subject_mappings avsm ON av.id = avsm.id
    LEFT JOIN value_resource_mappings avrm ON av.id = avrm.id
    LEFT JOIN (
        SELECT
            k.value_id,
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
        INNER JOIN key_access_servers kas ON kask.key_access_server_id = kas.id
        GROUP BY k.value_id
    ) value_keys ON av.id = value_keys.value_id                        
	WHERE (av.active = TRUE OR sqlc.arg('include_inactive_values')::BOOLEAN = TRUE)
	GROUP BY av.attribute_definition_id
)
SELECT
	td.id,
	td.name,
    td.rule,
    td.allow_traversal,
	td.active,
	n.namespace,
	fqns.fqn,
	values.values,
    td.grants,
    td.keys
FROM target_definition td
INNER JOIN attribute_fqns fqns ON td.id = fqns.attribute_id
INNER JOIN namespaces n ON td.namespace_id = n.id
LEFT JOIN values ON td.id = values.attribute_definition_id
WHERE fqns.value_id IS NULL;

-- name: getAttribute :one
SELECT
    ad.id,
    ad.name as attribute_name,
    ad.rule,
    ad.allow_traversal,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', ad.metadata -> 'labels', 'created_at', ad.created_at, 'updated_at', ad.updated_at)) AS metadata,
    ad.namespace_id,
    ad.active,
    n.name as namespace_name,
    JSON_AGG(
        JSON_BUILD_OBJECT(
            'id', avt.id,
            'value', avt.value,
            'active', avt.active,
            'fqn', CONCAT(fqns.fqn, '/value/', avt.value)
        ) ORDER BY ARRAY_POSITION(ad.values_order, avt.id)
    ) AS values,
    JSONB_AGG(
        DISTINCT JSONB_BUILD_OBJECT(
            'id', kas.id,
            'uri', kas.uri,
            'name', kas.name,
            'public_key', kas.public_key
        )
    ) FILTER (WHERE adkag.attribute_definition_id IS NOT NULL) AS grants,
    fqns.fqn,
    defk.keys as keys
FROM attribute_definitions ad
LEFT JOIN attribute_namespaces n ON n.id = ad.namespace_id
LEFT JOIN (
    SELECT
        av.id,
        av.value,
        av.active,
        av.attribute_definition_id
    FROM attribute_values av
    GROUP BY av.id
) avt ON avt.attribute_definition_id = ad.id
LEFT JOIN attribute_definition_key_access_grants adkag ON adkag.attribute_definition_id = ad.id
LEFT JOIN key_access_servers kas ON kas.id = adkag.key_access_server_id
LEFT JOIN attribute_fqns fqns ON fqns.attribute_id = ad.id AND fqns.value_id IS NULL
LEFT JOIN (
    SELECT
        k.definition_id,
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
    FROM attribute_definition_public_key_map k
    INNER JOIN key_access_server_keys kask ON k.key_access_server_key_id = kask.id
    INNER JOIN key_access_servers kas ON kask.key_access_server_id = kas.id
    GROUP BY k.definition_id
) defk ON ad.id = defk.definition_id
WHERE (sqlc.narg('id')::uuid IS NULL OR ad.id = sqlc.narg('id')::uuid)
  AND (sqlc.narg('fqn')::text IS NULL OR REGEXP_REPLACE(fqns.fqn, '^https://', '') = REGEXP_REPLACE(sqlc.narg('fqn')::text, '^https://', ''))
GROUP BY ad.id, n.name, fqns.fqn, defk.keys;

-- name: createAttribute :one
INSERT INTO attribute_definitions (namespace_id, name, rule, metadata, allow_traversal)
VALUES (@namespace_id, @name, @rule, @metadata, @allow_traversal) 
RETURNING id;

-- updateAttribute: Unsafe and Safe Updates both
-- name: updateAttribute :execrows
UPDATE attribute_definitions
SET
    name = COALESCE(sqlc.narg('name'), name),
    rule = COALESCE(sqlc.narg('rule'), rule),
    values_order = COALESCE(sqlc.narg('values_order'), values_order),
    metadata = COALESCE(sqlc.narg('metadata'), metadata),
    active = COALESCE(sqlc.narg('active'), active),
    allow_traversal = COALESCE(sqlc.narg('allow_traversal'), allow_traversal)
WHERE id = $1;

-- name: deleteAttribute :execrows
DELETE FROM attribute_definitions WHERE id = $1;

-- name: removeKeyAccessServerFromAttribute :execrows
DELETE FROM attribute_definition_key_access_grants
WHERE attribute_definition_id = $1 AND key_access_server_id = $2;

-- name: assignPublicKeyToAttributeDefinition :one
INSERT INTO attribute_definition_public_key_map (definition_id, key_access_server_key_id)
VALUES ($1, $2)
RETURNING *;

-- name: removePublicKeyFromAttributeDefinition :execrows
DELETE FROM attribute_definition_public_key_map
WHERE definition_id = $1 AND key_access_server_key_id = $2;

-- name: rotatePublicKeyForAttributeDefinition :many
UPDATE attribute_definition_public_key_map
SET key_access_server_key_id = sqlc.arg('new_key_id')::uuid
WHERE (key_access_server_key_id = sqlc.arg('old_key_id')::uuid)
RETURNING definition_id;
