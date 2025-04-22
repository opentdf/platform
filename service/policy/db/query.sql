---------------------------------------------------------------- 
-- KEY ACCESS SERVERS
----------------------------------------------------------------

-- name: ListKeyAccessServerGrants :many
WITH listed AS (
    SELECT
        COUNT(*) OVER () AS total,
        kas.id AS kas_id,
        kas.uri AS kas_uri,
        kas.name AS kas_name,
        kas.public_key AS kas_public_key,
        JSON_STRIP_NULLS(JSON_BUILD_OBJECT(
            'labels', kas.metadata -> 'labels',
            'created_at', kas.created_at,
            'updated_at', kas.updated_at
        )) AS kas_metadata,
        JSON_AGG(DISTINCT JSONB_BUILD_OBJECT(
            'id', attrkag.attribute_definition_id,
            'fqn', fqns_on_attr.fqn
        )) FILTER (WHERE attrkag.attribute_definition_id IS NOT NULL) AS attributes_grants,
        JSON_AGG(DISTINCT JSONB_BUILD_OBJECT(
            'id', valkag.attribute_value_id,
            'fqn', fqns_on_vals.fqn
        )) FILTER (WHERE valkag.attribute_value_id IS NOT NULL) AS values_grants,
        JSON_AGG(DISTINCT JSONB_BUILD_OBJECT(
            'id', nskag.namespace_id,
            'fqn', fqns_on_ns.fqn
        )) FILTER (WHERE nskag.namespace_id IS NOT NULL) AS namespace_grants
    FROM key_access_servers AS kas
    LEFT JOIN
        attribute_definition_key_access_grants AS attrkag
        ON kas.id = attrkag.key_access_server_id
    LEFT JOIN
        attribute_fqns AS fqns_on_attr
        ON attrkag.attribute_definition_id = fqns_on_attr.attribute_id
            AND fqns_on_attr.value_id IS NULL
    LEFT JOIN
        attribute_value_key_access_grants AS valkag
        ON kas.id = valkag.key_access_server_id
    LEFT JOIN 
        attribute_fqns AS fqns_on_vals
        ON valkag.attribute_value_id = fqns_on_vals.value_id
    LEFT JOIN
        attribute_namespace_key_access_grants AS nskag
        ON kas.id = nskag.key_access_server_id
    LEFT JOIN
        attribute_fqns AS fqns_on_ns
            ON nskag.namespace_id = fqns_on_ns.namespace_id
        AND fqns_on_ns.attribute_id IS NULL AND fqns_on_ns.value_id IS NULL
    WHERE (NULLIF(@kas_id, '') IS NULL OR kas.id = @kas_id::uuid) 
        AND (NULLIF(@kas_uri, '') IS NULL OR kas.uri = @kas_uri::varchar) 
        AND (NULLIF(@kas_name, '') IS NULL OR kas.name = @kas_name::varchar) 
    GROUP BY 
        kas.id
)
SELECT 
    listed.kas_id,
    listed.kas_uri,
    listed.kas_name,
    listed.kas_public_key,
    listed.kas_metadata,
    listed.attributes_grants,
    listed.values_grants,
    listed.namespace_grants,
    listed.total  
FROM listed
LIMIT @limit_ 
OFFSET @offset_; 

-- name: ListKeyAccessServers :many
WITH counted AS (
    SELECT COUNT(kas.id) AS total
    FROM key_access_servers AS kas
)

SELECT kas.id,
    kas.uri,
    kas.public_key,
    kas.name AS kas_name,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', kas.metadata -> 'labels', 'created_at', kas.created_at, 'updated_at', kas.updated_at)) AS metadata,
    counted.total
FROM key_access_servers AS kas
CROSS JOIN counted
LIMIT @limit_ 
OFFSET @offset_; 

-- name: GetKeyAccessServer :one
SELECT 
    kas.id,
    kas.uri, 
    kas.public_key, 
    kas.name,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', metadata -> 'labels', 'created_at', created_at, 'updated_at', updated_at)) AS metadata
FROM key_access_servers AS kas
WHERE (sqlc.narg('id')::uuid IS NULL OR kas.id = sqlc.narg('id')::uuid)
  AND (sqlc.narg('name')::text IS NULL OR kas.name = sqlc.narg('name')::text)
  AND (sqlc.narg('uri')::text IS NULL OR kas.uri = sqlc.narg('uri')::text);

-- name: CreateKeyAccessServer :one
INSERT INTO key_access_servers (uri, public_key, name, metadata)
VALUES ($1, $2, $3, $4)
RETURNING id;

-- name: UpdateKeyAccessServer :execrows
UPDATE key_access_servers
SET
    uri = COALESCE(sqlc.narg('uri'), uri),
    public_key = COALESCE(sqlc.narg('public_key'), public_key),
    name = COALESCE(sqlc.narg('name'), name),
    metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE id = $1;

-- name: DeleteKeyAccessServer :execrows
DELETE FROM key_access_servers WHERE id = $1;

---------------------------------------------------------------- 
-- ATTRIBUTE FQN
----------------------------------------------------------------

-- name: UpsertAttributeValueFqn :many
WITH new_fqns_cte AS (
    -- get attribute value fqns
    SELECT
        ns.id AS namespace_id,
        ad.id AS attribute_id,
        av.id AS value_id,
        CONCAT('https://', ns.name, '/attr/', ad.name, '/value/', av.value) AS fqn
    FROM attribute_values av
    INNER JOIN attribute_definitions AS ad ON av.attribute_definition_id = ad.id
    INNER JOIN attribute_namespaces AS ns ON ad.namespace_id = ns.id
    WHERE av.id = @value_id 
)

INSERT INTO attribute_fqns (namespace_id, attribute_id, value_id, fqn)
SELECT
    namespace_id,
    attribute_id,
    value_id,
    fqn
FROM new_fqns_cte
ON CONFLICT (namespace_id, attribute_id, value_id) 
    DO UPDATE 
        SET fqn = EXCLUDED.fqn
RETURNING
    COALESCE(namespace_id::TEXT, '')::TEXT AS namespace_id,
    COALESCE(attribute_id::TEXT, '')::TEXT AS attribute_id,
    COALESCE(value_id::TEXT, '')::TEXT AS value_id,
    fqn;

-- name: UpsertAttributeDefinitionFqn :many
WITH new_fqns_cte AS (
    -- get attribute definition fqns
    SELECT
        ns.id AS namespace_id,
        ad.id AS attribute_id,
        NULL::UUID AS value_id,
        CONCAT('https://', ns.name, '/attr/', ad.name) AS fqn
    FROM attribute_definitions ad
    JOIN attribute_namespaces ns ON ad.namespace_id = ns.id
    WHERE ad.id = @attribute_id 
    UNION
    -- get attribute value fqns
    SELECT
        ns.id as namespace_id,
        ad.id as attribute_id,
        av.id as value_id,
        CONCAT('https://', ns.name, '/attr/', ad.name, '/value/', av.value) AS fqn
    FROM attribute_values av
    JOIN attribute_definitions ad on av.attribute_definition_id = ad.id
    JOIN attribute_namespaces ns on ad.namespace_id = ns.id
    WHERE ad.id = @attribute_id 
)
INSERT INTO attribute_fqns (namespace_id, attribute_id, value_id, fqn)
SELECT 
    namespace_id,
    attribute_id,
    value_id,
    fqn
FROM new_fqns_cte
ON CONFLICT (namespace_id, attribute_id, value_id) 
    DO UPDATE 
        SET fqn = EXCLUDED.fqn
RETURNING
    COALESCE(namespace_id::TEXT, '')::TEXT as namespace_id,
    COALESCE(attribute_id::TEXT, '')::TEXT as attribute_id,
    COALESCE(value_id::TEXT, '')::TEXT as value_id,
    fqn;

-- name: UpsertAttributeNamespaceFqn :many
WITH new_fqns_cte AS (
    -- get namespace fqns
    SELECT
        ns.id as namespace_id,
        NULL::UUID as attribute_id,
        NULL::UUID as value_id,
        CONCAT('https://', ns.name) AS fqn
    FROM attribute_namespaces ns
    WHERE ns.id = @namespace_id 
    UNION
    -- get attribute definition fqns
    SELECT
        ns.id as namespace_id,
        ad.id as attribute_id,
        NULL::UUID as value_id,
        CONCAT('https://', ns.name, '/attr/', ad.name) AS fqn
    FROM attribute_definitions ad
    JOIN attribute_namespaces ns on ad.namespace_id = ns.id
    WHERE ns.id = @namespace_id 
    UNION
    -- get attribute value fqns
    SELECT
        ns.id as namespace_id,
        ad.id as attribute_id,
        av.id as value_id,
        CONCAT('https://', ns.name, '/attr/', ad.name, '/value/', av.value) AS fqn
    FROM attribute_values av
    JOIN attribute_definitions ad on av.attribute_definition_id = ad.id
    JOIN attribute_namespaces ns on ad.namespace_id = ns.id
    WHERE ns.id = @namespace_id 
)
INSERT INTO attribute_fqns (namespace_id, attribute_id, value_id, fqn)
SELECT 
    namespace_id,
    attribute_id,
    value_id,
    fqn
FROM new_fqns_cte
ON CONFLICT (namespace_id, attribute_id, value_id) 
    DO UPDATE 
        SET fqn = EXCLUDED.fqn
RETURNING
    COALESCE(namespace_id::TEXT, '')::TEXT as namespace_id,
    COALESCE(attribute_id::TEXT, '')::TEXT as attribute_id,
    COALESCE(value_id::TEXT, '')::TEXT as value_id,
    fqn;

---------------------------------------------------------------- 
-- ATTRIBUTES
----------------------------------------------------------------

-- name: ListAttributesDetail :many
WITH counted AS (
    SELECT COUNT(ad.id) AS total
    FROM attribute_definitions ad
)
SELECT
    ad.id,
    ad.name as attribute_name,
    ad.rule,
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
    counted.total
FROM attribute_definitions ad
CROSS JOIN counted
LEFT JOIN attribute_namespaces n ON n.id = ad.namespace_id
LEFT JOIN (
  SELECT
    av.id,
    av.value,
    av.active,
    JSON_AGG(
        DISTINCT JSONB_BUILD_OBJECT(
            'id', vkas.id,
            'uri', vkas.uri,
            'name', vkas.name,
            'public_key', vkas.public_key
        )
    ) FILTER (WHERE vkas.id IS NOT NULL AND vkas.uri IS NOT NULL AND vkas.public_key IS NOT NULL) AS val_grants_arr,
    av.attribute_definition_id
  FROM attribute_values av
  LEFT JOIN attribute_value_key_access_grants avg ON av.id = avg.attribute_value_id
  LEFT JOIN key_access_servers vkas ON avg.key_access_server_id = vkas.id
  GROUP BY av.id
) avt ON avt.attribute_definition_id = ad.id
LEFT JOIN attribute_fqns fqns ON fqns.attribute_id = ad.id AND fqns.value_id IS NULL
WHERE
    (sqlc.narg('active')::BOOLEAN IS NULL OR ad.active = sqlc.narg('active')) AND
    (NULLIF(@namespace_id, '') IS NULL OR ad.namespace_id = @namespace_id::uuid) AND 
    (NULLIF(@namespace_name, '') IS NULL OR n.name = @namespace_name) 
GROUP BY ad.id, n.name, fqns.fqn, counted.total
LIMIT @limit_ 
OFFSET @offset_; 

-- name: ListAttributesSummary :many
WITH counted AS (
    SELECT COUNT(ad.id) AS total FROM attribute_definitions ad
)
SELECT
    ad.id,
    ad.name as attribute_name,
    ad.rule,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', ad.metadata -> 'labels', 'created_at', ad.created_at, 'updated_at', ad.updated_at)) AS metadata,
    ad.namespace_id,
    ad.active,
    n.name as namespace_name,
    counted.total
FROM attribute_definitions ad
CROSS JOIN counted
LEFT JOIN attribute_namespaces n ON n.id = ad.namespace_id
WHERE ad.namespace_id = $1
GROUP BY ad.id, n.name, counted.total
LIMIT @limit_ 
OFFSET @offset_; 

-- name: ListAttributesByDefOrValueFqns :many
-- get the attribute definition for the provided value or definition fqn
WITH target_definition AS (
    SELECT DISTINCT
        ad.id,
        ad.namespace_id,
        ad.name,
        ad.rule,
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
        k.keys AS keys
    FROM attribute_fqns fqns
    INNER JOIN attribute_definitions ad ON fqns.attribute_id = ad.id
    LEFT JOIN attribute_definition_key_access_grants adkag ON ad.id = adkag.attribute_definition_id
    LEFT JOIN key_access_servers kas ON adkag.key_access_server_id = kas.id
    LEFT JOIN active_definition_public_keys_view k ON ad.id = k.definition_id
    WHERE fqns.fqn = ANY(@fqns::TEXT[]) 
        AND ad.active = TRUE
    GROUP BY ad.id, k.keys
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
            'keys', k.keys
    	) AS namespace
	FROM target_definition td
	INNER JOIN attribute_namespaces n ON td.namespace_id = n.id
	INNER JOIN attribute_fqns fqns ON n.id = fqns.namespace_id
	LEFT JOIN attribute_namespace_key_access_grants ankag ON n.id = ankag.namespace_id
	LEFT JOIN key_access_servers kas ON ankag.key_access_server_id = kas.id
    LEFT JOIN active_namespace_public_keys_view k ON n.id = k.namespace_id
	WHERE n.active = TRUE
		AND (fqns.attribute_id IS NULL AND fqns.value_id IS NULL)
	GROUP BY n.id, fqns.fqn, k.keys
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
                'actions', sm.actions,
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
                'keys', k.keys
	        -- enforce order of values in response
	        ) ORDER BY ARRAY_POSITION(td.values_order, av.id)
	    ) AS values
	FROM target_definition td
	LEFT JOIN attribute_values av ON td.id = av.attribute_definition_id
	LEFT JOIN attribute_fqns fqns ON av.id = fqns.value_id
	LEFT JOIN value_grants avg ON av.id = avg.id
	LEFT JOIN value_subject_mappings avsm ON av.id = avsm.id
    LEFT JOIN active_value_public_keys_view k ON av.id = k.value_id                        
	WHERE av.active = TRUE
	GROUP BY av.attribute_definition_id
)

SELECT
	td.id,
	td.name,
    td.rule,
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

-- name: GetAttribute :one
SELECT
    ad.id,
    ad.name as attribute_name,
    ad.rule,
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
    k.keys AS keys
FROM attribute_definitions ad
LEFT JOIN attribute_namespaces n ON n.id = ad.namespace_id
LEFT JOIN (
    SELECT
        av.id,
        av.value,
        av.active,
        JSON_AGG(DISTINCT JSONB_BUILD_OBJECT('id', vkas.id,'uri', vkas.uri,'name', vkas.name,'public_key', vkas.public_key )) FILTER (WHERE vkas.id IS NOT NULL AND vkas.uri IS NOT NULL AND vkas.public_key IS NOT NULL) AS val_grants_arr,
        av.attribute_definition_id
    FROM attribute_values av
    LEFT JOIN attribute_value_key_access_grants avg ON av.id = avg.attribute_value_id
    LEFT JOIN key_access_servers vkas ON avg.key_access_server_id = vkas.id
    GROUP BY av.id
) avt ON avt.attribute_definition_id = ad.id
LEFT JOIN attribute_definition_key_access_grants adkag ON adkag.attribute_definition_id = ad.id
LEFT JOIN key_access_servers kas ON kas.id = adkag.key_access_server_id
LEFT JOIN attribute_fqns fqns ON fqns.attribute_id = ad.id AND fqns.value_id IS NULL
LEFT JOIN active_definition_public_keys_view k ON ad.id = k.definition_id
WHERE (sqlc.narg('id')::uuid IS NULL OR ad.id = sqlc.narg('id')::uuid)
  AND (sqlc.narg('fqn')::text IS NULL OR REGEXP_REPLACE(fqns.fqn, '^https?://', '') = REGEXP_REPLACE(sqlc.narg('fqn')::text, '^https?://', ''))
GROUP BY ad.id, n.name, fqns.fqn, k.keys;

-- name: CreateAttribute :one
INSERT INTO attribute_definitions (namespace_id, name, rule, metadata)
VALUES (@namespace_id, @name, @rule, @metadata) 
RETURNING id;

-- UpdateAttribute: Unsafe and Safe Updates both
-- name: UpdateAttribute :execrows
UPDATE attribute_definitions
SET
    name = COALESCE(sqlc.narg('name'), name),
    rule = COALESCE(sqlc.narg('rule'), rule),
    values_order = COALESCE(sqlc.narg('values_order'), values_order),
    metadata = COALESCE(sqlc.narg('metadata'), metadata),
    active = COALESCE(sqlc.narg('active'), active)
WHERE id = $1;

-- name: DeleteAttribute :execrows
DELETE FROM attribute_definitions WHERE id = $1;

-- name: AssignKeyAccessServerToAttribute :execrows
INSERT INTO attribute_definition_key_access_grants (attribute_definition_id, key_access_server_id)
VALUES ($1, $2);

-- name: RemoveKeyAccessServerFromAttribute :execrows
DELETE FROM attribute_definition_key_access_grants
WHERE attribute_definition_id = $1 AND key_access_server_id = $2;

---------------------------------------------------------------- 
-- ATTRIBUTE VALUES
----------------------------------------------------------------

-- name: ListAttributeValues :many
WITH counted AS (
    SELECT COUNT(av.id) AS total
    FROM attribute_values av
)
SELECT
    av.id,
    av.value,
    av.active,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', av.metadata -> 'labels', 'created_at', av.created_at, 'updated_at', av.updated_at)) as metadata,
    av.attribute_definition_id,
    fqns.fqn,
    counted.total
FROM attribute_values av
CROSS JOIN counted
LEFT JOIN attribute_fqns fqns ON av.id = fqns.value_id
WHERE (
    (sqlc.narg('active')::BOOLEAN IS NULL OR av.active = sqlc.narg('active')) AND
    (NULLIF(@attribute_definition_id, '') IS NULL OR av.attribute_definition_id = @attribute_definition_id::UUID) 
)
LIMIT @limit_ 
OFFSET @offset_; 

-- name: GetAttributeValue :one
SELECT
    av.id,
    av.value,
    av.active,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', av.metadata -> 'labels', 'created_at', av.created_at, 'updated_at', av.updated_at)) as metadata,
    av.attribute_definition_id,
    fqns.fqn,
    JSONB_AGG(
        DISTINCT JSONB_BUILD_OBJECT(
            'id', kas.id,
            'uri', kas.uri,
            'name', kas.name,
            'public_key', kas.public_key
        )
    ) FILTER (WHERE avkag.attribute_value_id IS NOT NULL) AS grants,
    k.keys as keys
FROM attribute_values av
LEFT JOIN attribute_fqns fqns ON av.id = fqns.value_id
LEFT JOIN attribute_value_key_access_grants avkag ON av.id = avkag.attribute_value_id
LEFT JOIN key_access_servers kas ON avkag.key_access_server_id = kas.id
LEFT JOIN active_value_public_keys_view k ON av.id = k.value_id
WHERE (sqlc.narg('id')::uuid IS NULL OR av.id = sqlc.narg('id')::uuid)
  AND (sqlc.narg('fqn')::text IS NULL OR REGEXP_REPLACE(fqns.fqn, '^https?://', '') = REGEXP_REPLACE(sqlc.narg('fqn')::text, '^https?://', ''))
GROUP BY av.id, fqns.fqn, k.keys;

-- name: CreateAttributeValue :one
INSERT INTO attribute_values (attribute_definition_id, value, metadata)
VALUES (@attribute_definition_id, @value, @metadata) 
RETURNING id;

-- UpdateAttributeValue: Safe and Unsafe Updates both
-- name: UpdateAttributeValue :execrows
UPDATE attribute_values
SET
    value = COALESCE(sqlc.narg('value'), value),
    active = COALESCE(sqlc.narg('active'), active),
    metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE id = $1;

-- name: DeleteAttributeValue :execrows
DELETE FROM attribute_values WHERE id = $1;

-- name: AssignKeyAccessServerToAttributeValue :execrows
INSERT INTO attribute_value_key_access_grants (attribute_value_id, key_access_server_id)
VALUES ($1, $2);

-- name: RemoveKeyAccessServerFromAttributeValue :execrows
DELETE FROM attribute_value_key_access_grants
WHERE attribute_value_id = $1 AND key_access_server_id = $2;

---------------------------------------------------------------- 
-- RESOURCE MAPPING GROUPS
----------------------------------------------------------------

-- name: ListResourceMappingGroups :many
WITH counted AS (
    SELECT COUNT(rmg.id) AS total
    FROM resource_mapping_groups rmg
)
SELECT rmg.id,
    rmg.namespace_id,
    rmg.name,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', rmg.metadata -> 'labels', 'created_at', rmg.created_at, 'updated_at', rmg.updated_at)) as metadata,
    counted.total
FROM resource_mapping_groups rmg
CROSS JOIN counted
WHERE (NULLIF(@namespace_id, '') IS NULL OR rmg.namespace_id = @namespace_id::uuid) 
LIMIT @limit_ 
OFFSET @offset_; 

-- name: GetResourceMappingGroup :one
SELECT id, namespace_id, name,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', metadata -> 'labels', 'created_at', created_at, 'updated_at', updated_at)) as metadata
FROM resource_mapping_groups
WHERE id = $1;

-- name: CreateResourceMappingGroup :one
INSERT INTO resource_mapping_groups (namespace_id, name, metadata)
VALUES ($1, $2, $3)
RETURNING id;

-- name: UpdateResourceMappingGroup :execrows
UPDATE resource_mapping_groups
SET
    namespace_id = COALESCE(sqlc.narg('namespace_id'), namespace_id),
    name = COALESCE(sqlc.narg('name'), name),
    metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE id = $1;

-- name: DeleteResourceMappingGroup :execrows
DELETE FROM resource_mapping_groups WHERE id = $1;

---------------------------------------------------------------- 
-- RESOURCE MAPPING
----------------------------------------------------------------

-- name: ListResourceMappings :many
WITH counted AS (
    SELECT COUNT(rm.id) AS total
    FROM resource_mappings rm
)
SELECT
    m.id,
    JSON_BUILD_OBJECT('id', av.id, 'value', av.value, 'fqn', fqns.fqn) as attribute_value,
    m.terms,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', m.metadata -> 'labels', 'created_at', m.created_at, 'updated_at', m.updated_at)) as metadata,
    COALESCE(m.group_id::TEXT, '')::TEXT as group_id,
    counted.total
FROM resource_mappings m 
CROSS JOIN counted
LEFT JOIN attribute_values av on m.attribute_value_id = av.id
LEFT JOIN attribute_fqns fqns on av.id = fqns.value_id
WHERE (NULLIF(@group_id, '') IS NULL OR m.group_id = @group_id::UUID) 
GROUP BY av.id, m.id, fqns.fqn, counted.total
LIMIT @limit_ 
OFFSET @offset_; 

-- name: ListResourceMappingsByFullyQualifiedGroup :many
-- CTE to cache the group JSON build since it will be the same for all mappings of the group
WITH groups_cte AS (
    SELECT
        g.id,
        JSON_BUILD_OBJECT(
            'id', g.id,
            'namespace_id', g.namespace_id,
            'name', g.name,
            'metadata', JSON_STRIP_NULLS(JSON_BUILD_OBJECT(
                'labels', g.metadata -> 'labels',
                'created_at', g.created_at,
                'updated_at', g.updated_at
            ))
        ) as group
    FROM resource_mapping_groups g
    JOIN attribute_namespaces ns on g.namespace_id = ns.id
    WHERE ns.name = @namespace_name AND g.name = @group_name 
)
SELECT
    m.id,
    JSON_BUILD_OBJECT('id', av.id, 'value', av.value, 'fqn', fqns.fqn) as attribute_value,
    m.terms,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', m.metadata -> 'labels', 'created_at', m.created_at, 'updated_at', m.updated_at)) as metadata,
    g.group
FROM resource_mappings m
JOIN groups_cte g ON m.group_id = g.id
JOIN attribute_values av on m.attribute_value_id = av.id
JOIN attribute_fqns fqns on av.id = fqns.value_id;

-- name: GetResourceMapping :one
SELECT
    m.id,
    JSON_BUILD_OBJECT('id', av.id, 'value', av.value, 'fqn', fqns.fqn) as attribute_value,
    m.terms,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', m.metadata -> 'labels', 'created_at', m.created_at, 'updated_at', m.updated_at)) as metadata,
    COALESCE(m.group_id::TEXT, '')::TEXT as group_id
FROM resource_mappings m 
LEFT JOIN attribute_values av on m.attribute_value_id = av.id
LEFT JOIN attribute_fqns fqns on av.id = fqns.value_id
WHERE m.id = $1
GROUP BY av.id, m.id, fqns.fqn;

-- name: CreateResourceMapping :one
INSERT INTO resource_mappings (attribute_value_id, terms, metadata, group_id)
VALUES ($1, $2, $3, $4)
RETURNING id;

-- name: UpdateResourceMapping :execrows
UPDATE resource_mappings
SET
    attribute_value_id = COALESCE(sqlc.narg('attribute_value_id'), attribute_value_id),
    terms = COALESCE(sqlc.narg('terms'), terms),
    metadata = COALESCE(sqlc.narg('metadata'), metadata),
    group_id = COALESCE(sqlc.narg('group_id'), group_id)
WHERE id = $1;

-- name: DeleteResourceMapping :execrows
DELETE FROM resource_mappings WHERE id = $1;

---------------------------------------------------------------- 
-- NAMESPACES
----------------------------------------------------------------

-- name: ListNamespaces :many
WITH counted AS (
    SELECT COUNT(id) AS total FROM attribute_namespaces
)
SELECT
    ns.id,
    ns.name,
    ns.active,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', ns.metadata -> 'labels', 'created_at', ns.created_at, 'updated_at', ns.updated_at)) as metadata,
    fqns.fqn,
    counted.total
FROM attribute_namespaces ns
CROSS JOIN counted
LEFT JOIN attribute_fqns fqns ON ns.id = fqns.namespace_id AND fqns.attribute_id IS NULL
WHERE (sqlc.narg('active')::BOOLEAN IS NULL OR ns.active = sqlc.narg('active')::BOOLEAN)
LIMIT @limit_ 
OFFSET @offset_; 

-- name: GetNamespace :one
SELECT
    ns.id,
    ns.name,
    ns.active,
    fqns.fqn,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', ns.metadata -> 'labels', 'created_at', ns.created_at, 'updated_at', ns.updated_at)) as metadata,
    JSONB_AGG(DISTINCT JSONB_BUILD_OBJECT(
        'id', kas.id,
        'uri', kas.uri,
        'name', kas.name,
        'public_key', kas.public_key
    )) FILTER (WHERE kas_ns_grants.namespace_id IS NOT NULL) as grants,
    k.keys as keys
FROM attribute_namespaces ns
LEFT JOIN attribute_namespace_key_access_grants kas_ns_grants ON kas_ns_grants.namespace_id = ns.id
LEFT JOIN key_access_servers kas ON kas.id = kas_ns_grants.key_access_server_id
LEFT JOIN attribute_fqns fqns ON fqns.namespace_id = ns.id
LEFT JOIN active_namespace_public_keys_view k ON ns.id = k.namespace_id
WHERE fqns.attribute_id IS NULL AND fqns.value_id IS NULL 
  AND (sqlc.narg('id')::uuid IS NULL OR ns.id = sqlc.narg('id')::uuid)
  AND (sqlc.narg('name')::text IS NULL OR ns.name = REGEXP_REPLACE(sqlc.narg('name')::text, '^https?://', ''))
GROUP BY ns.id, fqns.fqn, k.keys;

-- name: CreateNamespace :one
INSERT INTO attribute_namespaces (name, metadata)
VALUES ($1, $2)
RETURNING id;

-- UpdateNamespace: both Safe and Unsafe Updates
-- name: UpdateNamespace :execrows
UPDATE attribute_namespaces
SET
    name = COALESCE(sqlc.narg('name'), name),
    active = COALESCE(sqlc.narg('active'), active),
    metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE id = $1;

-- name: DeleteNamespace :execrows
DELETE FROM attribute_namespaces WHERE id = $1;

-- name: AssignKeyAccessServerToNamespace :execrows
INSERT INTO attribute_namespace_key_access_grants (namespace_id, key_access_server_id)
VALUES ($1, $2);

-- name: RemoveKeyAccessServerFromNamespace :execrows
DELETE FROM attribute_namespace_key_access_grants
WHERE namespace_id = $1 AND key_access_server_id = $2;

---------------------------------------------------------------- 
-- SUBJECT CONDITION SETS
----------------------------------------------------------------

-- name: ListSubjectConditionSets :many
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
LIMIT @limit_ 
OFFSET @offset_; 

-- name: GetSubjectConditionSet :one
SELECT
    id,
    condition,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', metadata -> 'labels', 'created_at', created_at, 'updated_at', updated_at)) as metadata
FROM subject_condition_set
WHERE id = $1;

-- name: CreateSubjectConditionSet :one
INSERT INTO subject_condition_set (condition, metadata)
VALUES ($1, $2)
RETURNING id;

-- name: UpdateSubjectConditionSet :execrows
UPDATE subject_condition_set
SET
    condition = COALESCE(sqlc.narg('condition'), condition),
    metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE id = $1;

-- name: DeleteSubjectConditionSet :execrows
DELETE FROM subject_condition_set WHERE id = $1;

-- name: DeleteAllUnmappedSubjectConditionSets :many
DELETE FROM subject_condition_set
WHERE id NOT IN (SELECT DISTINCT sm.subject_condition_set_id FROM subject_mappings sm)
RETURNING id;

---------------------------------------------------------------- 
-- SUBJECT MAPPINGS
----------------------------------------------------------------

-- name: ListSubjectMappings :many
WITH counted AS (
    SELECT COUNT(sm.id) AS total
    FROM subject_mappings sm
)

SELECT
    sm.id,
    sm.actions,
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
LEFT JOIN attribute_values av ON sm.attribute_value_id = av.id
LEFT JOIN attribute_fqns fqns ON av.id = fqns.value_id
LEFT JOIN subject_condition_set scs ON scs.id = sm.subject_condition_set_id
GROUP BY av.id, sm.id, scs.id, counted.total, fqns.fqn
LIMIT @limit_
OFFSET @offset_;

-- name: GetSubjectMapping :one
SELECT
    sm.id,
    sm.actions,
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

-- name: MatchSubjectMappings :many
SELECT
    sm.id,
    sm.actions,
    JSON_BUILD_OBJECT(
        'id', scs.id,
        'subject_sets', scs.condition
    ) AS subject_condition_set,
    JSON_BUILD_OBJECT('id', av.id,'value', av.value,'active', av.active) AS attribute_value
FROM subject_mappings sm
LEFT JOIN attribute_values av ON sm.attribute_value_id = av.id
LEFT JOIN attribute_definitions ad ON av.attribute_definition_id = ad.id
LEFT JOIN attribute_namespaces ns ON ad.namespace_id = ns.id
LEFT JOIN subject_condition_set scs ON scs.id = sm.subject_condition_set_id
WHERE ns.active = true AND ad.active = true and av.active = true AND EXISTS (
    SELECT 1
    FROM JSONB_ARRAY_ELEMENTS(scs.condition) AS ss, JSONB_ARRAY_ELEMENTS(ss->'conditionGroups') AS cg, JSONB_ARRAY_ELEMENTS(cg->'conditions') AS each_condition
    WHERE (each_condition->>'subjectExternalSelectorValue' = ANY(@selectors::TEXT[])) 
)
GROUP BY av.id, sm.id, scs.id;


-- name: CreateSubjectMapping :one
INSERT INTO subject_mappings (attribute_value_id, actions, metadata, subject_condition_set_id)
VALUES ($1, $2, $3, $4)
RETURNING id;

-- name: UpdateSubjectMapping :execrows
UPDATE subject_mappings
SET
    actions = COALESCE(sqlc.narg('actions'), actions),
    metadata = COALESCE(sqlc.narg('metadata'), metadata),
    subject_condition_set_id = COALESCE(sqlc.narg('subject_condition_set_id'), subject_condition_set_id)
WHERE id = $1;

-- name: DeleteSubjectMapping :execrows
DELETE FROM subject_mappings WHERE id = $1;


---------------------------------------------------------------- 
-- KEYS
----------------------------------------------------------------

-- name: createPublicKey :one
INSERT INTO public_keys (key_access_server_id, key_id, alg, public_key, metadata)
VALUES ($1, $2, $3, $4, $5)
RETURNING id;

-- name: getPublicKey :one
SELECT 
    k.id,
    k.is_active,
    k.was_mapped,
    k.key_access_server_id,
    k.key_id,
    k.alg,
    k.public_key,
    kas.uri AS kas_uri,
    kas.name AS kas_name,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', k.metadata -> 'labels', 'created_at', k.created_at, 'updated_at', k.updated_at)) AS metadata
FROM public_keys AS k
LEFT JOIN key_access_servers AS kas ON k.key_access_server_id = kas.id
WHERE k.id = $1;

-- name: listPublicKeys :many
WITH counted AS (
    SELECT COUNT(DISTINCT kas.id) AS total FROM public_keys AS pk
    JOIN key_access_servers kas ON pk.key_access_server_id = kas.id
    WHERE (NULLIF(@kas_id, '') IS NULL OR kas.id = @kas_id::uuid)
    AND (NULLIF(@kas_name, '') IS NULL OR kas.name = @kas_name)
    AND (NULLIF(@kas_uri, '') IS NULL OR kas.uri = @kas_uri)
)

SELECT
    k.id,
    k.is_active,
    k.was_mapped,
    k.key_access_server_id,
    k.key_id,
    k.alg,
    k.public_key,
    kas.uri AS kas_uri,
    kas.name AS kas_name,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', k.metadata -> 'labels', 'created_at', k.created_at, 'updated_at', k.updated_at)) AS metadata,
    counted.total
FROM public_keys k
LEFT JOIN key_access_servers AS kas ON k.key_access_server_id = kas.id
CROSS JOIN counted
WHERE (
    NULLIF(@kas_id, '') IS NULL OR k.key_access_server_id = @kas_id::uuid 
)
AND (NULLIF(@kas_name, '') IS NULL OR kas.name = @kas_name)
AND (NULLIF(@kas_uri, '') IS NULL OR kas.uri = @kas_uri)
LIMIT @limit_ 
OFFSET @offset_; 

-- name: listPublicKeyMappings :many
WITH counted AS (
    SELECT COUNT(DISTINCT kas.id) AS total FROM public_keys AS pk
    JOIN key_access_servers kas ON pk.key_access_server_id = kas.id
    WHERE (NULLIF(@kas_id, '') IS NULL OR pk.key_access_server_id = @kas_id::uuid)
    AND (NULLIF(@kas_name, '') IS NULL OR kas.name = @kas_name)
    AND (NULLIF(@kas_uri, '') IS NULL OR kas.uri = @kas_uri)
    AND   ( NULLIF(@public_key_id, '') IS NULL OR pk.id = @public_key_id::uuid )
),
base_keys AS (
    SELECT 
        pk.id,
        pk.is_active,
        pk.was_mapped,
        pk.key_id,
        pk.alg,
        pk.public_key,
        kas.id as kas_id,
        kas.name as kas_name,
        kas.uri as kas_uri
    FROM public_keys pk
    JOIN key_access_servers kas ON pk.key_access_server_id = kas.id
    WHERE ( NULLIF(@kas_id, '') IS NULL OR kas.id = @kas_id::uuid )
    AND (NULLIF(@kas_name, '') IS NULL OR kas.name = @kas_name)
    AND (NULLIF(@kas_uri, '') IS NULL OR kas.uri = @kas_uri)
    AND   ( NULLIF(@public_key_id, '') IS NULL OR pk.id = @public_key_id::uuid )
),
namespace_mappings AS (
    SELECT 
        pk.id as key_id,
        ns.id as namespace_id,
        fqn_ns.fqn as namespace_fqn
    FROM public_keys pk
    JOIN attribute_namespace_public_key_map nm ON pk.id = nm.key_id
    JOIN attribute_namespaces ns ON nm.namespace_id = ns.id
    LEFT JOIN attribute_fqns fqn_ns ON fqn_ns.namespace_id = ns.id 
        AND fqn_ns.attribute_id IS NULL 
        AND fqn_ns.value_id IS NULL
),
definition_mappings AS (
    SELECT 
        pk.id as key_id,
        def.id as definition_id,
        fqn_def.fqn as definition_fqn
    FROM public_keys pk
    JOIN attribute_definition_public_key_map dm ON pk.id = dm.key_id
    JOIN attribute_definitions def ON dm.definition_id = def.id
    LEFT JOIN attribute_fqns fqn_def ON fqn_def.namespace_id = def.namespace_id 
        AND fqn_def.attribute_id = def.id 
        AND fqn_def.value_id IS NULL
),
value_mappings AS (
    SELECT 
        pk.id as key_id,
        val.id as value_id,
        fqn_val.fqn as value_fqn
    FROM public_keys pk
    JOIN attribute_value_public_key_map vm ON pk.id = vm.key_id
    JOIN attribute_values val ON vm.value_id = val.id
    LEFT JOIN attribute_fqns fqn_val ON fqn_val.value_id = val.id
)
SELECT jsonb_build_object(
    'kasId', bk.kas_id,
    'kasName', bk.kas_name,
    'kasUri', bk.kas_uri,
    'publicKeys', jsonb_agg(
        jsonb_build_object(
            'key', jsonb_build_object(
	            'id', bk.id,
	            'isActive', bk.is_active,
	            'wasMapped', bk.was_mapped,
                'publicKey', jsonb_build_object(
                    'kid', bk.key_id,
                    'alg', bk.alg,
                    'pem', bk.public_key
                )
            ),
            'namespaces', (
                SELECT jsonb_agg(DISTINCT jsonb_build_object(
                    'id', nm.namespace_id,
                    'fqn', nm.namespace_fqn
                ))
                FROM namespace_mappings nm
                WHERE nm.key_id = bk.id
            ),
            'definitions', (
                SELECT jsonb_agg(DISTINCT jsonb_build_object(
                    'id', dm.definition_id,
                    'fqn', dm.definition_fqn
                ))
                FROM definition_mappings dm
                WHERE dm.key_id = bk.id
            ),
            'values', (
                SELECT jsonb_agg(DISTINCT jsonb_build_object(
                    'id', vm.value_id,
                    'fqn', vm.value_fqn
                ))
                FROM value_mappings vm
                WHERE vm.key_id = bk.id
            )
        )
    )
) as kas_info,
counted.total
FROM base_keys bk
CROSS JOIN counted
GROUP BY bk.kas_id, bk.kas_name, bk.kas_uri, counted.total
LIMIT @limit_ 
OFFSET @offset_;

-- name: updatePublicKey :one
UPDATE public_keys
SET
    metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE id = $1
RETURNING *;

-- name: deletePublicKey :execrows
DELETE FROM public_keys WHERE id = $1;

-- name: deactivatePublicKey :execrows
UPDATE public_keys SET is_active = FALSE WHERE id = $1;

-- name: activatePublicKey :execrows
UPDATE public_keys SET is_active = TRUE WHERE id = $1;

-- name: assignPublicKeyToNamespace :execrows
INSERT INTO attribute_namespace_public_key_map (namespace_id, key_id) VALUES ($1, $2);

-- name: removePublicKeyFromNamespace :execrows
DELETE FROM attribute_namespace_public_key_map WHERE namespace_id = $1 AND key_id = $2;

-- name: assignPublicKeyToAttributeDefinition :execrows
INSERT INTO attribute_definition_public_key_map (definition_id, key_id) VALUES ($1, $2);

-- name: removePublicKeyFromAttributeDefinition :execrows
DELETE FROM attribute_definition_public_key_map WHERE definition_id = $1 AND key_id = $2;

-- name: assignPublicKeyToAttributeValue :execrows
INSERT INTO attribute_value_public_key_map (value_id, key_id) VALUES ($1, $2);

-- name: removePublicKeyFromAttributeValue :execrows
DELETE FROM attribute_value_public_key_map WHERE value_id = $1 AND key_id = $2;


----------------------------------------------------------------
-- REGISTERED RESOURCES
----------------------------------------------------------------

-- name: createRegisteredResource :one
INSERT INTO registered_resources (name, metadata)
VALUES ($1, $2)
RETURNING id;

-- name: getRegisteredResource :one
-- TODO add FQN support
SELECT
    r.id,
    r.name,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', r.metadata -> 'labels', 'created_at', r.created_at, 'updated_at', r.updated_at)) as metadata,
    JSON_AGG(
        JSON_BUILD_OBJECT(
            'id', v.id,
            'value', v.value
        )
    ) FILTER (WHERE v.id IS NOT NULL) as values
FROM registered_resources r
LEFT JOIN registered_resource_values v ON v.registered_resource_id = r.id
WHERE r.id = $1
GROUP BY r.id;

-- name: listRegisteredResources :many
WITH counted AS (
    SELECT COUNT(id) AS total
    FROM registered_resources
)
SELECT
    r.id,
    r.name,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', r.metadata -> 'labels', 'created_at', r.created_at, 'updated_at', r.updated_at)) as metadata,
    JSON_AGG(
        JSON_BUILD_OBJECT(
            'id', v.id,
            'value', v.value
        )
    ) FILTER (WHERE v.id IS NOT NULL) as values,
    counted.total
FROM registered_resources r
CROSS JOIN counted
LEFT JOIN registered_resource_values v ON v.registered_resource_id = r.id
GROUP BY r.id, counted.total
LIMIT @limit_ 
OFFSET @offset_;

-- name: updateRegisteredResource :execrows
UPDATE registered_resources
SET
    name = COALESCE(sqlc.narg('name'), name),
    metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE id = $1;

-- name: deleteRegisteredResource :execrows
DELETE FROM registered_resources WHERE id = $1;


----------------------------------------------------------------
-- REGISTERED RESOURCE VALUES
----------------------------------------------------------------

-- name: createRegisteredResourceValue :one
INSERT INTO registered_resource_values (registered_resource_id, value, metadata)
VALUES ($1, $2, $3)
RETURNING id;

-- name: getRegisteredResourceValue :one
SELECT
    id,
    registered_resource_id,
    value,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', metadata -> 'labels', 'created_at', created_at, 'updated_at', updated_at)) as metadata
FROM registered_resource_values
WHERE id = $1;

-- name: listRegisteredResourceValues :many
WITH counted AS (
    SELECT COUNT(id) AS total
    FROM registered_resource_values
    WHERE
        NULLIF(@registered_resource_id, '') IS NULL OR registered_resource_id = @registered_resource_id::UUID
)
SELECT
    id,
    registered_resource_id,
    value,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', metadata -> 'labels', 'created_at', created_at, 'updated_at', updated_at)) as metadata,
    counted.total
FROM registered_resource_values
CROSS JOIN counted
WHERE
    NULLIF(@registered_resource_id, '') IS NULL OR registered_resource_id = @registered_resource_id::UUID
LIMIT @limit_
OFFSET @offset_;

-- name: updateRegisteredResourceValue :execrows
UPDATE registered_resource_values
SET
    value = COALESCE(sqlc.narg('value'), value),
    metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE id = $1;

-- name: deleteRegisteredResourceValue :execrows
DELETE FROM registered_resource_values WHERE id = $1;
