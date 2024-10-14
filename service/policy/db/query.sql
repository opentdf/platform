---------------------------------------------------------------- 
-- KEY ACCESS SERVERS
----------------------------------------------------------------

-- name: ListKeyAccessServerGrants :many
SELECT 
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
FROM 
    key_access_servers kas
LEFT JOIN 
    attribute_definition_key_access_grants attrkag 
    ON kas.id = attrkag.key_access_server_id
LEFT JOIN 
    attribute_fqns fqns_on_attr 
    ON attrkag.attribute_definition_id = fqns_on_attr.attribute_id 
    AND fqns_on_attr.value_id IS NULL
LEFT JOIN 
    attribute_value_key_access_grants valkag 
    ON kas.id = valkag.key_access_server_id
LEFT JOIN 
    attribute_fqns fqns_on_vals 
    ON valkag.attribute_value_id = fqns_on_vals.value_id
LEFT JOIN
    attribute_namespace_key_access_grants nskag
    ON kas.id = nskag.key_access_server_id
LEFT JOIN 
    attribute_fqns fqns_on_ns
    ON nskag.namespace_id = fqns_on_ns.namespace_id
    AND fqns_on_ns.attribute_id IS NULL AND fqns_on_ns.value_id IS NULL
WHERE (NULLIF(@kas_id, '') IS NULL OR kas.id = @kas_id::uuid)
    AND (NULLIF(@kas_uri, '') IS NULL OR kas.uri = @kas_uri::varchar)
    AND (NULLIF(@kas_name, '') IS NULL OR kas.name = @kas_name::varchar)
GROUP BY 
    kas.id;

-- name: ListKeyAccessServers :many
SELECT id, uri, public_key, name,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', metadata -> 'labels', 'created_at', created_at, 'updated_at', updated_at)) as metadata
FROM key_access_servers;

-- name: GetKeyAccessServer :one
SELECT id, uri, public_key, name,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', metadata -> 'labels', 'created_at', created_at, 'updated_at', updated_at)) as metadata
FROM key_access_servers
WHERE id = $1;

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

-- name: UpsertAttributeValueFqn :one
INSERT INTO attribute_fqns (namespace_id, attribute_id, value_id, fqn)
SELECT
    n.id,
    ad.id,
    av.id,
    CONCAT('https://', n.name, '/attr/', ad.name, '/value/', av.value) AS fqn
FROM attribute_namespaces n
JOIN attribute_definitions ad ON n.id = ad.namespace_id
JOIN attribute_values av ON ad.id = av.attribute_definition_id
WHERE av.id = $1
ON CONFLICT (namespace_id, attribute_id, value_id) 
    DO UPDATE 
        SET fqn = EXCLUDED.fqn
RETURNING fqn;

-- name: UpsertAttributeDefinitionFqn :one
INSERT INTO attribute_fqns (namespace_id, attribute_id, value_id, fqn)
SELECT
    n.id,
    ad.id,
    NULL,
    CONCAT('https://', n.name, '/attr/', ad.name) AS fqn
FROM attribute_namespaces n
JOIN attribute_definitions ad ON n.id = ad.namespace_id
WHERE ad.id = $1
ON CONFLICT (namespace_id, attribute_id, value_id) 
    DO UPDATE 
        SET fqn = EXCLUDED.fqn
RETURNING fqn;

-- name: UpsertAttributeNamespaceFqn :one
INSERT INTO attribute_fqns (namespace_id, attribute_id, value_id, fqn)
SELECT
    n.id,
    NULL,
    NULL,
    CONCAT('https://', n.name) AS fqn
FROM attribute_namespaces n
WHERE n.id = $1
ON CONFLICT (namespace_id, attribute_id, value_id) 
    DO UPDATE 
        SET fqn = EXCLUDED.fqn
RETURNING fqn;

---------------------------------------------------------------- 
-- ATTRIBUTES
----------------------------------------------------------------

-- name: ListAttributesDetail :many
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
    fqns.fqn
FROM attribute_definitions ad
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
GROUP BY ad.id, n.name, fqns.fqn;

-- name: ListAttributesSummary :many
SELECT
    ad.id,
    ad.name as attribute_name,
    ad.rule,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', ad.metadata -> 'labels', 'created_at', ad.created_at, 'updated_at', ad.updated_at)) AS metadata,
    ad.namespace_id,
    ad.active,
    n.name as namespace_name
FROM attribute_definitions ad
LEFT JOIN attribute_namespaces n ON n.id = ad.namespace_id
WHERE ad.namespace_id = $1
GROUP BY ad.id, n.name;

-- name: GetAttributeByDefOrValueFqn :one
-- get the attribute definition for the provided value or definition fqn
WITH target_definition AS (
    SELECT ad.id
    FROM attribute_definitions ad
    INNER JOIN attribute_fqns af ON af.attribute_id = ad.id
    WHERE af.fqn = $1
    LIMIT 1
),
-- get the active values with KAS grants under the attribute definition
active_attribute_values AS (
    SELECT
        av.id,
        av.value,
        av.active,
        av.attribute_definition_id,
        JSON_AGG(
            DISTINCT JSONB_BUILD_OBJECT(
                'id', vkas.id,
                'uri', vkas.uri,
                'public_key', vkas.public_key
            )
        ) FILTER (WHERE vkas.id IS NOT NULL AND vkas.uri IS NOT NULL AND vkas.public_key IS NOT NULL) AS val_grants_arr
    FROM
        attribute_values av
    LEFT JOIN attribute_value_key_access_grants avg ON av.id = avg.attribute_value_id
    LEFT JOIN key_access_servers vkas ON avg.key_access_server_id = vkas.id
    WHERE av.active = TRUE
    AND av.attribute_definition_id = (SELECT id FROM target_definition)
    GROUP BY av.id
),
-- get the namespace fqn for the attribute definition
namespace_fqn_cte AS (
    SELECT anfqn.namespace_id, anfqn.fqn
    FROM attribute_fqns anfqn
    WHERE anfqn.attribute_id IS NULL AND anfqn.value_id IS NULL
),
-- get the grants for the attribute's namespace
namespace_grants_cte AS (
    SELECT
        ankag.namespace_id,
        JSONB_AGG(
            DISTINCT JSONB_BUILD_OBJECT(
                'id', kas.id,
                'uri', kas.uri,
                'public_key', kas.public_key
            )
        ) AS grants
    FROM
        attribute_namespace_key_access_grants ankag
    LEFT JOIN key_access_servers kas ON kas.id = ankag.key_access_server_id
    GROUP BY ankag.namespace_id
),
-- get the definition fqn for the attribute definition (could have been provided a value fqn initially)
target_definition_fqn_cte AS (
    SELECT af.fqn
    FROM attribute_fqns af
    WHERE af.namespace_id = (SELECT namespace_id FROM attribute_definitions WHERE id = (SELECT id FROM target_definition))
    AND af.attribute_id = (SELECT id FROM target_definition)
    AND af.value_id IS NULL
),
-- get the subject mappings for the active values under the attribute definition
subject_mappings_cte AS (
    SELECT
        av.id AS av_id,
        JSON_AGG(
            JSON_BUILD_OBJECT(
                'id', sm.id,
                'actions', sm.actions,
                'metadata', JSON_STRIP_NULLS(JSON_BUILD_OBJECT(
                    'labels', sm.metadata -> 'labels',
                    'created_at', sm.created_at,
                    'updated_at', sm.updated_at
                )),
                'subject_condition_set', JSON_BUILD_OBJECT(
                    'id', scs.id,
                    'metadata', JSON_STRIP_NULLS(JSON_BUILD_OBJECT(
                        'labels', scs.metadata -> 'labels',
                        'created_at', scs.created_at,
                        'updated_at', scs.updated_at
                    )),
                    'subject_sets', scs.condition
                )
            )
        ) AS sub_maps_arr
    FROM
        subject_mappings sm
    LEFT JOIN attribute_values av ON sm.attribute_value_id = av.id
    LEFT JOIN subject_condition_set scs ON sm.subject_condition_set_id = scs.id
    WHERE av.active = TRUE
    AND av.attribute_definition_id = (SELECT id FROM target_definition)
    GROUP BY av.id
)
-- get the attribute definition and give structure to the result
SELECT
    ad.id,
    ad.name,
    ad.rule,
    JSON_STRIP_NULLS(
        JSON_BUILD_OBJECT(
            'labels', ad.metadata -> 'labels',
            'created_at', ad.created_at,
            'updated_at', ad.updated_at
        )
    ) AS metadata,
    ad.active,
    JSON_BUILD_OBJECT(
        'name', an.name,
        'id', an.id,
        'fqn', nfq.fqn,
        'grants', n_grants.grants,
        'active', an.active
    ) AS namespace,
    (SELECT fqn FROM target_definition_fqn_cte) AS definition_fqn,
    JSON_AGG(
        JSON_BUILD_OBJECT(
            'id', avt.id,
            'value', avt.value,
            'active', avt.active,
            'fqn', af.fqn,
            'subject_mappings', sm.sub_maps_arr,
            'grants', avt.val_grants_arr
        -- enforce order of values in response
        ) ORDER BY ARRAY_POSITION(ad.values_order, avt.id)
    ) AS values,
    JSONB_AGG(
        DISTINCT JSONB_BUILD_OBJECT(
            'id', kas.id,
            'uri', kas.uri,
            'public_key', kas.public_key
        )
    ) FILTER (WHERE kas.id IS NOT NULL AND kas.uri IS NOT NULL AND kas.public_key IS NOT NULL) AS definition_grants
FROM
    attribute_definitions ad
LEFT JOIN attribute_namespaces an ON an.id = ad.namespace_id
LEFT JOIN active_attribute_values avt ON avt.attribute_definition_id = ad.id
LEFT JOIN attribute_definition_key_access_grants adkag ON adkag.attribute_definition_id = ad.id
LEFT JOIN key_access_servers kas ON kas.id = adkag.key_access_server_id
LEFT JOIN attribute_fqns af ON af.value_id = avt.id
LEFT JOIN namespace_fqn_cte nfq ON nfq.namespace_id = an.id
LEFT JOIN namespace_grants_cte n_grants ON n_grants.namespace_id = an.id
LEFT JOIN subject_mappings_cte sm ON avt.id = sm.av_id
WHERE
    ad.active = TRUE
    AND ad.id = (SELECT id FROM target_definition)
    AND an.active = TRUE
GROUP BY
    ad.id, an.id, nfq.fqn, n_grants.grants;

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
    fqns.fqn
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
WHERE ad.id = $1
GROUP BY ad.id, n.name, fqns.fqn;

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

SELECT
    av.id,
    av.value,
    av.active,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', av.metadata -> 'labels', 'created_at', av.created_at, 'updated_at', av.updated_at)) as metadata,
    av.attribute_definition_id,
    fqns.fqn
FROM attribute_values av
LEFT JOIN attribute_fqns fqns ON av.id = fqns.value_id
WHERE (
    (sqlc.narg('active')::BOOLEAN IS NULL OR av.active = sqlc.narg('active')) AND
    (NULLIF(@attribute_definition_id, '') IS NULL OR av.attribute_definition_id = @attribute_definition_id::UUID)
)
GROUP BY av.id, fqns.fqn;

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
    ) FILTER (WHERE avkag.attribute_value_id IS NOT NULL) AS grants
FROM attribute_values av
LEFT JOIN attribute_fqns fqns ON av.id = fqns.value_id
LEFT JOIN attribute_value_key_access_grants avkag ON av.id = avkag.attribute_value_id
LEFT JOIN key_access_servers kas ON avkag.key_access_server_id = kas.id
WHERE av.id = $1
GROUP BY av.id, fqns.fqn;

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
SELECT id, namespace_id, name,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', metadata -> 'labels', 'created_at', created_at, 'updated_at', updated_at)) as metadata
FROM resource_mapping_groups
WHERE (NULLIF(@namespace_id, '') IS NULL OR namespace_id = @namespace_id::uuid);

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
SELECT
    m.id,
    JSON_BUILD_OBJECT('id', av.id, 'value', av.value, 'fqn', fqns.fqn) as attribute_value,
    m.terms,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', m.metadata -> 'labels', 'created_at', m.created_at, 'updated_at', m.updated_at)) as metadata,
    COALESCE(m.group_id::TEXT, '')::TEXT as group_id
FROM resource_mappings m 
LEFT JOIN attribute_values av on m.attribute_value_id = av.id
LEFT JOIN attribute_fqns fqns on av.id = fqns.value_id
WHERE (NULLIF(@group_id, '') IS NULL OR m.group_id = @group_id::UUID)
GROUP BY av.id, m.id, fqns.fqn;

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
SELECT
    ns.id,
    ns.name,
    ns.active,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', ns.metadata -> 'labels', 'created_at', ns.created_at, 'updated_at', ns.updated_at)) as metadata,
    fqns.fqn
FROM attribute_namespaces ns
LEFT JOIN attribute_fqns fqns ON ns.id = fqns.namespace_id AND fqns.attribute_id IS NULL
WHERE (sqlc.narg('active')::BOOLEAN IS NULL OR ns.active = sqlc.narg('active')::BOOLEAN);

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
    )) FILTER (WHERE kas_ns_grants.namespace_id IS NOT NULL) as grants
FROM attribute_namespaces ns
LEFT JOIN attribute_namespace_key_access_grants kas_ns_grants ON kas_ns_grants.namespace_id = ns.id
LEFT JOIN key_access_servers kas ON kas.id = kas_ns_grants.key_access_server_id
LEFT JOIN attribute_fqns fqns ON fqns.namespace_id = ns.id
WHERE ns.id = $1 AND fqns.attribute_id IS NULL AND fqns.value_id IS NULL
GROUP BY ns.id, fqns.fqn;

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
SELECT
    id,
    condition,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', metadata -> 'labels', 'created_at', created_at, 'updated_at', updated_at)) as metadata
FROM subject_condition_set;

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

---------------------------------------------------------------- 
-- SUBJECT MAPPINGS
----------------------------------------------------------------

-- name: ListSubjectMappings :many
SELECT
    sm.id,
    sm.actions,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', sm.metadata -> 'labels', 'created_at', sm.created_at, 'updated_at', sm.updated_at)) AS metadata,
    JSON_BUILD_OBJECT(
        'id', scs.id,
        'metadata', JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', scs.metadata->'labels', 'created_at', scs.created_at, 'updated_at', scs.updated_at)),
        'subject_sets', scs.condition
    ) AS subject_condition_set,
    JSON_BUILD_OBJECT('id', av.id,'value', av.value,'active', av.active) AS attribute_value
FROM subject_mappings sm
LEFT JOIN attribute_values av ON sm.attribute_value_id = av.id
LEFT JOIN subject_condition_set scs ON scs.id = sm.subject_condition_set_id
GROUP BY av.id, sm.id, scs.id;

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
