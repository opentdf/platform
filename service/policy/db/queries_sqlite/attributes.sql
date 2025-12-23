----------------------------------------------------------------
-- ATTRIBUTES (SQLite)
----------------------------------------------------------------

-- name: listAttributesDetail :many
-- Note: SQLite version - values_order ordering handled differently
SELECT
    ad.id,
    ad.name as attribute_name,
    ad.rule,
    json_object(
        'labels', json_extract(ad.metadata, '$.labels'),
        'created_at', ad.created_at,
        'updated_at', ad.updated_at
    ) AS metadata,
    ad.namespace_id,
    ad.active,
    n.name as namespace_name,
    -- Values aggregation with ordering via subquery
    (
        SELECT json_group_array(
            json_object(
                'id', av.id,
                'value', av.value,
                'active', av.active,
                'fqn', fqns.fqn || '/value/' || av.value
            )
        )
        FROM attribute_values av
        LEFT JOIN attribute_fqns fqns ON av.attribute_definition_id = fqns.attribute_id AND fqns.value_id IS NULL
        WHERE av.attribute_definition_id = ad.id
        -- Note: values_order is JSON array in SQLite, ordering handled in app layer
    ) AS "values",
    fqns.fqn,
    COUNT(*) OVER() AS total
FROM attribute_definitions ad
LEFT JOIN attribute_namespaces n ON n.id = ad.namespace_id
LEFT JOIN attribute_fqns fqns ON fqns.attribute_id = ad.id AND fqns.value_id IS NULL
WHERE
    (sqlc.narg('active') IS NULL OR ad.active = sqlc.narg('active')) AND
    (NULLIF(@namespace_id, '') IS NULL OR ad.namespace_id = @namespace_id) AND
    (NULLIF(@namespace_name, '') IS NULL OR n.name = @namespace_name)
GROUP BY ad.id, n.name, fqns.fqn
LIMIT @limit_
OFFSET @offset_;

-- name: listAttributesSummary :many
SELECT
    ad.id,
    ad.name as attribute_name,
    ad.rule,
    json_object(
        'labels', json_extract(ad.metadata, '$.labels'),
        'created_at', ad.created_at,
        'updated_at', ad.updated_at
    ) AS metadata,
    ad.namespace_id,
    ad.active,
    n.name as namespace_name,
    COUNT(*) OVER() AS total
FROM attribute_definitions ad
LEFT JOIN attribute_namespaces n ON n.id = ad.namespace_id
WHERE ad.namespace_id = @namespace_id
GROUP BY ad.id, n.name
LIMIT @limit_
OFFSET @offset_;

-- name: listAttributesByDefOrValueFqns :many
-- Note: SQLite version - complex query simplified, some data fetched in app layer
-- Uses json_each instead of ANY() for array matching
WITH target_definition AS (
    SELECT DISTINCT
        ad.id,
        ad.namespace_id,
        ad.name,
        ad.rule,
        ad.active,
        ad.values_order
    FROM attribute_fqns fqns
    INNER JOIN attribute_definitions ad ON fqns.attribute_id = ad.id
    WHERE fqns.fqn IN (SELECT value FROM json_each(@fqns))
        AND ad.active = 1
    GROUP BY ad.id
),
namespaces AS (
    SELECT
        n.id,
        json_object(
            'id', n.id,
            'name', n.name,
            'active', n.active,
            'fqn', fqns.fqn
        ) AS namespace
    FROM target_definition td
    INNER JOIN attribute_namespaces n ON td.namespace_id = n.id
    INNER JOIN attribute_fqns fqns ON n.id = fqns.namespace_id
    WHERE n.active = 1
        AND (fqns.attribute_id IS NULL AND fqns.value_id IS NULL)
    GROUP BY n.id, fqns.fqn
)
SELECT
    td.id,
    td.name,
    td.rule,
    td.active,
    n.namespace,
    fqns.fqn,
    -- Values fetched in app layer for proper ordering
    (
        SELECT json_group_array(
            json_object(
                'id', av.id,
                'value', av.value,
                'active', av.active,
                'fqn', vfqns.fqn
            )
        )
        FROM attribute_values av
        LEFT JOIN attribute_fqns vfqns ON av.id = vfqns.value_id
        WHERE av.attribute_definition_id = td.id AND av.active = 1
    ) AS "values",
    -- Grants as subquery
    (
        SELECT json_group_array(
            json_object(
                'id', kas.id,
                'uri', kas.uri,
                'name', kas.name,
                'public_key', kas.public_key
            )
        )
        FROM attribute_definition_key_access_grants adkag
        JOIN key_access_servers kas ON adkag.key_access_server_id = kas.id
        WHERE adkag.attribute_definition_id = td.id
    ) AS grants,
    -- Keys simplified, full details in app layer
    (
        SELECT json_group_array(
            json_object(
                'kas_id', kas.id,
                'kas_uri', kas.uri,
                'key_id', kask.key_id,
                'algorithm', kask.key_algorithm
            )
        )
        FROM attribute_definition_public_key_map k
        INNER JOIN key_access_server_keys kask ON k.key_access_server_key_id = kask.id
        INNER JOIN key_access_servers kas ON kask.key_access_server_id = kas.id
        WHERE k.definition_id = td.id
    ) AS keys
FROM target_definition td
INNER JOIN attribute_fqns fqns ON td.id = fqns.attribute_id
INNER JOIN namespaces n ON td.namespace_id = n.id
WHERE fqns.value_id IS NULL;

-- name: getAttribute :one
SELECT
    ad.id,
    ad.name as attribute_name,
    ad.rule,
    json_object(
        'labels', json_extract(ad.metadata, '$.labels'),
        'created_at', ad.created_at,
        'updated_at', ad.updated_at
    ) AS metadata,
    ad.namespace_id,
    ad.active,
    n.name as namespace_name,
    -- Values as subquery
    (
        SELECT json_group_array(
            json_object(
                'id', av.id,
                'value', av.value,
                'active', av.active,
                'fqn', fqns.fqn || '/value/' || av.value
            )
        )
        FROM attribute_values av
        WHERE av.attribute_definition_id = ad.id
    ) AS "values",
    -- Grants as subquery
    (
        SELECT json_group_array(
            json_object(
                'id', kas.id,
                'uri', kas.uri,
                'name', kas.name,
                'public_key', kas.public_key
            )
        )
        FROM attribute_definition_key_access_grants adkag
        JOIN key_access_servers kas ON adkag.key_access_server_id = kas.id
        WHERE adkag.attribute_definition_id = ad.id
    ) AS grants,
    fqns.fqn,
    -- Keys simplified
    (
        SELECT json_group_array(
            json_object(
                'kas_id', kas.id,
                'kas_uri', kas.uri,
                'key_id', kask.key_id,
                'algorithm', kask.key_algorithm
            )
        )
        FROM attribute_definition_public_key_map k
        INNER JOIN key_access_server_keys kask ON k.key_access_server_key_id = kask.id
        INNER JOIN key_access_servers kas ON kask.key_access_server_id = kas.id
        WHERE k.definition_id = ad.id
    ) AS keys
FROM attribute_definitions ad
LEFT JOIN attribute_namespaces n ON n.id = ad.namespace_id
LEFT JOIN attribute_fqns fqns ON fqns.attribute_id = ad.id AND fqns.value_id IS NULL
WHERE (sqlc.narg('id') IS NULL OR ad.id = sqlc.narg('id'))
  AND (sqlc.narg('fqn') IS NULL OR REPLACE(REPLACE(fqns.fqn, 'https://', ''), 'http://', '') = REPLACE(REPLACE(sqlc.narg('fqn'), 'https://', ''), 'http://', ''))
GROUP BY ad.id, n.name, fqns.fqn;

-- name: createAttribute :one
-- Note: ID generated in application layer before INSERT
INSERT INTO attribute_definitions (id, namespace_id, name, rule, metadata)
VALUES (@id, @namespace_id, @name, @rule, @metadata)
RETURNING id;

-- updateAttribute: Unsafe and Safe Updates both
-- name: updateAttribute :execrows
UPDATE attribute_definitions
SET
    name = COALESCE(sqlc.narg('name'), name),
    rule = COALESCE(sqlc.narg('rule'), rule),
    values_order = COALESCE(sqlc.narg('values_order'), values_order),
    metadata = COALESCE(sqlc.narg('metadata'), metadata),
    active = COALESCE(sqlc.narg('active'), active)
WHERE id = @id;

-- name: deleteAttribute :execrows
DELETE FROM attribute_definitions WHERE id = @id;

-- name: removeKeyAccessServerFromAttribute :execrows
DELETE FROM attribute_definition_key_access_grants
WHERE attribute_definition_id = @attribute_definition_id AND key_access_server_id = @key_access_server_id;

-- name: assignPublicKeyToAttributeDefinition :one
INSERT INTO attribute_definition_public_key_map (definition_id, key_access_server_key_id)
VALUES (@definition_id, @key_access_server_key_id)
RETURNING definition_id, key_access_server_key_id;

-- name: removePublicKeyFromAttributeDefinition :execrows
DELETE FROM attribute_definition_public_key_map
WHERE definition_id = @definition_id AND key_access_server_key_id = @key_access_server_key_id;

-- name: rotatePublicKeyForAttributeDefinition :many
UPDATE attribute_definition_public_key_map
SET key_access_server_key_id = sqlc.arg('new_key_id')
WHERE (key_access_server_key_id = sqlc.arg('old_key_id'))
RETURNING definition_id;
