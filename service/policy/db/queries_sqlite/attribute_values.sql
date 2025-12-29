----------------------------------------------------------------
-- ATTRIBUTE VALUES (SQLite)
----------------------------------------------------------------

-- name: listAttributeValues :many
SELECT
    COUNT(*) OVER() AS total,
    av.id,
    av.value,
    av.active,
    json_object(
        'labels', json_extract(av.metadata, '$.labels'),
        'created_at', av.created_at,
        'updated_at', av.updated_at
    ) as metadata,
    av.attribute_definition_id,
    fqns.fqn
FROM attribute_values av
LEFT JOIN attribute_fqns fqns ON av.id = fqns.value_id
WHERE (
    (sqlc.narg('active') IS NULL OR av.active = sqlc.narg('active')) AND
    (NULLIF(@attribute_definition_id, '') IS NULL OR av.attribute_definition_id = @attribute_definition_id)
)
LIMIT @limit_
OFFSET @offset_;

-- name: getAttributeValue :one
-- Note: SQLite version - complex obligation aggregations handled separately
SELECT
    av.id,
    av.value,
    av.active,
    json_object(
        'labels', json_extract(av.metadata, '$.labels'),
        'created_at', av.created_at,
        'updated_at', av.updated_at
    ) as metadata,
    av.attribute_definition_id,
    fqns.fqn,
    -- Grants as correlated subquery
    (
        SELECT json_group_array(
            json_object(
                'id', kas.id,
                'uri', kas.uri,
                'name', kas.name,
                'public_key', kas.public_key
            )
        )
        FROM attribute_value_key_access_grants avkag
        JOIN key_access_servers kas ON avkag.key_access_server_id = kas.id
        WHERE avkag.attribute_value_id = av.id
    ) AS grants,
    -- Keys as correlated subquery
    (
        SELECT json_group_array(
            json_object(
                'kas_uri', kas.uri,
                'kas_id', kas.id,
                'public_key', json_object(
                    'algorithm', kask.key_algorithm,
                    'kid', kask.key_id,
                    'pem', json_extract(kask.public_key_ctx, '$.pem')
                )
            )
        )
        FROM attribute_value_public_key_map k
        INNER JOIN key_access_server_keys kask ON k.key_access_server_key_id = kask.id
        INNER JOIN key_access_servers kas ON kas.id = kask.key_access_server_id
        WHERE k.value_id = av.id
    ) AS keys,
    -- Obligations fetched separately in app layer for SQLite
    NULL AS obligations
FROM attribute_values av
LEFT JOIN attribute_fqns fqns ON av.id = fqns.value_id
WHERE (sqlc.narg('id') IS NULL OR av.id = sqlc.narg('id'))
  AND (sqlc.narg('fqn') IS NULL OR REPLACE(REPLACE(fqns.fqn, 'https://', ''), 'http://', '') = REPLACE(REPLACE(sqlc.narg('fqn'), 'https://', ''), 'http://', ''));

-- name: createAttributeValue :one
-- Note: ID generated in application layer before INSERT
INSERT INTO attribute_values (id, attribute_definition_id, value, metadata)
VALUES (@id, @attribute_definition_id, @value, @metadata)
RETURNING id;

-- updateAttributeValue: Safe and Unsafe Updates both
-- name: updateAttributeValue :execrows
UPDATE attribute_values
SET
    value = COALESCE(sqlc.narg('value'), value),
    active = COALESCE(sqlc.narg('active'), active),
    metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE id = @id;

-- name: deleteAttributeValue :execrows
DELETE FROM attribute_values WHERE id = @id;

-- name: removeKeyAccessServerFromAttributeValue :execrows
DELETE FROM attribute_value_key_access_grants
WHERE attribute_value_id = @attribute_value_id AND key_access_server_id = @key_access_server_id;

-- name: assignPublicKeyToAttributeValue :one
INSERT INTO attribute_value_public_key_map (value_id, key_access_server_key_id)
VALUES (@value_id, @key_access_server_key_id)
RETURNING value_id, key_access_server_key_id;

-- name: removePublicKeyFromAttributeValue :execrows
DELETE FROM attribute_value_public_key_map
WHERE value_id = @value_id AND key_access_server_key_id = @key_access_server_key_id;

-- name: rotatePublicKeyForAttributeValue :many
UPDATE attribute_value_public_key_map
SET key_access_server_key_id = sqlc.arg('new_key_id')
WHERE (key_access_server_key_id = sqlc.arg('old_key_id'))
RETURNING value_id;
