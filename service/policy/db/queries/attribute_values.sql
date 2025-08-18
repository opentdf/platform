---------------------------------------------------------------- 
-- ATTRIBUTE VALUES
----------------------------------------------------------------

-- name: listAttributeValues :many
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

-- name: getAttributeValue :one
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
    value_keys.keys as keys
FROM attribute_values av
LEFT JOIN attribute_fqns fqns ON av.id = fqns.value_id
LEFT JOIN attribute_value_key_access_grants avkag ON av.id = avkag.attribute_value_id
LEFT JOIN key_access_servers kas ON avkag.key_access_server_id = kas.id
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
    INNER JOIN key_access_servers kas ON kas.id = kask.key_access_server_id
    GROUP BY k.value_id
) value_keys ON av.id = value_keys.value_id   
WHERE (sqlc.narg('id')::uuid IS NULL OR av.id = sqlc.narg('id')::uuid)
  AND (sqlc.narg('fqn')::text IS NULL OR REGEXP_REPLACE(fqns.fqn, '^https?://', '') = REGEXP_REPLACE(sqlc.narg('fqn')::text, '^https?://', ''))
GROUP BY av.id, fqns.fqn, value_keys.keys;

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
