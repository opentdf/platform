-- name: GetNamespaceByFqn :one
SELECT id,
    name,
    active,
    metadata,
    created_at,
    updated_at
FROM attribute_namespaces
WHERE id = (SELECT namespace_id
            FROM attribute_fqns
            WHERE fqn = $1)
LIMIT 1;

