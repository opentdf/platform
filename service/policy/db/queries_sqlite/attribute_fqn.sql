----------------------------------------------------------------
-- ATTRIBUTE FQN (SQLite)
-- Note: UUID generation handled in application layer
-- These queries use INSERT OR REPLACE for upsert semantics
----------------------------------------------------------------

-- name: upsertAttributeValueFqn :one
-- Note: ID generated in application layer
INSERT INTO attribute_fqns (id, namespace_id, attribute_id, value_id, fqn)
SELECT
    @id,
    ns.id,
    ad.id,
    av.id,
    'https://' || ns.name || '/attr/' || ad.name || '/value/' || av.value
FROM attribute_values av
INNER JOIN attribute_definitions AS ad ON av.attribute_definition_id = ad.id
INNER JOIN attribute_namespaces AS ns ON ad.namespace_id = ns.id
WHERE av.id = @value_id
ON CONFLICT (namespace_id, attribute_id, value_id)
    DO UPDATE SET fqn = EXCLUDED.fqn
RETURNING namespace_id, attribute_id, value_id, fqn;

-- name: upsertAttributeDefinitionFqn :one
-- Note: ID generated in application layer. Values FQNs inserted separately.
INSERT INTO attribute_fqns (id, namespace_id, attribute_id, value_id, fqn)
SELECT
    @id,
    ns.id,
    ad.id,
    NULL,
    'https://' || ns.name || '/attr/' || ad.name
FROM attribute_definitions ad
JOIN attribute_namespaces ns ON ad.namespace_id = ns.id
WHERE ad.id = @attribute_id
ON CONFLICT (namespace_id, attribute_id, value_id)
    DO UPDATE SET fqn = EXCLUDED.fqn
RETURNING namespace_id, attribute_id, COALESCE(value_id, '') AS value_id, fqn;

-- name: upsertAttributeNamespaceFqn :one
-- Note: ID generated in application layer. Definition/Value FQNs inserted separately.
INSERT INTO attribute_fqns (id, namespace_id, attribute_id, value_id, fqn)
SELECT
    @id,
    ns.id,
    NULL,
    NULL,
    'https://' || ns.name
FROM attribute_namespaces ns
WHERE ns.id = @namespace_id
ON CONFLICT (namespace_id, attribute_id, value_id)
    DO UPDATE SET fqn = EXCLUDED.fqn
RETURNING namespace_id, COALESCE(attribute_id, '') AS attribute_id, COALESCE(value_id, '') AS value_id, fqn;

-- name: getValueFqnsByDefinition :many
-- Helper to get all value FQNs for a definition (used to upsert after definition update)
SELECT
    av.id AS value_id,
    ns.id AS namespace_id,
    ad.id AS attribute_id,
    'https://' || ns.name || '/attr/' || ad.name || '/value/' || av.value AS fqn
FROM attribute_values av
JOIN attribute_definitions ad ON av.attribute_definition_id = ad.id
JOIN attribute_namespaces ns ON ad.namespace_id = ns.id
WHERE ad.id = @attribute_id;

-- name: getDefinitionFqnsByNamespace :many
-- Helper to get all definition FQNs for a namespace
SELECT
    ad.id AS attribute_id,
    ns.id AS namespace_id,
    'https://' || ns.name || '/attr/' || ad.name AS fqn
FROM attribute_definitions ad
JOIN attribute_namespaces ns ON ad.namespace_id = ns.id
WHERE ns.id = @namespace_id;

-- name: getValueFqnsByNamespace :many
-- Helper to get all value FQNs for a namespace
SELECT
    av.id AS value_id,
    ad.id AS attribute_id,
    ns.id AS namespace_id,
    'https://' || ns.name || '/attr/' || ad.name || '/value/' || av.value AS fqn
FROM attribute_values av
JOIN attribute_definitions ad ON av.attribute_definition_id = ad.id
JOIN attribute_namespaces ns ON ad.namespace_id = ns.id
WHERE ns.id = @namespace_id;
