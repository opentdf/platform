-- name: UpsertAttrFqnValue :one
INSERT INTO attribute_fqns (namespace_id, attribute_id, value_id, fqn)
SELECT n.id, ad.id, v.id, CONCAT('https://', n.name, '/attr/', ad.name, '/value/', v.value) AS fqn
FROM attribute_namespaces n
JOIN attribute_definitions ad ON ad.namespace_id = n.id
JOIN attribute_values v ON v.attribute_id = ad.id
WHERE v.id = $1
ON CONFLICT (namespace_id, attribute_id, value_id) DO UPDATE SET fqn = EXCLUDED.fqn
RETURNING fqn;

-- name: UpsertAttrFqnDefinition :many
INSERT INTO attribute_fqns (namespace_id, attribute_id, value_id, fqn)
SELECT n.id, ad.id, v.id,
       CASE
         WHEN v.value IS NOT NULL THEN CONCAT('https://', n.name, '/attr/', ad.name, '/value/', v.value)
         ELSE CONCAT('https://', n.name, '/attr/', ad.name)
       END AS fqn
FROM attribute_namespaces n
JOIN attribute_definitions ad ON ad.namespace_id = n.id
JOIN attribute_values v ON v.attribute_id = ad.id
WHERE ad.id = $1
ON CONFLICT (namespace_id, attribute_id, value_id) DO UPDATE SET fqn = EXCLUDED.fqn
RETURNING fqn;

-- name: UpsertAttrFqnNamespace :many
INSERT INTO attribute_fqns (namespace_id, attribute_id, value_id, fqn)
SELECT n.id, ad.id, v.id,
       CONCAT('https://', n.name, 
              CASE WHEN ad.id IS NOT NULL THEN '/attr/' || ad.name ELSE '' END,
              CASE WHEN v.id IS NOT NULL THEN '/value/' || v.value ELSE '' END) AS fqn
FROM attribute_namespaces n
LEFT JOIN attribute_definitions ad ON ad.namespace_id = n.id
LEFT JOIN attribute_values v ON v.attribute_id = ad.id
WHERE n.id = $1
ON CONFLICT (namespace_id, attribute_id, value_id) DO UPDATE SET fqn = EXCLUDED.fqn
RETURNING fqn;