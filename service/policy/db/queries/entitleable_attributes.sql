-- name: getEntitleableAttributeValues :many
-- Authorization needs value identity and rule context, not grants, keys, or resource
-- mappings. Only hierarchy definitions need their other active values, in policy order.
WITH definitions AS (
    SELECT ad.id, ad.namespace_id, ad.rule, ad.allow_traversal, ad.values_order,
        df.fqn AS definition_fqn
    FROM attribute_definitions ad
    JOIN attribute_fqns df ON df.attribute_id = ad.id AND df.value_id IS NULL
    JOIN attribute_namespaces ns ON ns.id = ad.namespace_id AND ns.active = TRUE
    WHERE df.fqn = ANY(@definition_fqns::text[]) AND ad.active = TRUE
), requested_values AS (
    SELECT av.id, av.attribute_definition_id, av.active, vf.fqn
    FROM attribute_fqns vf
    JOIN attribute_values av ON av.id = vf.value_id
    JOIN definitions d ON d.id = av.attribute_definition_id
    WHERE vf.fqn = ANY(@value_fqns::text[])
), selected_values AS (
    SELECT * FROM requested_values
    UNION ALL
    SELECT av.id, av.attribute_definition_id, av.active, vf.fqn
    FROM definitions d
    JOIN attribute_values av ON av.attribute_definition_id = d.id AND av.active = TRUE
    JOIN attribute_fqns vf ON vf.value_id = av.id
    WHERE d.rule = 'HIERARCHY' AND NOT EXISTS (SELECT 1 FROM requested_values rv WHERE rv.id = av.id)
)
SELECT d.id AS definition_id, d.definition_fqn, d.rule, d.allow_traversal,
    ns.id AS namespace_id, ns.name AS namespace_name, nf.fqn AS namespace_fqn,
    COALESCE(v.id::text, '')::text AS value_id,
    COALESCE(v.fqn, '')::text AS value_fqn,
    COALESCE(v.active, FALSE)::boolean AS value_active
FROM definitions d
JOIN attribute_namespaces ns ON ns.id = d.namespace_id
JOIN attribute_fqns nf ON nf.namespace_id = ns.id AND nf.attribute_id IS NULL AND nf.value_id IS NULL
LEFT JOIN selected_values v ON v.attribute_definition_id = d.id
ORDER BY d.id, CASE WHEN d.rule = 'HIERARCHY' THEN ARRAY_POSITION(d.values_order, v.id) END, v.id;
