---------------------------------------------------------------- 
-- ATTRIBUTE FQN
----------------------------------------------------------------

-- name: upsertAttributeValueFqn :many
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

-- name: upsertAttributeDefinitionFqn :many
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

-- name: upsertAttributeNamespaceFqn :many
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
