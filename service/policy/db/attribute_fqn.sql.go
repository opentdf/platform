// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.29.0
// source: attribute_fqn.sql

package db

import (
	"context"
)

const upsertAttributeDefinitionFqn = `-- name: upsertAttributeDefinitionFqn :many
WITH new_fqns_cte AS (
    -- get attribute definition fqns
    SELECT
        ns.id AS namespace_id,
        ad.id AS attribute_id,
        NULL::UUID AS value_id,
        CONCAT('https://', ns.name, '/attr/', ad.name) AS fqn
    FROM attribute_definitions ad
    JOIN attribute_namespaces ns ON ad.namespace_id = ns.id
    WHERE ad.id = $1 
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
    WHERE ad.id = $1 
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
    fqn
`

type upsertAttributeDefinitionFqnRow struct {
	NamespaceID string `json:"namespace_id"`
	AttributeID string `json:"attribute_id"`
	ValueID     string `json:"value_id"`
	Fqn         string `json:"fqn"`
}

// upsertAttributeDefinitionFqn
//
//	WITH new_fqns_cte AS (
//	    -- get attribute definition fqns
//	    SELECT
//	        ns.id AS namespace_id,
//	        ad.id AS attribute_id,
//	        NULL::UUID AS value_id,
//	        CONCAT('https://', ns.name, '/attr/', ad.name) AS fqn
//	    FROM attribute_definitions ad
//	    JOIN attribute_namespaces ns ON ad.namespace_id = ns.id
//	    WHERE ad.id = $1
//	    UNION
//	    -- get attribute value fqns
//	    SELECT
//	        ns.id as namespace_id,
//	        ad.id as attribute_id,
//	        av.id as value_id,
//	        CONCAT('https://', ns.name, '/attr/', ad.name, '/value/', av.value) AS fqn
//	    FROM attribute_values av
//	    JOIN attribute_definitions ad on av.attribute_definition_id = ad.id
//	    JOIN attribute_namespaces ns on ad.namespace_id = ns.id
//	    WHERE ad.id = $1
//	)
//	INSERT INTO attribute_fqns (namespace_id, attribute_id, value_id, fqn)
//	SELECT
//	    namespace_id,
//	    attribute_id,
//	    value_id,
//	    fqn
//	FROM new_fqns_cte
//	ON CONFLICT (namespace_id, attribute_id, value_id)
//	    DO UPDATE
//	        SET fqn = EXCLUDED.fqn
//	RETURNING
//	    COALESCE(namespace_id::TEXT, '')::TEXT as namespace_id,
//	    COALESCE(attribute_id::TEXT, '')::TEXT as attribute_id,
//	    COALESCE(value_id::TEXT, '')::TEXT as value_id,
//	    fqn
func (q *Queries) upsertAttributeDefinitionFqn(ctx context.Context, attributeID string) ([]upsertAttributeDefinitionFqnRow, error) {
	rows, err := q.db.Query(ctx, upsertAttributeDefinitionFqn, attributeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []upsertAttributeDefinitionFqnRow
	for rows.Next() {
		var i upsertAttributeDefinitionFqnRow
		if err := rows.Scan(
			&i.NamespaceID,
			&i.AttributeID,
			&i.ValueID,
			&i.Fqn,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const upsertAttributeNamespaceFqn = `-- name: upsertAttributeNamespaceFqn :many
WITH new_fqns_cte AS (
    -- get namespace fqns
    SELECT
        ns.id as namespace_id,
        NULL::UUID as attribute_id,
        NULL::UUID as value_id,
        CONCAT('https://', ns.name) AS fqn
    FROM attribute_namespaces ns
    WHERE ns.id = $1 
    UNION
    -- get attribute definition fqns
    SELECT
        ns.id as namespace_id,
        ad.id as attribute_id,
        NULL::UUID as value_id,
        CONCAT('https://', ns.name, '/attr/', ad.name) AS fqn
    FROM attribute_definitions ad
    JOIN attribute_namespaces ns on ad.namespace_id = ns.id
    WHERE ns.id = $1 
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
    WHERE ns.id = $1 
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
    fqn
`

type upsertAttributeNamespaceFqnRow struct {
	NamespaceID string `json:"namespace_id"`
	AttributeID string `json:"attribute_id"`
	ValueID     string `json:"value_id"`
	Fqn         string `json:"fqn"`
}

// upsertAttributeNamespaceFqn
//
//	WITH new_fqns_cte AS (
//	    -- get namespace fqns
//	    SELECT
//	        ns.id as namespace_id,
//	        NULL::UUID as attribute_id,
//	        NULL::UUID as value_id,
//	        CONCAT('https://', ns.name) AS fqn
//	    FROM attribute_namespaces ns
//	    WHERE ns.id = $1
//	    UNION
//	    -- get attribute definition fqns
//	    SELECT
//	        ns.id as namespace_id,
//	        ad.id as attribute_id,
//	        NULL::UUID as value_id,
//	        CONCAT('https://', ns.name, '/attr/', ad.name) AS fqn
//	    FROM attribute_definitions ad
//	    JOIN attribute_namespaces ns on ad.namespace_id = ns.id
//	    WHERE ns.id = $1
//	    UNION
//	    -- get attribute value fqns
//	    SELECT
//	        ns.id as namespace_id,
//	        ad.id as attribute_id,
//	        av.id as value_id,
//	        CONCAT('https://', ns.name, '/attr/', ad.name, '/value/', av.value) AS fqn
//	    FROM attribute_values av
//	    JOIN attribute_definitions ad on av.attribute_definition_id = ad.id
//	    JOIN attribute_namespaces ns on ad.namespace_id = ns.id
//	    WHERE ns.id = $1
//	)
//	INSERT INTO attribute_fqns (namespace_id, attribute_id, value_id, fqn)
//	SELECT
//	    namespace_id,
//	    attribute_id,
//	    value_id,
//	    fqn
//	FROM new_fqns_cte
//	ON CONFLICT (namespace_id, attribute_id, value_id)
//	    DO UPDATE
//	        SET fqn = EXCLUDED.fqn
//	RETURNING
//	    COALESCE(namespace_id::TEXT, '')::TEXT as namespace_id,
//	    COALESCE(attribute_id::TEXT, '')::TEXT as attribute_id,
//	    COALESCE(value_id::TEXT, '')::TEXT as value_id,
//	    fqn
func (q *Queries) upsertAttributeNamespaceFqn(ctx context.Context, namespaceID string) ([]upsertAttributeNamespaceFqnRow, error) {
	rows, err := q.db.Query(ctx, upsertAttributeNamespaceFqn, namespaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []upsertAttributeNamespaceFqnRow
	for rows.Next() {
		var i upsertAttributeNamespaceFqnRow
		if err := rows.Scan(
			&i.NamespaceID,
			&i.AttributeID,
			&i.ValueID,
			&i.Fqn,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const upsertAttributeValueFqn = `-- name: upsertAttributeValueFqn :many

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
    WHERE av.id = $1 
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
    fqn
`

type upsertAttributeValueFqnRow struct {
	NamespaceID string `json:"namespace_id"`
	AttributeID string `json:"attribute_id"`
	ValueID     string `json:"value_id"`
	Fqn         string `json:"fqn"`
}

// --------------------------------------------------------------
// ATTRIBUTE FQN
// --------------------------------------------------------------
//
//	WITH new_fqns_cte AS (
//	    -- get attribute value fqns
//	    SELECT
//	        ns.id AS namespace_id,
//	        ad.id AS attribute_id,
//	        av.id AS value_id,
//	        CONCAT('https://', ns.name, '/attr/', ad.name, '/value/', av.value) AS fqn
//	    FROM attribute_values av
//	    INNER JOIN attribute_definitions AS ad ON av.attribute_definition_id = ad.id
//	    INNER JOIN attribute_namespaces AS ns ON ad.namespace_id = ns.id
//	    WHERE av.id = $1
//	)
//
//	INSERT INTO attribute_fqns (namespace_id, attribute_id, value_id, fqn)
//	SELECT
//	    namespace_id,
//	    attribute_id,
//	    value_id,
//	    fqn
//	FROM new_fqns_cte
//	ON CONFLICT (namespace_id, attribute_id, value_id)
//	    DO UPDATE
//	        SET fqn = EXCLUDED.fqn
//	RETURNING
//	    COALESCE(namespace_id::TEXT, '')::TEXT AS namespace_id,
//	    COALESCE(attribute_id::TEXT, '')::TEXT AS attribute_id,
//	    COALESCE(value_id::TEXT, '')::TEXT AS value_id,
//	    fqn
func (q *Queries) upsertAttributeValueFqn(ctx context.Context, valueID string) ([]upsertAttributeValueFqnRow, error) {
	rows, err := q.db.Query(ctx, upsertAttributeValueFqn, valueID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []upsertAttributeValueFqnRow
	for rows.Next() {
		var i upsertAttributeValueFqnRow
		if err := rows.Scan(
			&i.NamespaceID,
			&i.AttributeID,
			&i.ValueID,
			&i.Fqn,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}
