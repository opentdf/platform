// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.26.0
// source: query.sql

package db

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
)

const assignKeyAccessServerToNamespace = `-- name: AssignKeyAccessServerToNamespace :execrows
INSERT INTO attribute_namespace_key_access_grants
(namespace_id, key_access_server_id)
VALUES ($1, $2)
`

type AssignKeyAccessServerToNamespaceParams struct {
	NamespaceID       string `json:"namespace_id"`
	KeyAccessServerID string `json:"key_access_server_id"`
}

// AssignKeyAccessServerToNamespace
//
//	INSERT INTO attribute_namespace_key_access_grants
//	(namespace_id, key_access_server_id)
//	VALUES ($1, $2)
func (q *Queries) AssignKeyAccessServerToNamespace(ctx context.Context, arg AssignKeyAccessServerToNamespaceParams) (int64, error) {
	result, err := q.db.Exec(ctx, assignKeyAccessServerToNamespace, arg.NamespaceID, arg.KeyAccessServerID)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

const createKeyAccessServer = `-- name: CreateKeyAccessServer :one
INSERT INTO key_access_servers (uri, public_key, metadata)
VALUES ($1, $2, $3)
RETURNING id
`

type CreateKeyAccessServerParams struct {
	Uri       string `json:"uri"`
	PublicKey []byte `json:"public_key"`
	Metadata  []byte `json:"metadata"`
}

// CreateKeyAccessServer
//
//	INSERT INTO key_access_servers (uri, public_key, metadata)
//	VALUES ($1, $2, $3)
//	RETURNING id
func (q *Queries) CreateKeyAccessServer(ctx context.Context, arg CreateKeyAccessServerParams) (string, error) {
	row := q.db.QueryRow(ctx, createKeyAccessServer, arg.Uri, arg.PublicKey, arg.Metadata)
	var id string
	err := row.Scan(&id)
	return id, err
}

const createResourceMappingGroup = `-- name: CreateResourceMappingGroup :one
INSERT INTO resource_mapping_groups (namespace_id, name)
VALUES ($1, $2)
RETURNING id
`

type CreateResourceMappingGroupParams struct {
	NamespaceID string `json:"namespace_id"`
	Name        string `json:"name"`
}

// CreateResourceMappingGroup
//
//	INSERT INTO resource_mapping_groups (namespace_id, name)
//	VALUES ($1, $2)
//	RETURNING id
func (q *Queries) CreateResourceMappingGroup(ctx context.Context, arg CreateResourceMappingGroupParams) (string, error) {
	row := q.db.QueryRow(ctx, createResourceMappingGroup, arg.NamespaceID, arg.Name)
	var id string
	err := row.Scan(&id)
	return id, err
}

const deleteKeyAccessServer = `-- name: DeleteKeyAccessServer :execrows
DELETE FROM key_access_servers WHERE id = $1
`

// DeleteKeyAccessServer
//
//	DELETE FROM key_access_servers WHERE id = $1
func (q *Queries) DeleteKeyAccessServer(ctx context.Context, id string) (int64, error) {
	result, err := q.db.Exec(ctx, deleteKeyAccessServer, id)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

const deleteResourceMappingGroup = `-- name: DeleteResourceMappingGroup :execrows
DELETE FROM resource_mapping_groups WHERE id = $1
`

// DeleteResourceMappingGroup
//
//	DELETE FROM resource_mapping_groups WHERE id = $1
func (q *Queries) DeleteResourceMappingGroup(ctx context.Context, id string) (int64, error) {
	result, err := q.db.Exec(ctx, deleteResourceMappingGroup, id)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

const getAttributeByValueFqn = `-- name: GetAttributeByValueFqn :one
WITH target_definition AS (
    SELECT ad.id
    FROM attribute_definitions ad
    INNER JOIN attribute_fqns af ON af.attribute_id = ad.id
    WHERE af.fqn = $1
    LIMIT 1
),
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
namespace_fqn_cte AS (
    SELECT anfqn.namespace_id, anfqn.fqn
    FROM attribute_fqns anfqn
    WHERE anfqn.attribute_id IS NULL AND anfqn.value_id IS NULL
),
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
target_definition_fqn_cte AS (
    SELECT af.fqn
    FROM attribute_fqns af
    WHERE af.namespace_id = (SELECT namespace_id FROM attribute_definitions WHERE id = (SELECT id FROM target_definition))
    AND af.attribute_id = (SELECT id FROM target_definition)
    AND af.value_id IS NULL
),
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
        ) ORDER BY array_position(ad.values_order, avt.id)
    ) AS values
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
    ad.id, an.id, nfq.fqn, n_grants.grants
`

type GetAttributeByValueFqnRow struct {
	ID            string                  `json:"id"`
	Name          string                  `json:"name"`
	Rule          AttributeDefinitionRule `json:"rule"`
	Metadata      []byte                  `json:"metadata"`
	Active        bool                    `json:"active"`
	Namespace     []byte                  `json:"namespace"`
	DefinitionFqn string                  `json:"definition_fqn"`
	Values        []byte                  `json:"values"`
}

// get the attribute definition for the provided value or definition fqn
// get the active values with KAS grants under the attribute definition
// get the namespace fqn for the attribute definition
// get the grants for the attribute's namespace
// get the definition fqn for the attribute definition (could have been provided a value fqn initially)
// get the subject mappings for the active values under the attribute definition
// get the attribute definition and give structure to the result
//
//	WITH target_definition AS (
//	    SELECT ad.id
//	    FROM attribute_definitions ad
//	    INNER JOIN attribute_fqns af ON af.attribute_id = ad.id
//	    WHERE af.fqn = $1
//	    LIMIT 1
//	),
//	active_attribute_values AS (
//	    SELECT
//	        av.id,
//	        av.value,
//	        av.active,
//	        av.attribute_definition_id,
//	        JSON_AGG(
//	            DISTINCT JSONB_BUILD_OBJECT(
//	                'id', vkas.id,
//	                'uri', vkas.uri,
//	                'public_key', vkas.public_key
//	            )
//	        ) FILTER (WHERE vkas.id IS NOT NULL AND vkas.uri IS NOT NULL AND vkas.public_key IS NOT NULL) AS val_grants_arr
//	    FROM
//	        attribute_values av
//	    LEFT JOIN attribute_value_key_access_grants avg ON av.id = avg.attribute_value_id
//	    LEFT JOIN key_access_servers vkas ON avg.key_access_server_id = vkas.id
//	    WHERE av.active = TRUE
//	    AND av.attribute_definition_id = (SELECT id FROM target_definition)
//	    GROUP BY av.id
//	),
//	namespace_fqn_cte AS (
//	    SELECT anfqn.namespace_id, anfqn.fqn
//	    FROM attribute_fqns anfqn
//	    WHERE anfqn.attribute_id IS NULL AND anfqn.value_id IS NULL
//	),
//	namespace_grants_cte AS (
//	    SELECT
//	        ankag.namespace_id,
//	        JSONB_AGG(
//	            DISTINCT JSONB_BUILD_OBJECT(
//	                'id', kas.id,
//	                'uri', kas.uri,
//	                'public_key', kas.public_key
//	            )
//	        ) AS grants
//	    FROM
//	        attribute_namespace_key_access_grants ankag
//	    LEFT JOIN key_access_servers kas ON kas.id = ankag.key_access_server_id
//	    GROUP BY ankag.namespace_id
//	),
//	target_definition_fqn_cte AS (
//	    SELECT af.fqn
//	    FROM attribute_fqns af
//	    WHERE af.namespace_id = (SELECT namespace_id FROM attribute_definitions WHERE id = (SELECT id FROM target_definition))
//	    AND af.attribute_id = (SELECT id FROM target_definition)
//	    AND af.value_id IS NULL
//	),
//	subject_mappings_cte AS (
//	    SELECT
//	        av.id AS av_id,
//	        JSON_AGG(
//	            JSON_BUILD_OBJECT(
//	                'id', sm.id,
//	                'actions', sm.actions,
//	                'metadata', JSON_STRIP_NULLS(JSON_BUILD_OBJECT(
//	                    'labels', sm.metadata -> 'labels',
//	                    'created_at', sm.created_at,
//	                    'updated_at', sm.updated_at
//	                )),
//	                'subject_condition_set', JSON_BUILD_OBJECT(
//	                    'id', scs.id,
//	                    'metadata', JSON_STRIP_NULLS(JSON_BUILD_OBJECT(
//	                        'labels', scs.metadata -> 'labels',
//	                        'created_at', scs.created_at,
//	                        'updated_at', scs.updated_at
//	                    )),
//	                    'subject_sets', scs.condition
//	                )
//	            )
//	        ) AS sub_maps_arr
//	    FROM
//	        subject_mappings sm
//	    LEFT JOIN attribute_values av ON sm.attribute_value_id = av.id
//	    LEFT JOIN subject_condition_set scs ON sm.subject_condition_set_id = scs.id
//	    WHERE av.active = TRUE
//	    AND av.attribute_definition_id = (SELECT id FROM target_definition)
//	    GROUP BY av.id
//	)
//	SELECT
//	    ad.id,
//	    ad.name,
//	    ad.rule,
//	    JSON_STRIP_NULLS(
//	        JSON_BUILD_OBJECT(
//	            'labels', ad.metadata -> 'labels',
//	            'created_at', ad.created_at,
//	            'updated_at', ad.updated_at
//	        )
//	    ) AS metadata,
//	    ad.active,
//	    JSON_BUILD_OBJECT(
//	        'name', an.name,
//	        'id', an.id,
//	        'fqn', nfq.fqn,
//	        'grants', n_grants.grants,
//	        'active', an.active
//	    ) AS namespace,
//	    (SELECT fqn FROM target_definition_fqn_cte) AS definition_fqn,
//	    JSON_AGG(
//	        JSON_BUILD_OBJECT(
//	            'id', avt.id,
//	            'value', avt.value,
//	            'active', avt.active,
//	            'fqn', af.fqn,
//	            'subject_mappings', sm.sub_maps_arr,
//	            'grants', avt.val_grants_arr
//	        -- enforce order of values in response
//	        ) ORDER BY array_position(ad.values_order, avt.id)
//	    ) AS values
//	FROM
//	    attribute_definitions ad
//	LEFT JOIN attribute_namespaces an ON an.id = ad.namespace_id
//	LEFT JOIN active_attribute_values avt ON avt.attribute_definition_id = ad.id
//	LEFT JOIN attribute_definition_key_access_grants adkag ON adkag.attribute_definition_id = ad.id
//	LEFT JOIN key_access_servers kas ON kas.id = adkag.key_access_server_id
//	LEFT JOIN attribute_fqns af ON af.value_id = avt.id
//	LEFT JOIN namespace_fqn_cte nfq ON nfq.namespace_id = an.id
//	LEFT JOIN namespace_grants_cte n_grants ON n_grants.namespace_id = an.id
//	LEFT JOIN subject_mappings_cte sm ON avt.id = sm.av_id
//	WHERE
//	    ad.active = TRUE
//	    AND ad.id = (SELECT id FROM target_definition)
//	    AND an.active = TRUE
//	GROUP BY
//	    ad.id, an.id, nfq.fqn, n_grants.grants
func (q *Queries) GetAttributeByValueFqn(ctx context.Context, fqn string) (GetAttributeByValueFqnRow, error) {
	row := q.db.QueryRow(ctx, getAttributeByValueFqn, fqn)
	var i GetAttributeByValueFqnRow
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.Rule,
		&i.Metadata,
		&i.Active,
		&i.Namespace,
		&i.DefinitionFqn,
		&i.Values,
	)
	return i, err
}

const getKeyAccessServer = `-- name: GetKeyAccessServer :one
SELECT id, uri, public_key,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', metadata -> 'labels', 'created_at', created_at, 'updated_at', updated_at)) as metadata
FROM key_access_servers WHERE id = $1
`

type GetKeyAccessServerRow struct {
	ID        string `json:"id"`
	Uri       string `json:"uri"`
	PublicKey []byte `json:"public_key"`
	Metadata  []byte `json:"metadata"`
}

// GetKeyAccessServer
//
//	SELECT id, uri, public_key,
//	    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', metadata -> 'labels', 'created_at', created_at, 'updated_at', updated_at)) as metadata
//	FROM key_access_servers WHERE id = $1
func (q *Queries) GetKeyAccessServer(ctx context.Context, id string) (GetKeyAccessServerRow, error) {
	row := q.db.QueryRow(ctx, getKeyAccessServer, id)
	var i GetKeyAccessServerRow
	err := row.Scan(
		&i.ID,
		&i.Uri,
		&i.PublicKey,
		&i.Metadata,
	)
	return i, err
}

const getNamespace = `-- name: GetNamespace :one

SELECT ns.id, ns.name, ns.active,
    attribute_fqns.fqn as fqn,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', ns.metadata -> 'labels', 'created_at', ns.created_at, 'updated_at', ns.updated_at)) as metadata,
    JSONB_AGG(DISTINCT JSONB_BUILD_OBJECT(
        'id', kas.id, 
        'uri', kas.uri, 
        'public_key', kas.public_key
    )) FILTER (WHERE kas_ns_grants.namespace_id IS NOT NULL) as grants
FROM attribute_namespaces ns
LEFT JOIN attribute_namespace_key_access_grants kas_ns_grants ON kas_ns_grants.namespace_id = ns.id
LEFT JOIN key_access_servers kas ON kas.id = kas_ns_grants.key_access_server_id
LEFT JOIN attribute_fqns ON attribute_fqns.namespace_id = ns.id
WHERE ns.id = $1
AND attribute_fqns.attribute_id IS NULL AND attribute_fqns.value_id IS NULL
GROUP BY ns.id, 
attribute_fqns.fqn
`

type GetNamespaceRow struct {
	ID       string      `json:"id"`
	Name     string      `json:"name"`
	Active   bool        `json:"active"`
	Fqn      pgtype.Text `json:"fqn"`
	Metadata []byte      `json:"metadata"`
	Grants   []byte      `json:"grants"`
}

// --------------------------------------------------------------
// NAMESPACES
// --------------------------------------------------------------
//
//	SELECT ns.id, ns.name, ns.active,
//	    attribute_fqns.fqn as fqn,
//	    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', ns.metadata -> 'labels', 'created_at', ns.created_at, 'updated_at', ns.updated_at)) as metadata,
//	    JSONB_AGG(DISTINCT JSONB_BUILD_OBJECT(
//	        'id', kas.id,
//	        'uri', kas.uri,
//	        'public_key', kas.public_key
//	    )) FILTER (WHERE kas_ns_grants.namespace_id IS NOT NULL) as grants
//	FROM attribute_namespaces ns
//	LEFT JOIN attribute_namespace_key_access_grants kas_ns_grants ON kas_ns_grants.namespace_id = ns.id
//	LEFT JOIN key_access_servers kas ON kas.id = kas_ns_grants.key_access_server_id
//	LEFT JOIN attribute_fqns ON attribute_fqns.namespace_id = ns.id
//	WHERE ns.id = $1
//	AND attribute_fqns.attribute_id IS NULL AND attribute_fqns.value_id IS NULL
//	GROUP BY ns.id,
//	attribute_fqns.fqn
func (q *Queries) GetNamespace(ctx context.Context, id string) (GetNamespaceRow, error) {
	row := q.db.QueryRow(ctx, getNamespace, id)
	var i GetNamespaceRow
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.Active,
		&i.Fqn,
		&i.Metadata,
		&i.Grants,
	)
	return i, err
}

const getResourceMappingGroup = `-- name: GetResourceMappingGroup :one
SELECT id, namespace_id, name
FROM resource_mapping_groups
WHERE id = $1
`

// GetResourceMappingGroup
//
//	SELECT id, namespace_id, name
//	FROM resource_mapping_groups
//	WHERE id = $1
func (q *Queries) GetResourceMappingGroup(ctx context.Context, id string) (ResourceMappingGroup, error) {
	row := q.db.QueryRow(ctx, getResourceMappingGroup, id)
	var i ResourceMappingGroup
	err := row.Scan(&i.ID, &i.NamespaceID, &i.Name)
	return i, err
}

const listKeyAccessServerGrants = `-- name: ListKeyAccessServerGrants :many

SELECT 
    kas.id AS kas_id, 
    kas.uri AS kas_uri, 
    kas.public_key AS kas_public_key,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT(
        'labels', kas.metadata -> 'labels', 
        'created_at', kas.created_at, 
        'updated_at', kas.updated_at
    )) AS kas_metadata,
    json_agg(DISTINCT jsonb_build_object(
        'id', attrkag.attribute_definition_id, 
        'fqn', fqns_on_attr.fqn
    )) FILTER (WHERE attrkag.attribute_definition_id IS NOT NULL) AS attributes_grants,
    json_agg(DISTINCT jsonb_build_object(
        'id', valkag.attribute_value_id, 
        'fqn', fqns_on_vals.fqn
    )) FILTER (WHERE valkag.attribute_value_id IS NOT NULL) AS values_grants,
    json_agg(DISTINCT jsonb_build_object(
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
WHERE (NULLIF($1, '') IS NULL OR kas.id = $1::uuid)
    AND (NULLIF($2, '') IS NULL OR kas.uri = $2::varchar)
GROUP BY 
    kas.id
`

type ListKeyAccessServerGrantsParams struct {
	KasID  interface{} `json:"kas_id"`
	KasUri interface{} `json:"kas_uri"`
}

type ListKeyAccessServerGrantsRow struct {
	KasID            string `json:"kas_id"`
	KasUri           string `json:"kas_uri"`
	KasPublicKey     []byte `json:"kas_public_key"`
	KasMetadata      []byte `json:"kas_metadata"`
	AttributesGrants []byte `json:"attributes_grants"`
	ValuesGrants     []byte `json:"values_grants"`
	NamespaceGrants  []byte `json:"namespace_grants"`
}

// --------------------------------------------------------------
// ATTRIBUTES
// --------------------------------------------------------------
//
//	SELECT
//	    kas.id AS kas_id,
//	    kas.uri AS kas_uri,
//	    kas.public_key AS kas_public_key,
//	    JSON_STRIP_NULLS(JSON_BUILD_OBJECT(
//	        'labels', kas.metadata -> 'labels',
//	        'created_at', kas.created_at,
//	        'updated_at', kas.updated_at
//	    )) AS kas_metadata,
//	    json_agg(DISTINCT jsonb_build_object(
//	        'id', attrkag.attribute_definition_id,
//	        'fqn', fqns_on_attr.fqn
//	    )) FILTER (WHERE attrkag.attribute_definition_id IS NOT NULL) AS attributes_grants,
//	    json_agg(DISTINCT jsonb_build_object(
//	        'id', valkag.attribute_value_id,
//	        'fqn', fqns_on_vals.fqn
//	    )) FILTER (WHERE valkag.attribute_value_id IS NOT NULL) AS values_grants,
//	    json_agg(DISTINCT jsonb_build_object(
//	        'id', nskag.namespace_id,
//	        'fqn', fqns_on_ns.fqn
//	    )) FILTER (WHERE nskag.namespace_id IS NOT NULL) AS namespace_grants
//	FROM
//	    key_access_servers kas
//	LEFT JOIN
//	    attribute_definition_key_access_grants attrkag
//	    ON kas.id = attrkag.key_access_server_id
//	LEFT JOIN
//	    attribute_fqns fqns_on_attr
//	    ON attrkag.attribute_definition_id = fqns_on_attr.attribute_id
//	    AND fqns_on_attr.value_id IS NULL
//	LEFT JOIN
//	    attribute_value_key_access_grants valkag
//	    ON kas.id = valkag.key_access_server_id
//	LEFT JOIN
//	    attribute_fqns fqns_on_vals
//	    ON valkag.attribute_value_id = fqns_on_vals.value_id
//	LEFT JOIN
//	    attribute_namespace_key_access_grants nskag
//	    ON kas.id = nskag.key_access_server_id
//	LEFT JOIN
//	    attribute_fqns fqns_on_ns
//	    ON nskag.namespace_id = fqns_on_ns.namespace_id
//	WHERE (NULLIF($1, '') IS NULL OR kas.id = $1::uuid)
//	    AND (NULLIF($2, '') IS NULL OR kas.uri = $2::varchar)
//	GROUP BY
//	    kas.id
func (q *Queries) ListKeyAccessServerGrants(ctx context.Context, arg ListKeyAccessServerGrantsParams) ([]ListKeyAccessServerGrantsRow, error) {
	rows, err := q.db.Query(ctx, listKeyAccessServerGrants, arg.KasID, arg.KasUri)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []ListKeyAccessServerGrantsRow
	for rows.Next() {
		var i ListKeyAccessServerGrantsRow
		if err := rows.Scan(
			&i.KasID,
			&i.KasUri,
			&i.KasPublicKey,
			&i.KasMetadata,
			&i.AttributesGrants,
			&i.ValuesGrants,
			&i.NamespaceGrants,
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

const listKeyAccessServers = `-- name: ListKeyAccessServers :many

SELECT id, uri, public_key,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', metadata -> 'labels', 'created_at', created_at, 'updated_at', updated_at)) as metadata
FROM key_access_servers
`

type ListKeyAccessServersRow struct {
	ID        string `json:"id"`
	Uri       string `json:"uri"`
	PublicKey []byte `json:"public_key"`
	Metadata  []byte `json:"metadata"`
}

// --------------------------------------------------------------
// KEY ACCESS SERVERS
// --------------------------------------------------------------
//
//	SELECT id, uri, public_key,
//	    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', metadata -> 'labels', 'created_at', created_at, 'updated_at', updated_at)) as metadata
//	FROM key_access_servers
func (q *Queries) ListKeyAccessServers(ctx context.Context) ([]ListKeyAccessServersRow, error) {
	rows, err := q.db.Query(ctx, listKeyAccessServers)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []ListKeyAccessServersRow
	for rows.Next() {
		var i ListKeyAccessServersRow
		if err := rows.Scan(
			&i.ID,
			&i.Uri,
			&i.PublicKey,
			&i.Metadata,
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

const listResourceMappingGroups = `-- name: ListResourceMappingGroups :many

SELECT id, namespace_id, name
FROM resource_mapping_groups
`

// --------------------------------------------------------------
// RESOURCE MAPPING GROUPS
// --------------------------------------------------------------
//
//	SELECT id, namespace_id, name
//	FROM resource_mapping_groups
func (q *Queries) ListResourceMappingGroups(ctx context.Context) ([]ResourceMappingGroup, error) {
	rows, err := q.db.Query(ctx, listResourceMappingGroups)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []ResourceMappingGroup
	for rows.Next() {
		var i ResourceMappingGroup
		if err := rows.Scan(&i.ID, &i.NamespaceID, &i.Name); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const removeKeyAccessServerFromNamespace = `-- name: RemoveKeyAccessServerFromNamespace :execrows
DELETE FROM attribute_namespace_key_access_grants
WHERE namespace_id = $1 AND key_access_server_id = $2
`

type RemoveKeyAccessServerFromNamespaceParams struct {
	NamespaceID       string `json:"namespace_id"`
	KeyAccessServerID string `json:"key_access_server_id"`
}

// RemoveKeyAccessServerFromNamespace
//
//	DELETE FROM attribute_namespace_key_access_grants
//	WHERE namespace_id = $1 AND key_access_server_id = $2
func (q *Queries) RemoveKeyAccessServerFromNamespace(ctx context.Context, arg RemoveKeyAccessServerFromNamespaceParams) (int64, error) {
	result, err := q.db.Exec(ctx, removeKeyAccessServerFromNamespace, arg.NamespaceID, arg.KeyAccessServerID)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

const updateKeyAccessServer = `-- name: UpdateKeyAccessServer :one
UPDATE key_access_servers
SET 
    uri = coalesce($2, uri),
    public_key = coalesce($3, public_key),
    metadata = coalesce($4, metadata)
WHERE id = $1
RETURNING id
`

type UpdateKeyAccessServerParams struct {
	ID        string      `json:"id"`
	Uri       pgtype.Text `json:"uri"`
	PublicKey []byte      `json:"public_key"`
	Metadata  []byte      `json:"metadata"`
}

// UpdateKeyAccessServer
//
//	UPDATE key_access_servers
//	SET
//	    uri = coalesce($2, uri),
//	    public_key = coalesce($3, public_key),
//	    metadata = coalesce($4, metadata)
//	WHERE id = $1
//	RETURNING id
func (q *Queries) UpdateKeyAccessServer(ctx context.Context, arg UpdateKeyAccessServerParams) (string, error) {
	row := q.db.QueryRow(ctx, updateKeyAccessServer,
		arg.ID,
		arg.Uri,
		arg.PublicKey,
		arg.Metadata,
	)
	var id string
	err := row.Scan(&id)
	return id, err
}

const updateResourceMappingGroup = `-- name: UpdateResourceMappingGroup :one
UPDATE resource_mapping_groups
SET
    namespace_id = coalesce($2, namespace_id),
    name = coalesce($3, name)
WHERE id = $1
RETURNING id
`

type UpdateResourceMappingGroupParams struct {
	ID          string      `json:"id"`
	NamespaceID pgtype.UUID `json:"namespace_id"`
	Name        pgtype.Text `json:"name"`
}

// UpdateResourceMappingGroup
//
//	UPDATE resource_mapping_groups
//	SET
//	    namespace_id = coalesce($2, namespace_id),
//	    name = coalesce($3, name)
//	WHERE id = $1
//	RETURNING id
func (q *Queries) UpdateResourceMappingGroup(ctx context.Context, arg UpdateResourceMappingGroupParams) (string, error) {
	row := q.db.QueryRow(ctx, updateResourceMappingGroup, arg.ID, arg.NamespaceID, arg.Name)
	var id string
	err := row.Scan(&id)
	return id, err
}
