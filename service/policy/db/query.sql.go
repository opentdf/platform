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

const getResourceMappingGroupByFqn = `-- name: GetResourceMappingGroupByFqn :one
SELECT g.id, g.namespace_id, g.name
FROM resource_mapping_groups g
LEFT JOIN attribute_namespaces ns ON g.namespace_id = ns.id
WHERE ns.name = LOWER($1) AND g.name = LOWER($2)
`

type GetResourceMappingGroupByFqnParams struct {
	NamespaceName string `json:"namespace_name"`
	GroupName     string `json:"group_name"`
}

// GetResourceMappingGroupByFqn
//
//	SELECT g.id, g.namespace_id, g.name
//	FROM resource_mapping_groups g
//	LEFT JOIN attribute_namespaces ns ON g.namespace_id = ns.id
//	WHERE ns.name = LOWER($1) AND g.name = LOWER($2)
func (q *Queries) GetResourceMappingGroupByFqn(ctx context.Context, arg GetResourceMappingGroupByFqnParams) (ResourceMappingGroup, error) {
	row := q.db.QueryRow(ctx, getResourceMappingGroupByFqn, arg.NamespaceName, arg.GroupName)
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
