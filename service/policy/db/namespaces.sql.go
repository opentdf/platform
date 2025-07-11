// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.29.0
// source: namespaces.sql

package db

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
)

const assignPublicKeyToNamespace = `-- name: assignPublicKeyToNamespace :one
INSERT INTO attribute_namespace_public_key_map (namespace_id, key_access_server_key_id)
VALUES ($1, $2)
RETURNING namespace_id, key_access_server_key_id
`

type assignPublicKeyToNamespaceParams struct {
	NamespaceID          string `json:"namespace_id"`
	KeyAccessServerKeyID string `json:"key_access_server_key_id"`
}

// assignPublicKeyToNamespace
//
//	INSERT INTO attribute_namespace_public_key_map (namespace_id, key_access_server_key_id)
//	VALUES ($1, $2)
//	RETURNING namespace_id, key_access_server_key_id
func (q *Queries) assignPublicKeyToNamespace(ctx context.Context, arg assignPublicKeyToNamespaceParams) (AttributeNamespacePublicKeyMap, error) {
	row := q.db.QueryRow(ctx, assignPublicKeyToNamespace, arg.NamespaceID, arg.KeyAccessServerKeyID)
	var i AttributeNamespacePublicKeyMap
	err := row.Scan(&i.NamespaceID, &i.KeyAccessServerKeyID)
	return i, err
}

const createNamespace = `-- name: createNamespace :one
INSERT INTO attribute_namespaces (name, metadata)
VALUES ($1, $2)
RETURNING id
`

type createNamespaceParams struct {
	Name     string `json:"name"`
	Metadata []byte `json:"metadata"`
}

// createNamespace
//
//	INSERT INTO attribute_namespaces (name, metadata)
//	VALUES ($1, $2)
//	RETURNING id
func (q *Queries) createNamespace(ctx context.Context, arg createNamespaceParams) (string, error) {
	row := q.db.QueryRow(ctx, createNamespace, arg.Name, arg.Metadata)
	var id string
	err := row.Scan(&id)
	return id, err
}

const deleteNamespace = `-- name: deleteNamespace :execrows
DELETE FROM attribute_namespaces WHERE id = $1
`

// deleteNamespace
//
//	DELETE FROM attribute_namespaces WHERE id = $1
func (q *Queries) deleteNamespace(ctx context.Context, id string) (int64, error) {
	result, err := q.db.Exec(ctx, deleteNamespace, id)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

const getNamespace = `-- name: getNamespace :one
SELECT
    ns.id,
    ns.name,
    ns.active,
    fqns.fqn,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', ns.metadata -> 'labels', 'created_at', ns.created_at, 'updated_at', ns.updated_at)) as metadata,
    JSONB_AGG(DISTINCT JSONB_BUILD_OBJECT(
        'id', kas.id,
        'uri', kas.uri,
        'name', kas.name,
        'public_key', kas.public_key
    )) FILTER (WHERE kas_ns_grants.namespace_id IS NOT NULL) as grants,
    nmp_keys.keys as keys
FROM attribute_namespaces ns
LEFT JOIN attribute_namespace_key_access_grants kas_ns_grants ON kas_ns_grants.namespace_id = ns.id
LEFT JOIN key_access_servers kas ON kas.id = kas_ns_grants.key_access_server_id
LEFT JOIN attribute_fqns fqns ON fqns.namespace_id = ns.id
LEFT JOIN (
    SELECT
        k.namespace_id,
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
    FROM attribute_namespace_public_key_map k
    INNER JOIN key_access_server_keys kask ON k.key_access_server_key_id = kask.id
    INNER JOIN key_access_servers kas ON kask.key_access_server_id = kas.id
    GROUP BY k.namespace_id
) nmp_keys ON ns.id = nmp_keys.namespace_id
WHERE fqns.attribute_id IS NULL AND fqns.value_id IS NULL 
  AND ($1::uuid IS NULL OR ns.id = $1::uuid)
  AND ($2::text IS NULL OR ns.name = REGEXP_REPLACE($2::text, '^https?://', ''))
GROUP BY ns.id, fqns.fqn, nmp_keys.keys
`

type getNamespaceParams struct {
	ID   pgtype.UUID `json:"id"`
	Name pgtype.Text `json:"name"`
}

type getNamespaceRow struct {
	ID       string      `json:"id"`
	Name     string      `json:"name"`
	Active   bool        `json:"active"`
	Fqn      pgtype.Text `json:"fqn"`
	Metadata []byte      `json:"metadata"`
	Grants   []byte      `json:"grants"`
	Keys     []byte      `json:"keys"`
}

// getNamespace
//
//	SELECT
//	    ns.id,
//	    ns.name,
//	    ns.active,
//	    fqns.fqn,
//	    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', ns.metadata -> 'labels', 'created_at', ns.created_at, 'updated_at', ns.updated_at)) as metadata,
//	    JSONB_AGG(DISTINCT JSONB_BUILD_OBJECT(
//	        'id', kas.id,
//	        'uri', kas.uri,
//	        'name', kas.name,
//	        'public_key', kas.public_key
//	    )) FILTER (WHERE kas_ns_grants.namespace_id IS NOT NULL) as grants,
//	    nmp_keys.keys as keys
//	FROM attribute_namespaces ns
//	LEFT JOIN attribute_namespace_key_access_grants kas_ns_grants ON kas_ns_grants.namespace_id = ns.id
//	LEFT JOIN key_access_servers kas ON kas.id = kas_ns_grants.key_access_server_id
//	LEFT JOIN attribute_fqns fqns ON fqns.namespace_id = ns.id
//	LEFT JOIN (
//	    SELECT
//	        k.namespace_id,
//	        JSONB_AGG(
//	            DISTINCT JSONB_BUILD_OBJECT(
//	                'kas_uri', kas.uri,
//	                'kas_id', kas.id,
//	                'public_key', JSONB_BUILD_OBJECT(
//	                     'algorithm', kask.key_algorithm::INTEGER,
//	                     'kid', kask.key_id,
//	                     'pem', CONVERT_FROM(DECODE(kask.public_key_ctx ->> 'pem', 'base64'), 'UTF8')
//	                )
//	            )
//	        ) FILTER (WHERE kask.id IS NOT NULL) AS keys
//	    FROM attribute_namespace_public_key_map k
//	    INNER JOIN key_access_server_keys kask ON k.key_access_server_key_id = kask.id
//	    INNER JOIN key_access_servers kas ON kask.key_access_server_id = kas.id
//	    GROUP BY k.namespace_id
//	) nmp_keys ON ns.id = nmp_keys.namespace_id
//	WHERE fqns.attribute_id IS NULL AND fqns.value_id IS NULL
//	  AND ($1::uuid IS NULL OR ns.id = $1::uuid)
//	  AND ($2::text IS NULL OR ns.name = REGEXP_REPLACE($2::text, '^https?://', ''))
//	GROUP BY ns.id, fqns.fqn, nmp_keys.keys
func (q *Queries) getNamespace(ctx context.Context, arg getNamespaceParams) (getNamespaceRow, error) {
	row := q.db.QueryRow(ctx, getNamespace, arg.ID, arg.Name)
	var i getNamespaceRow
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.Active,
		&i.Fqn,
		&i.Metadata,
		&i.Grants,
		&i.Keys,
	)
	return i, err
}

const listNamespaces = `-- name: listNamespaces :many

WITH counted AS (
    SELECT COUNT(id) AS total FROM attribute_namespaces
)
SELECT
    ns.id,
    ns.name,
    ns.active,
    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', ns.metadata -> 'labels', 'created_at', ns.created_at, 'updated_at', ns.updated_at)) as metadata,
    fqns.fqn,
    counted.total
FROM attribute_namespaces ns
CROSS JOIN counted
LEFT JOIN attribute_fqns fqns ON ns.id = fqns.namespace_id AND fqns.attribute_id IS NULL
WHERE ($1::BOOLEAN IS NULL OR ns.active = $1::BOOLEAN)
LIMIT $3 
OFFSET $2
`

type listNamespacesParams struct {
	Active pgtype.Bool `json:"active"`
	Offset int32       `json:"offset_"`
	Limit  int32       `json:"limit_"`
}

type listNamespacesRow struct {
	ID       string      `json:"id"`
	Name     string      `json:"name"`
	Active   bool        `json:"active"`
	Metadata []byte      `json:"metadata"`
	Fqn      pgtype.Text `json:"fqn"`
	Total    int64       `json:"total"`
}

// --------------------------------------------------------------
// NAMESPACES
// --------------------------------------------------------------
//
//	WITH counted AS (
//	    SELECT COUNT(id) AS total FROM attribute_namespaces
//	)
//	SELECT
//	    ns.id,
//	    ns.name,
//	    ns.active,
//	    JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', ns.metadata -> 'labels', 'created_at', ns.created_at, 'updated_at', ns.updated_at)) as metadata,
//	    fqns.fqn,
//	    counted.total
//	FROM attribute_namespaces ns
//	CROSS JOIN counted
//	LEFT JOIN attribute_fqns fqns ON ns.id = fqns.namespace_id AND fqns.attribute_id IS NULL
//	WHERE ($1::BOOLEAN IS NULL OR ns.active = $1::BOOLEAN)
//	LIMIT $3
//	OFFSET $2
func (q *Queries) listNamespaces(ctx context.Context, arg listNamespacesParams) ([]listNamespacesRow, error) {
	rows, err := q.db.Query(ctx, listNamespaces, arg.Active, arg.Offset, arg.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []listNamespacesRow
	for rows.Next() {
		var i listNamespacesRow
		if err := rows.Scan(
			&i.ID,
			&i.Name,
			&i.Active,
			&i.Metadata,
			&i.Fqn,
			&i.Total,
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

const removeKeyAccessServerFromNamespace = `-- name: removeKeyAccessServerFromNamespace :execrows
DELETE FROM attribute_namespace_key_access_grants
WHERE namespace_id = $1 AND key_access_server_id = $2
`

type removeKeyAccessServerFromNamespaceParams struct {
	NamespaceID       string `json:"namespace_id"`
	KeyAccessServerID string `json:"key_access_server_id"`
}

// removeKeyAccessServerFromNamespace
//
//	DELETE FROM attribute_namespace_key_access_grants
//	WHERE namespace_id = $1 AND key_access_server_id = $2
func (q *Queries) removeKeyAccessServerFromNamespace(ctx context.Context, arg removeKeyAccessServerFromNamespaceParams) (int64, error) {
	result, err := q.db.Exec(ctx, removeKeyAccessServerFromNamespace, arg.NamespaceID, arg.KeyAccessServerID)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

const removePublicKeyFromNamespace = `-- name: removePublicKeyFromNamespace :execrows
DELETE FROM attribute_namespace_public_key_map
WHERE namespace_id = $1 AND key_access_server_key_id = $2
`

type removePublicKeyFromNamespaceParams struct {
	NamespaceID          string `json:"namespace_id"`
	KeyAccessServerKeyID string `json:"key_access_server_key_id"`
}

// removePublicKeyFromNamespace
//
//	DELETE FROM attribute_namespace_public_key_map
//	WHERE namespace_id = $1 AND key_access_server_key_id = $2
func (q *Queries) removePublicKeyFromNamespace(ctx context.Context, arg removePublicKeyFromNamespaceParams) (int64, error) {
	result, err := q.db.Exec(ctx, removePublicKeyFromNamespace, arg.NamespaceID, arg.KeyAccessServerKeyID)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

const rotatePublicKeyForNamespace = `-- name: rotatePublicKeyForNamespace :many
UPDATE attribute_namespace_public_key_map
SET key_access_server_key_id = $1::uuid
WHERE (key_access_server_key_id = $2::uuid)
RETURNING namespace_id
`

type rotatePublicKeyForNamespaceParams struct {
	NewKeyID string `json:"new_key_id"`
	OldKeyID string `json:"old_key_id"`
}

// rotatePublicKeyForNamespace
//
//	UPDATE attribute_namespace_public_key_map
//	SET key_access_server_key_id = $1::uuid
//	WHERE (key_access_server_key_id = $2::uuid)
//	RETURNING namespace_id
func (q *Queries) rotatePublicKeyForNamespace(ctx context.Context, arg rotatePublicKeyForNamespaceParams) ([]string, error) {
	rows, err := q.db.Query(ctx, rotatePublicKeyForNamespace, arg.NewKeyID, arg.OldKeyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []string
	for rows.Next() {
		var namespace_id string
		if err := rows.Scan(&namespace_id); err != nil {
			return nil, err
		}
		items = append(items, namespace_id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const updateNamespace = `-- name: updateNamespace :execrows
UPDATE attribute_namespaces
SET
    name = COALESCE($2, name),
    active = COALESCE($3, active),
    metadata = COALESCE($4, metadata)
WHERE id = $1
`

type updateNamespaceParams struct {
	ID       string      `json:"id"`
	Name     pgtype.Text `json:"name"`
	Active   pgtype.Bool `json:"active"`
	Metadata []byte      `json:"metadata"`
}

// updateNamespace: both Safe and Unsafe Updates
//
//	UPDATE attribute_namespaces
//	SET
//	    name = COALESCE($2, name),
//	    active = COALESCE($3, active),
//	    metadata = COALESCE($4, metadata)
//	WHERE id = $1
func (q *Queries) updateNamespace(ctx context.Context, arg updateNamespaceParams) (int64, error) {
	result, err := q.db.Exec(ctx, updateNamespace,
		arg.ID,
		arg.Name,
		arg.Active,
		arg.Metadata,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}
