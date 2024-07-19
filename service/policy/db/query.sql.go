// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.26.0
// source: query.sql

package db

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
)

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

const getKeyAccessServer = `-- name: GetKeyAccessServer :one
SELECT id, uri, public_key, metadata FROM key_access_servers WHERE id = $1
`

type GetKeyAccessServerRow struct {
	ID        string `json:"id"`
	Uri       string `json:"uri"`
	PublicKey []byte `json:"public_key"`
	Metadata  []byte `json:"metadata"`
}

// GetKeyAccessServer
//
//	SELECT id, uri, public_key, metadata FROM key_access_servers WHERE id = $1
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

const listKeyAccessServers = `-- name: ListKeyAccessServers :many

SELECT id, uri, public_key, metadata FROM key_access_servers
`

type ListKeyAccessServersRow struct {
	ID        string `json:"id"`
	Uri       string `json:"uri"`
	PublicKey []byte `json:"public_key"`
	Metadata  []byte `json:"metadata"`
}

// KEY ACCESS SERVERS
//
//	SELECT id, uri, public_key, metadata FROM key_access_servers
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
