package db

import (
	"context"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/opentdf-v2-poc/sdk/common"
	kasr "github.com/opentdf/opentdf-v2-poc/sdk/kasregistry"
	"google.golang.org/protobuf/encoding/protojson"
)

var KeyAccessServerTable = tableName(TableKeyAccessServerRegistry)

func keyAccessServerSelect() sq.SelectBuilder {
	return newStatementBuilder().
		Select(
			"id",
			"key_access_server",
			"public_key",
			"metadata",
		)
}

func listAllKeyAccessServersSql() (string, []interface{}, error) {
	return keyAccessServerSelect().
		From(KeyAccessServerTable).
		ToSql()
}

func (c Client) ListKeyAccessServers(ctx context.Context) ([]*kasr.KeyAccessServer, error) {
	sql, args, err := listAllKeyAccessServersSql()

	rows, err := c.query(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}
	var keyAccessServers []*kasr.KeyAccessServer

	var (
		id            string
		name          string
		publicKeyJSON []byte
		metadataJSON  []byte
	)

	_, err = pgx.ForEachRow(rows, []any{&id, &name, &publicKeyJSON, &metadataJSON}, func() error {
		var (
			keyAccessServer = new(kasr.KeyAccessServer)
			publicKey       = new(kasr.PublicKey)
			metadata        = new(common.Metadata)
		)

		if err := protojson.Unmarshal(publicKeyJSON, publicKey); err != nil {
			return err
		}

		if metadataJSON != nil {
			if err := protojson.Unmarshal(metadataJSON, metadata); err != nil {
				return err
			}
		}

		keyAccessServer.Id = id
		keyAccessServer.Name = name
		keyAccessServer.PublicKey = publicKey
		keyAccessServer.Metadata = metadata

		keyAccessServers = append(keyAccessServers, keyAccessServer)

		return nil
	})

	if err != nil {
		return nil, err
	}

	return keyAccessServers, nil
}

func getKeyAccessServerSql(id string) (string, []interface{}, error) {
	return keyAccessServerSelect().
		Where(sq.Eq{"id": id}).
		From(KeyAccessServerTable).
		ToSql()
}

func (c Client) GetKeyAccessServer(ctx context.Context, id string) (*kasr.KeyAccessServer, error) {
	sql, args, err := getKeyAccessServerSql(id)

	row, err := c.queryRow(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}

	var (
		name          string
		publicKeyJSON []byte
		publicKey     = new(kasr.PublicKey)
		metadataJSON  []byte
		metadata      = new(common.Metadata)
	)
	err = row.Scan(&id, &name, &publicKeyJSON, &metadataJSON)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, err
		}
		return nil, err
	}

	if err := protojson.Unmarshal(publicKeyJSON, publicKey); err != nil {
		return nil, err
	}

	if metadataJSON != nil {
		if err := protojson.Unmarshal(metadataJSON, metadata); err != nil {
			return nil, err
		}
	}

	return &kasr.KeyAccessServer{
		Metadata:  metadata,
		Id:        id,
		Name:      name,
		PublicKey: publicKey,
	}, nil
}

func createKeyAccessServerSQL(name string, publicKey, metadata []byte) (string, []interface{}, error) {
	return newStatementBuilder().
		Insert(KeyAccessServerTable).
		Columns("key_access_server", "public_key", "metadata").
		Values(name, publicKey, metadata).
		Suffix("RETURNING \"id\"").
		ToSql()
}

func (c Client) CreateKeyAccessServer(ctx context.Context, keyAccessServer *kasr.KeyAccessServerCreateUpdate) (*kasr.KeyAccessServer, error) {
	metadataBytes, newMetadata, err := marshalCreateMetadata(keyAccessServer.Metadata)
	if err != nil {
		return nil, err
	}

	pkBytes, err := protojson.Marshal(keyAccessServer.PublicKey)
	if err != nil {
		return nil, err
	}

	sql, args, err := createKeyAccessServerSQL(keyAccessServer.Name, pkBytes, metadataBytes)

	row, err := c.queryRow(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}

	// Get ID of new resource
	var id string
	if err = row.Scan(&id); err != nil {
		return nil, err
	}

	return &kasr.KeyAccessServer{
		Metadata:  newMetadata,
		Id:        id,
		Name:      keyAccessServer.Name,
		PublicKey: keyAccessServer.PublicKey,
	}, nil
}

func updateKeyAccessServerSQL(id, name string, publicKey, metadata []byte) (string, []interface{}, error) {
	return newStatementBuilder().
		Update(KeyAccessServerTable).
		Set("key_access_server", name).
		Set("public_key", publicKey).
		Set("metadata", metadata).
		Where(sq.Eq{"id": id}).
		ToSql()
}

func (c Client) UpdateKeyAccessServer(ctx context.Context, id string, keyAccessServer *kasr.KeyAccessServerCreateUpdate) (*kasr.KeyAccessServer, error) {
	k, err := c.GetKeyAccessServer(ctx, id)
	if err != nil {
		return nil, err
	}

	metadataJSON, _, err := marshalUpdateMetadata(k.Metadata, keyAccessServer.Metadata)
	if err != nil {
		return nil, err
	}

	publicKeyJSON, err := protojson.Marshal(keyAccessServer.PublicKey)
	if err != nil {
		return nil, err
	}

	sql, args, err := updateKeyAccessServerSQL(id, keyAccessServer.Name, publicKeyJSON, metadataJSON)

	if err = c.exec(ctx, sql, args, err); err != nil {
		return nil, err
	}

	return k, nil
}

func deleteKeyAccessServerSQL(id string) (string, []interface{}, error) {
	return newStatementBuilder().
		Delete(KeyAccessServerTable).
		Where(sq.Eq{"id": id}).
		ToSql()
}

func (c Client) DeleteKeyAccessServer(ctx context.Context, id string) (*kasr.KeyAccessServer, error) {
	// get attribute before deleting
	k, err := c.GetKeyAccessServer(ctx, id)
	if err != nil {
		return nil, err
	}

	sql, args, err := deleteKeyAccessServerSQL(id)

	if err := c.exec(ctx, sql, args, err); err != nil {
		return nil, err
	}

	// return the attribute before deleting
	return k, nil
}
