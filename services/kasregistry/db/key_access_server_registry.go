package db

import (
	"context"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/platform/internal/db"
	"github.com/opentdf/platform/protocol/go/common"
	kasr "github.com/opentdf/platform/protocol/go/kasregistry"
	"google.golang.org/protobuf/encoding/protojson"
)

var KeyAccessServerTable string

type KasRegistryDbClient struct {
	db.Client
}

func NewClient(c db.Client) *KasRegistryDbClient {
	KeyAccessServerTable = db.Tables.KeyAccessServerRegistry.Name()

	return &KasRegistryDbClient{c}
}

func keyAccessServerSelect() sq.SelectBuilder {
	return db.NewStatementBuilder().
		Select(
			"id",
			"uri",
			"public_key",
			"metadata",
		)
}

func listAllKeyAccessServersSql() (string, []interface{}, error) {
	return keyAccessServerSelect().
		From(KeyAccessServerTable).
		ToSql()
}

func (c KasRegistryDbClient) ListKeyAccessServers(ctx context.Context) ([]*kasr.KeyAccessServer, error) {
	sql, args, err := listAllKeyAccessServersSql()

	rows, err := c.Query(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}
	var keyAccessServers []*kasr.KeyAccessServer

	var (
		id            string
		uri           string
		publicKeyJSON []byte
		metadataJSON  []byte
	)

	_, err = pgx.ForEachRow(rows, []any{&id, &uri, &publicKeyJSON, &metadataJSON}, func() error {
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
		keyAccessServer.Uri = uri
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

func (c KasRegistryDbClient) GetKeyAccessServer(ctx context.Context, id string) (*kasr.KeyAccessServer, error) {
	sql, args, err := getKeyAccessServerSql(id)

	row, err := c.QueryRow(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}

	var (
		uri           string
		publicKeyJSON []byte
		publicKey     = new(kasr.PublicKey)
		metadataJSON  []byte
		metadata      = new(common.Metadata)
	)
	err = row.Scan(&id, &uri, &publicKeyJSON, &metadataJSON)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
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
		Uri:       uri,
		PublicKey: publicKey,
	}, nil
}

func createKeyAccessServerSQL(uri string, publicKey, metadata []byte) (string, []interface{}, error) {
	return db.NewStatementBuilder().
		Insert(KeyAccessServerTable).
		Columns("uri", "public_key", "metadata").
		Values(uri, publicKey, metadata).
		Suffix("RETURNING \"id\"").
		ToSql()
}

func (c KasRegistryDbClient) CreateKeyAccessServer(ctx context.Context, keyAccessServer *kasr.KeyAccessServerCreateUpdate) (*kasr.KeyAccessServer, error) {
	metadataBytes, newMetadata, err := db.MarshalCreateMetadata(keyAccessServer.Metadata)
	if err != nil {
		return nil, err
	}

	pkBytes, err := protojson.Marshal(keyAccessServer.PublicKey)
	if err != nil {
		return nil, err
	}

	sql, args, err := createKeyAccessServerSQL(keyAccessServer.Uri, pkBytes, metadataBytes)

	row, err := c.QueryRow(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}

	// Get ID of new resource
	var id string
	if err = row.Scan(&id); err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &kasr.KeyAccessServer{
		Metadata:  newMetadata,
		Id:        id,
		Uri:       keyAccessServer.Uri,
		PublicKey: keyAccessServer.PublicKey,
	}, nil
}

func updateKeyAccessServerSQL(id, keyAccessServer string, publicKey, metadata []byte) (string, []interface{}, error) {
	return db.NewStatementBuilder().
		Update(KeyAccessServerTable).
		Set("uri", keyAccessServer).
		Set("public_key", publicKey).
		Set("metadata", metadata).
		Where(sq.Eq{"id": id}).
		ToSql()
}

func (c KasRegistryDbClient) UpdateKeyAccessServer(ctx context.Context, id string, keyAccessServer *kasr.KeyAccessServerCreateUpdate) (*kasr.KeyAccessServer, error) {
	k, err := c.GetKeyAccessServer(ctx, id)
	if err != nil {
		return nil, err
	}

	metadataJSON, _, err := db.MarshalUpdateMetadata(k.Metadata, keyAccessServer.Metadata)
	if err != nil {
		return nil, err
	}

	publicKeyJSON, err := protojson.Marshal(keyAccessServer.PublicKey)
	if err != nil {
		return nil, err
	}

	sql, args, err := updateKeyAccessServerSQL(id, keyAccessServer.Uri, publicKeyJSON, metadataJSON)

	if err = c.Exec(ctx, sql, args, err); err != nil {
		return nil, err
	}

	return k, nil
}

func deleteKeyAccessServerSQL(id string) (string, []interface{}, error) {
	return db.NewStatementBuilder().
		Delete(KeyAccessServerTable).
		Where(sq.Eq{"id": id}).
		ToSql()
}

func (c KasRegistryDbClient) DeleteKeyAccessServer(ctx context.Context, id string) (*kasr.KeyAccessServer, error) {
	// get attribute before deleting
	k, err := c.GetKeyAccessServer(ctx, id)
	if err != nil {
		return nil, err
	}

	sql, args, err := deleteKeyAccessServerSQL(id)

	if err := c.Exec(ctx, sql, args, err); err != nil {
		return nil, err
	}

	// return the attribute before deleting
	return k, nil
}
