package db

import (
	"context"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/platform/protocol/go/common"
	kasr "github.com/opentdf/platform/protocol/go/kasregistry"
	"github.com/opentdf/platform/service/internal/db"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	TableKeyAccessServerRegistry = "key_access_servers"

	Tables struct {
		KeyAccessServerRegistry db.Table
	}
)

type KasRegistryDBClient struct {
	db.Client
}

func NewClient(c db.Client) *KasRegistryDBClient {
	Tables.KeyAccessServerRegistry = db.NewTable(TableKeyAccessServerRegistry)

	return &KasRegistryDBClient{c}
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
		From(Tables.KeyAccessServerRegistry.Name()).
		ToSql()
}

func (c KasRegistryDBClient) ListKeyAccessServers(ctx context.Context) ([]*kasr.KeyAccessServer, error) {
	sql, args, err := listAllKeyAccessServersSql()
	if err != nil {
		return nil, err
	}

	rows, err := c.Query(ctx, sql, args)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
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
		From(Tables.KeyAccessServerRegistry.Name()).
		ToSql()
}

func (c KasRegistryDBClient) GetKeyAccessServer(ctx context.Context, id string) (*kasr.KeyAccessServer, error) {
	sql, args, err := getKeyAccessServerSql(id)
	if err != nil {
		return nil, err
	}

	row, err := c.QueryRow(ctx, sql, args)
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
		Insert(Tables.KeyAccessServerRegistry.Name()).
		Columns("uri", "public_key", "metadata").
		Values(uri, publicKey, metadata).
		Suffix("RETURNING \"id\"").
		ToSql()
}

func (c KasRegistryDBClient) CreateKeyAccessServer(ctx context.Context, r *kasr.CreateKeyAccessServerRequest) (*kasr.KeyAccessServer, error) {
	metadataBytes, _, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}

	pkBytes, err := protojson.Marshal(r.GetPublicKey())
	if err != nil {
		return nil, err
	}

	sql, args, err := createKeyAccessServerSQL(r.GetUri(), pkBytes, metadataBytes)
	if err != nil {
		return nil, err
	}

	row, err := c.QueryRow(ctx, sql, args)
	if err != nil {
		return nil, err
	}

	// Get ID of new resource
	var id string
	if err = row.Scan(&id); err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &kasr.KeyAccessServer{
		Id: id,
	}, nil
}

func updateKeyAccessServerSQL(id, uri string, publicKey, metadata []byte) (string, []interface{}, error) {
	sb := db.NewStatementBuilder().
		Update(Tables.KeyAccessServerRegistry.Name())

	if uri != "" {
		sb = sb.Set("uri", uri)
	}

	if publicKey != nil {
		sb = sb.Set("public_key", publicKey)
	}

	if metadata != nil {
		sb = sb.Set("metadata", metadata)
	}

	return sb.Where(sq.Eq{"id": id}).ToSql()
}

func (c KasRegistryDBClient) UpdateKeyAccessServer(ctx context.Context, id string, r *kasr.UpdateKeyAccessServerRequest) (*kasr.KeyAccessServer, error) {
	// if extend we need to merge the metadata
	metadataJSON, _, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
		k, err := c.GetKeyAccessServer(ctx, id)
		if err != nil {
			return nil, err
		}
		return k.GetMetadata(), nil
	})
	if err != nil {
		return nil, err
	}

	var publicKeyJSON []byte
	if r.GetPublicKey() != nil {
		publicKeyJSON, err = protojson.Marshal(r.GetPublicKey())
		if err != nil {
			return nil, err
		}
	}

	sql, args, err := updateKeyAccessServerSQL(id, r.GetUri(), publicKeyJSON, metadataJSON)
	if db.IsQueryBuilderSetClauseError(err) {
		return &kasr.KeyAccessServer{
			Id: id,
		}, nil
	}
	if err != nil {
		return nil, err
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
	}

	return &kasr.KeyAccessServer{
		Id: id,
	}, nil
}

func deleteKeyAccessServerSQL(id string) (string, []interface{}, error) {
	return db.NewStatementBuilder().
		Delete(Tables.KeyAccessServerRegistry.Name()).
		Where(sq.Eq{"id": id}).
		ToSql()
}

func (c KasRegistryDBClient) DeleteKeyAccessServer(ctx context.Context, id string) (*kasr.KeyAccessServer, error) {
	sql, args, err := deleteKeyAccessServerSQL(id)
	if err != nil {
		return nil, err
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
	}

	// return the attribute before deleting
	return &kasr.KeyAccessServer{
		Id: id,
	}, nil
}
