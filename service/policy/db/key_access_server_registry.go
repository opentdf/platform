package db

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/service/pkg/db"
	"google.golang.org/protobuf/encoding/protojson"
)

func setMetadataTimestampLabels(metadata *common.Metadata, createdAt, updatedAt pgtype.Timestamptz) {
	if metadata == nil {
		metadata = new(common.Metadata)
	}
	if metadata.GetLabels() == nil {
		metadata.Labels = make(map[string]string)
	}
	metadata.Labels["created_at"] = createdAt.Time.String()
	metadata.Labels["updated_at"] = updatedAt.Time.String()
}

func (c PolicyDBClient) ListKeyAccessServers(ctx context.Context) ([]*policy.KeyAccessServer, error) {
	list, err := c.Queries.ListKeyAccessServers(ctx)
	if err != nil {
		return nil, err
	}
	keyAccessServers := make([]*policy.KeyAccessServer, len(list))

	for i, kas := range list {
		var (
			keyAccessServer = new(policy.KeyAccessServer)
			publicKey       = new(policy.PublicKey)
			metadata        = new(common.Metadata)
		)

		if err := protojson.Unmarshal(kas.PublicKey, publicKey); err != nil {
			return nil, err
		}

		if kas.Metadata != nil {
			if err := protojson.Unmarshal(kas.Metadata, metadata); err != nil {
				return nil, err
			}
		}
		setMetadataTimestampLabels(metadata, kas.CreatedAt, kas.UpdatedAt)

		keyAccessServer.Id = kas.ID
		keyAccessServer.Uri = kas.Uri
		keyAccessServer.PublicKey = publicKey
		keyAccessServer.Metadata = metadata

		keyAccessServers[i] = keyAccessServer
	}

	return keyAccessServers, nil
}

func (c PolicyDBClient) GetKeyAccessServer(ctx context.Context, id string) (*policy.KeyAccessServer, error) {
	kas, err := c.Queries.GetKeyAccessServer(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	var (
		publicKey = new(policy.PublicKey)
		metadata  = new(common.Metadata)
	)

	if err := protojson.Unmarshal(kas.PublicKey, publicKey); err != nil {
		return nil, err
	}

	if kas.Metadata != nil {
		if err := protojson.Unmarshal(kas.Metadata, metadata); err != nil {
			return nil, err
		}
	}

	return &policy.KeyAccessServer{
		Id:        kas.ID,
		Uri:       kas.Uri,
		Metadata:  metadata,
		PublicKey: publicKey,
	}, nil
}

func (c PolicyDBClient) CreateKeyAccessServer(ctx context.Context, r *kasregistry.CreateKeyAccessServerRequest) (*policy.KeyAccessServer, error) {
	metadataBytes, _, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}

	pkBytes, err := protojson.Marshal(r.GetPublicKey())
	if err != nil {
		return nil, err
	}

	createdID, err := c.Queries.CreateKeyAccessServer(ctx, CreateKeyAccessServerParams{
		Uri:       r.GetUri(),
		PublicKey: pkBytes,
		Metadata:  metadataBytes,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &policy.KeyAccessServer{
		Id: createdID,
	}, nil
}

func (c PolicyDBClient) UpdateKeyAccessServer(ctx context.Context, id string, r *kasregistry.UpdateKeyAccessServerRequest) (*policy.KeyAccessServer, error) {
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

	uri := pgtype.Text{
		String: r.GetUri(),
	}
	if r.GetUri() != "" {
		uri.Valid = true
	}

	createdID, err := c.Queries.UpdateKeyAccessServer(ctx, UpdateKeyAccessServerParams{
		ID:        id,
		Uri:       uri,
		PublicKey: publicKeyJSON,
		Metadata:  metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &policy.KeyAccessServer{
		Id: createdID,
	}, nil
}

func (c PolicyDBClient) DeleteKeyAccessServer(ctx context.Context, id string) (*policy.KeyAccessServer, error) {
	count, err := c.Queries.DeleteKeyAccessServer(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	// return the KAS that was deleted
	return &policy.KeyAccessServer{
		Id: id,
	}, nil
}
