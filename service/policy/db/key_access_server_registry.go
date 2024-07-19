package db

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/service/pkg/db"
	"google.golang.org/protobuf/encoding/protojson"
)

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

		keyAccessServer.Id = kas.ID.String()
		keyAccessServer.Uri = kas.Uri
		keyAccessServer.PublicKey = publicKey
		keyAccessServer.Metadata = metadata

		keyAccessServers[i] = keyAccessServer
	}

	return keyAccessServers, nil
}

func (c PolicyDBClient) GetKeyAccessServer(ctx context.Context, id string) (*policy.KeyAccessServer, error) {
	uuid, err := uuid.Parse(id)
	if err != nil {
		return nil, db.ErrUUIDInvalid
	}
	kas, err := c.Queries.GetKeyAccessServer(ctx, uuid)
	if err != nil {
		return nil, err
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
		Id:        kas.ID.String(),
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
		return nil, err
	}

	return &policy.KeyAccessServer{
		Id: createdID.String(),
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

	uuid, err := uuid.Parse(id)
	if err != nil {
		return nil, db.ErrUUIDInvalid
	}

	uri := pgtype.Text{
		String: r.GetUri(),
	}
	if r.GetUri() != "" {
		uri.Valid = true
	}

	createdID, err := c.Queries.UpdateKeyAccessServer(ctx, UpdateKeyAccessServerParams{
		ID:        uuid,
		Uri:       uri,
		PublicKey: publicKeyJSON,
		Metadata:  metadataJSON,
	})
	if err != nil {
		return nil, err
	}

	return &policy.KeyAccessServer{
		Id: createdID.String(),
	}, nil
}

func (c PolicyDBClient) DeleteKeyAccessServer(ctx context.Context, id string) (*policy.KeyAccessServer, error) {
	uuid, err := uuid.Parse(id)
	if err != nil {
		return nil, db.ErrUUIDInvalid
	}

	count, err := c.Queries.DeleteKeyAccessServer(ctx, uuid)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	// return the KAS that was deleted
	return &policy.KeyAccessServer{
		Id: id,
	}, nil
}
