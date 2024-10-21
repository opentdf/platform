package db

import (
	"context"
	"fmt"
	"strings"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/service/pkg/db"
	"google.golang.org/protobuf/encoding/protojson"
)

func (c PolicyDBClient) ListKeyAccessServers(ctx context.Context) ([]*policy.KeyAccessServer, error) {
	list, err := c.Queries.ListKeyAccessServers(ctx)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
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

		if err := unmarshalMetadata(kas.Metadata, metadata); err != nil {
			return nil, err
		}

		keyAccessServer.Id = kas.ID
		keyAccessServer.Uri = kas.Uri
		keyAccessServer.PublicKey = publicKey
		keyAccessServer.Name = kas.Name.String
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

	if err := unmarshalMetadata(kas.Metadata, metadata); err != nil {
		return nil, err
	}

	return &policy.KeyAccessServer{
		Id:        kas.ID,
		Uri:       kas.Uri,
		PublicKey: publicKey,
		Name:      kas.Name.String,
		Metadata:  metadata,
	}, nil
}

func (c PolicyDBClient) CreateKeyAccessServer(ctx context.Context, r *kasregistry.CreateKeyAccessServerRequest) (*policy.KeyAccessServer, error) {
	uri := r.GetUri()
	publicKey := r.GetPublicKey()
	name := strings.ToLower(r.GetName())

	metadataJSON, metadata, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}

	publicKeyJSON, err := protojson.Marshal(publicKey)
	if err != nil {
		return nil, err
	}

	createdID, err := c.Queries.CreateKeyAccessServer(ctx, CreateKeyAccessServerParams{
		Uri:       uri,
		PublicKey: publicKeyJSON,
		Name:      pgtypeText(name),
		Metadata:  metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &policy.KeyAccessServer{
		Id:        createdID,
		Uri:       uri,
		PublicKey: publicKey,
		Name:      name,
		Metadata:  metadata,
	}, nil
}

func (c PolicyDBClient) UpdateKeyAccessServer(ctx context.Context, id string, r *kasregistry.UpdateKeyAccessServerRequest) (*policy.KeyAccessServer, error) {
	uri := r.GetUri()
	publicKey := r.GetPublicKey()
	name := strings.ToLower(r.GetName())

	// if extend we need to merge the metadata
	metadataJSON, metadata, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
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
	if publicKey != nil {
		publicKeyJSON, err = protojson.Marshal(publicKey)
		if err != nil {
			return nil, err
		}
	}

	count, err := c.Queries.UpdateKeyAccessServer(ctx, UpdateKeyAccessServerParams{
		ID:        id,
		Uri:       pgtypeText(uri),
		Name:      pgtypeText(name),
		PublicKey: publicKeyJSON,
		Metadata:  metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.KeyAccessServer{
		Id:        id,
		Uri:       uri,
		Name:      name,
		PublicKey: publicKey,
		Metadata:  metadata,
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

func (c PolicyDBClient) ListKeyAccessServerGrants(ctx context.Context, kasID, kasURI, kasName string) ([]*kasregistry.KeyAccessServerGrants, error) {
	params := ListKeyAccessServerGrantsParams{
		KasID:   kasID,
		KasUri:  kasURI,
		KasName: kasName,
	}
	listRows, err := c.Queries.ListKeyAccessServerGrants(ctx, params)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	grants := make([]*kasregistry.KeyAccessServerGrants, len(listRows))
	for i, grant := range listRows {
		pubKey := new(policy.PublicKey)
		if err := protojson.Unmarshal(grant.KasPublicKey, pubKey); err != nil {
			return nil, fmt.Errorf("failed to unmarshal KAS public key: %w", err)
		}
		kas := &policy.KeyAccessServer{
			Id:        grant.KasID,
			Uri:       grant.KasUri,
			PublicKey: pubKey,
			Name:      grant.KasName.String,
		}
		attrGrants, err := db.GrantedPolicyObjectProtoJSON(grant.AttributesGrants)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal attribute grants: %w", err)
		}
		valGrants, err := db.GrantedPolicyObjectProtoJSON(grant.ValuesGrants)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal value grants: %w", err)
		}
		namespaceGrants, err := db.GrantedPolicyObjectProtoJSON(grant.NamespaceGrants)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal namespace grants: %w", err)
		}
		grants[i] = &kasregistry.KeyAccessServerGrants{
			KeyAccessServer: kas,
			AttributeGrants: attrGrants,
			ValueGrants:     valGrants,
			NamespaceGrants: namespaceGrants,
		}
	}

	return grants, nil
}
