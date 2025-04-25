package db

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/service/pkg/db"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func (c PolicyDBClient) ListKeyAccessServers(ctx context.Context, r *kasregistry.ListKeyAccessServersRequest) (*kasregistry.ListKeyAccessServersResponse, error) {
	limit, offset := c.getRequestedLimitOffset(r.GetPagination())

	maxLimit := c.listCfg.limitMax
	if maxLimit > 0 && limit > maxLimit {
		return nil, db.ErrListLimitTooLarge
	}

	list, err := c.Queries.ListKeyAccessServers(ctx, ListKeyAccessServersParams{
		Offset: offset,
		Limit:  limit,
	})
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
		keyAccessServer.Name = kas.KasName.String
		keyAccessServer.Metadata = metadata

		keyAccessServers[i] = keyAccessServer
	}
	var total int32
	var nextOffset int32
	if len(list) > 0 {
		total = int32(list[0].Total)
		nextOffset = getNextOffset(offset, limit, total)
	}

	return &kasregistry.ListKeyAccessServersResponse{
		KeyAccessServers: keyAccessServers,
		Pagination: &policy.PageResponse{
			CurrentOffset: offset,
			Total:         total,
			NextOffset:    nextOffset,
		},
	}, nil
}

func (c PolicyDBClient) GetKeyAccessServer(ctx context.Context, identifier any) (*policy.KeyAccessServer, error) {
	var (
		kas    GetKeyAccessServerRow
		err    error
		params GetKeyAccessServerParams
	)

	switch i := identifier.(type) {
	case *kasregistry.GetKeyAccessServerRequest_KasId:
		id := pgtypeUUID(i.KasId)
		if !id.Valid {
			return nil, db.ErrUUIDInvalid
		}
		params = GetKeyAccessServerParams{ID: id}
	case *kasregistry.GetKeyAccessServerRequest_Name:
		name := pgtypeText(i.Name)
		if !name.Valid {
			return nil, db.ErrSelectIdentifierInvalid
		}
		params = GetKeyAccessServerParams{Name: name}
	case *kasregistry.GetKeyAccessServerRequest_Uri:
		uri := pgtypeText(i.Uri)
		if !uri.Valid {
			return nil, db.ErrSelectIdentifierInvalid
		}
		params = GetKeyAccessServerParams{Uri: uri}
	case string:
		id := pgtypeUUID(i)
		if !id.Valid {
			return nil, db.ErrUUIDInvalid
		}
		params = GetKeyAccessServerParams{ID: id}
	default:
		// unexpected type
		return nil, errors.Join(db.ErrUnknownSelectIdentifier, fmt.Errorf("type [%T] value [%v]", i, i))
	}

	kas, err = c.Queries.GetKeyAccessServer(ctx, params)
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

func (c PolicyDBClient) ListKeyAccessServerGrants(ctx context.Context, r *kasregistry.ListKeyAccessServerGrantsRequest) (*kasregistry.ListKeyAccessServerGrantsResponse, error) {
	limit, offset := c.getRequestedLimitOffset(r.GetPagination())
	maxLimit := c.listCfg.limitMax
	if maxLimit > 0 && limit > maxLimit {
		return nil, db.ErrListLimitTooLarge
	}

	params := ListKeyAccessServerGrantsParams{
		KasID:   r.GetKasId(),
		KasUri:  r.GetKasUri(),
		KasName: r.GetKasName(),
		Offset:  offset,
		Limit:   limit,
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
	var total int32
	var nextOffset int32
	if len(listRows) > 0 {
		total = int32(listRows[0].Total)
		nextOffset = getNextOffset(offset, limit, total)
	}
	return &kasregistry.ListKeyAccessServerGrantsResponse{
		Grants: grants,
		Pagination: &policy.PageResponse{
			CurrentOffset: params.Offset,
			Total:         total,
			NextOffset:    nextOffset,
		},
	}, nil
}

func (c PolicyDBClient) CreatePublicKey(ctx context.Context, r *kasregistry.CreatePublicKeyRequest) (*kasregistry.CreatePublicKeyResponse, error) {
	var ck *kasregistry.GetPublicKeyResponse

	kasID := r.GetKasId()
	key := r.GetKey()

	metadataJSON, _, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}

	err = c.RunInTx(ctx, func(txClient *PolicyDBClient) error {
		id, err := txClient.Queries.createPublicKey(ctx, createPublicKeyParams{
			KeyAccessServerID: kasID,
			KeyID:             key.GetKid(),
			Alg:               key.GetAlg().String(),
			PublicKey:         key.GetPem(),
			Metadata:          metadataJSON,
		})
		if err != nil {
			return db.WrapIfKnownInvalidQueryErr(err)
		}

		// Get freshly created key
		ck, err = txClient.GetPublicKey(ctx, &kasregistry.GetPublicKeyRequest{
			Identifier: &kasregistry.GetPublicKeyRequest_Id{
				Id: id,
			},
		})
		if err != nil {
			return db.WrapIfKnownInvalidQueryErr(err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return &kasregistry.CreatePublicKeyResponse{
		Key: ck.GetKey(),
	}, nil
}

func (c PolicyDBClient) GetPublicKey(ctx context.Context, r *kasregistry.GetPublicKeyRequest) (*kasregistry.GetPublicKeyResponse, error) {
	metadata := new(common.Metadata)

	keyID := r.GetId()
	key, err := c.Queries.getPublicKey(ctx, keyID)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	err = unmarshalMetadata(key.Metadata, metadata)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &kasregistry.GetPublicKeyResponse{
		Key: &policy.Key{
			Id:        keyID,
			IsActive:  wrapperspb.Bool(key.IsActive),
			WasMapped: wrapperspb.Bool(key.WasMapped),
			Metadata:  metadata,
			Kas: &policy.KeyAccessServer{
				Id:   key.KeyAccessServerID,
				Uri:  key.KasUri.String,
				Name: key.KasName.String,
			},
			PublicKey: &policy.KasPublicKey{
				Kid: key.KeyID,
				Alg: policy.KasPublicKeyAlgEnum(policy.KasPublicKeyAlgEnum_value[key.Alg]),
				Pem: key.PublicKey,
			},
		},
	}, nil
}

func (c PolicyDBClient) ListPublicKeys(ctx context.Context, r *kasregistry.ListPublicKeysRequest) (*kasregistry.ListPublicKeysResponse, error) {
	limit, offset := c.getRequestedLimitOffset(r.GetPagination())
	maxLimit := c.listCfg.limitMax
	if maxLimit > 0 && limit > maxLimit {
		return nil, db.ErrListLimitTooLarge
	}

	// Validate kas_id is uuid if set
	if r.GetKasId() != "" {
		if _, err := uuid.Parse(r.GetKasId()); err != nil {
			return nil, db.StatusifyError(err, db.ErrEnumValueInvalid.Error())
		}
	}

	params := listPublicKeysParams{
		KasID:   r.GetKasId(),
		KasUri:  r.GetKasUri(),
		KasName: r.GetKasName(),
		Offset:  offset,
		Limit:   limit,
	}
	listRows, err := c.Queries.listPublicKeys(ctx, params)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	keys := make([]*policy.Key, len(listRows))
	for i, key := range listRows {
		metadata := new(common.Metadata)
		err := unmarshalMetadata(key.Metadata, metadata)
		if err != nil {
			return nil, db.WrapIfKnownInvalidQueryErr(err)
		}
		keys[i] = &policy.Key{
			Id:        key.ID,
			IsActive:  wrapperspb.Bool(key.IsActive),
			WasMapped: wrapperspb.Bool(key.WasMapped),
			Metadata:  metadata,
			Kas: &policy.KeyAccessServer{
				Id:   key.KeyAccessServerID,
				Uri:  key.KasUri.String,
				Name: key.KasName.String,
			},
			PublicKey: &policy.KasPublicKey{
				Kid: key.KeyID,
				Alg: policy.KasPublicKeyAlgEnum(policy.KasPublicKeyAlgEnum_value[key.Alg]),
				Pem: key.PublicKey,
			},
		}
	}
	var total int32
	var nextOffset int32
	if len(listRows) > 0 {
		total = int32(listRows[0].Total)
		nextOffset = getNextOffset(offset, limit, total)
	}
	return &kasregistry.ListPublicKeysResponse{
		Keys: keys,
		Pagination: &policy.PageResponse{
			CurrentOffset: params.Offset,
			Total:         total,
			NextOffset:    nextOffset,
		},
	}, nil
}

func (c PolicyDBClient) ListPublicKeyMappings(ctx context.Context, r *kasregistry.ListPublicKeyMappingRequest) (*kasregistry.ListPublicKeyMappingResponse, error) {
	limit, offset := c.getRequestedLimitOffset(r.GetPagination())
	maxLimit := c.listCfg.limitMax
	if maxLimit > 0 && limit > maxLimit {
		return nil, db.ErrListLimitTooLarge
	}

	params := listPublicKeyMappingsParams{
		KasID:       r.GetKasId(),
		KasUri:      r.GetKasUri(),
		KasName:     r.GetKasName(),
		PublicKeyID: r.GetPublicKeyId(),
		Offset:      offset,
		Limit:       limit,
	}

	listRows, err := c.Queries.listPublicKeyMappings(ctx, params)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	mappings := make([]*kasregistry.ListPublicKeyMappingResponse_PublicKeyMapping, len(listRows))
	for i, mapping := range listRows {
		pkm := new(kasregistry.ListPublicKeyMappingResponse_PublicKeyMapping)
		err := protojson.Unmarshal(mapping.KasInfo, pkm)
		if err != nil {
			return nil, db.WrapIfKnownInvalidQueryErr(err)
		}
		mappings[i] = pkm
	}

	var total int32
	var nextOffset int32
	if len(listRows) > 0 {
		total = int32(listRows[0].Total)
		nextOffset = getNextOffset(offset, limit, total)
	}

	return &kasregistry.ListPublicKeyMappingResponse{
		PublicKeyMappings: mappings,
		Pagination: &policy.PageResponse{
			CurrentOffset: params.Offset,
			Total:         total,
			NextOffset:    nextOffset,
		},
	}, nil
}

func (c PolicyDBClient) UpdatePublicKey(ctx context.Context, r *kasregistry.UpdatePublicKeyRequest) (*kasregistry.UpdatePublicKeyResponse, error) {
	keyID := r.GetId()

	mdJSON, metadata, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
		k, err := c.GetPublicKey(ctx, &kasregistry.GetPublicKeyRequest{
			Identifier: &kasregistry.GetPublicKeyRequest_Id{
				Id: keyID,
			},
		})
		if err != nil {
			return nil, err
		}
		return k.GetKey().GetMetadata(), nil
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	pk, err := c.Queries.updatePublicKey(ctx, updatePublicKeyParams{
		ID:       keyID,
		Metadata: mdJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &kasregistry.UpdatePublicKeyResponse{
		Key: &policy.Key{
			Id: pk.ID,
			Kas: &policy.KeyAccessServer{
				Id: pk.KeyAccessServerID,
			},
			IsActive:  wrapperspb.Bool(pk.IsActive),
			WasMapped: wrapperspb.Bool(pk.WasMapped),
			PublicKey: &policy.KasPublicKey{
				Kid: pk.KeyID,
				Alg: policy.KasPublicKeyAlgEnum(policy.KasPublicKeyAlgEnum_value[pk.Alg]),
				Pem: pk.PublicKey,
			},
			Metadata: metadata,
		},
	}, nil
}

func (c PolicyDBClient) DeactivatePublicKey(ctx context.Context, r *kasregistry.DeactivatePublicKeyRequest) (*kasregistry.DeactivatePublicKeyResponse, error) {
	keyID := r.GetId()
	count, err := c.Queries.deactivatePublicKey(ctx, keyID)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}
	return &kasregistry.DeactivatePublicKeyResponse{
		Key: &policy.Key{
			Id: keyID,
		},
	}, nil
}

func (c PolicyDBClient) ActivatePublicKey(ctx context.Context, r *kasregistry.ActivatePublicKeyRequest) (*kasregistry.ActivatePublicKeyResponse, error) {
	keyID := r.GetId()
	count, err := c.Queries.activatePublicKey(ctx, keyID)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}
	return &kasregistry.ActivatePublicKeyResponse{
		Key: &policy.Key{
			Id: keyID,
		},
	}, nil
}
