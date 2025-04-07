package db

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/keymanagement"
	"github.com/opentdf/platform/service/pkg/db"
	"google.golang.org/protobuf/encoding/protojson"
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

/*
* Key Access Server Keys
 */
func (c PolicyDBClient) CreateKey(ctx context.Context, r *kasregistry.CreateKeyRequest) (*kasregistry.CreateKeyResponse, error) {
	keyID := r.GetKeyId()
	algo := int32(r.GetKeyAlgorithm())
	mode := int32(r.GetKeyMode())
	privateCtx := r.GetPrivateKeyCtx()
	pubCtx := r.GetPublicKeyCtx()
	providerConfigID := r.GetProviderConfigId()
	keyStatus := int32(policy.KeyStatus_KEY_STATUS_ACTIVE)

	kasID := r.GetKasId()
	_, err := c.GetKeyAccessServer(ctx, &kasregistry.GetKeyAccessServerRequest_KasId{
		KasId: kasID,
	})
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, kasID)
	}

	// Only allow one active key for an algo per KAS.
	activeKeyExists, err := c.Queries.CheckIfKeyExists(ctx, CheckIfKeyExistsParams{
		KeyAccessServerID: kasID,
		KeyStatus:         keyStatus,
		KeyAlgorithm:      algo,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	} else if activeKeyExists {
		return nil, fmt.Errorf("cannot create a new key when an active key already exists with algorithm %s", r.GetKeyAlgorithm().String())
	}

	// Especially if we need to verify the connection and get the public key.
	// Need provider logic to validate connection to remote provider.
	var pc *policy.KeyProviderConfig
	if providerConfigID != "" {
		pc, err = c.GetProviderConfig(ctx, &keymanagement.GetProviderConfigRequest_Id{Id: providerConfigID})
		if err != nil {
			return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, kasID)
		}
	}

	metadataJSON, _, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}

	key, err := c.Queries.CreateKey(ctx, CreateKeyParams{
		KeyAccessServerID: kasID,
		KeyAlgorithm:      algo,
		KeyID:             keyID,
		KeyMode:           mode,
		KeyStatus:         keyStatus,
		Metadata:          metadataJSON,
		PrivateKeyCtx:     privateCtx,
		PublicKeyCtx:      pubCtx,
		ProviderConfigID:  pgtypeUUID(pc.GetId()),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	metadata := &common.Metadata{}
	if err := unmarshalMetadata(key.Metadata, metadata); err != nil {
		return nil, err
	}

	return &kasregistry.CreateKeyResponse{
		Key: &policy.AsymmetricKey{
			Id:             key.ID,
			KeyId:          key.KeyID,
			KeyStatus:      policy.KeyStatus(key.KeyStatus),
			KeyAlgorithm:   policy.Algorithm(key.KeyAlgorithm),
			KeyMode:        policy.KeyMode(key.KeyMode),
			PrivateKeyCtx:  key.PrivateKeyCtx,
			PublicKeyCtx:   key.PublicKeyCtx,
			ProviderConfig: pc,
			Metadata:       metadata,
		},
	}, nil
}

func (c PolicyDBClient) GetKey(ctx context.Context, identifier any) (*policy.AsymmetricKey, error) {
	var params GetKeyParams

	switch i := identifier.(type) {
	case *kasregistry.GetKeyRequest_Id:
		pgUUID := pgtypeUUID(i.Id)
		if !pgUUID.Valid {
			return nil, db.ErrUUIDInvalid
		}
		params = GetKeyParams{ID: pgUUID}
	case *kasregistry.GetKeyRequest_KeyId:
		keyID := pgtypeText(i.KeyId)
		if !keyID.Valid {
			return nil, db.ErrSelectIdentifierInvalid
		}
		params = GetKeyParams{KeyID: keyID}
	default:
		return nil, errors.Join(db.ErrUnknownSelectIdentifier, fmt.Errorf("type [%T] value [%v]", i, i))
	}

	key, err := c.Queries.GetKey(ctx, params)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	metadata := &common.Metadata{}
	if err := unmarshalMetadata(key.Metadata, metadata); err != nil {
		return nil, err
	}

	var providerConfig *policy.KeyProviderConfig
	if key.ProviderConfigID.Valid {
		providerConfig = &policy.KeyProviderConfig{}
		providerConfig.Id = UUIDToString(key.ProviderConfigID)
		providerConfig.Name = key.ProviderName.String
		providerConfig.ConfigJson = key.PcConfig
		providerConfig.Metadata = &common.Metadata{}
		if err := unmarshalMetadata(key.PcMetadata, providerConfig.GetMetadata()); err != nil {
			return nil, err
		}
	}

	return &policy.AsymmetricKey{
		Id:             key.ID,
		KeyId:          key.KeyID,
		KeyStatus:      policy.KeyStatus(key.KeyStatus),
		KeyAlgorithm:   policy.Algorithm(key.KeyAlgorithm),
		KeyMode:        policy.KeyMode(key.KeyMode),
		PrivateKeyCtx:  key.PrivateKeyCtx,
		PublicKeyCtx:   key.PublicKeyCtx,
		ProviderConfig: providerConfig,
		Metadata:       metadata,
	}, nil
}

func (c PolicyDBClient) UpdateKey(ctx context.Context, r *kasregistry.UpdateKeyRequest) (*policy.AsymmetricKey, error) {
	keyID := r.GetId()
	if !pgtypeUUID(keyID).Valid {
		return nil, db.ErrUUIDInvalid
	}

	// Check if trying to update to unspecified key status
	if r.GetKeyStatus() == policy.KeyStatus_KEY_STATUS_UNSPECIFIED && r.GetMetadata() == nil && r.GetMetadataUpdateBehavior() == common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_UNSPECIFIED {
		return nil, fmt.Errorf("cannot update key status to unspecified")
	}

	// Add check to see if a key exists with the updated keys given algo and if that key is active.
	// If so, return an error.
	keyStatus := r.GetKeyStatus()
	if keyStatus == policy.KeyStatus_KEY_STATUS_ACTIVE {
		activeKeyExists, err := c.Queries.IsUpdateKeySafe(ctx, IsUpdateKeySafeParams{
			ID:        r.GetId(),
			KeyStatus: int32(keyStatus),
		})
		if err != nil {
			return nil, db.WrapIfKnownInvalidQueryErr(err)
		} else if activeKeyExists {
			return nil, fmt.Errorf("key cannot be updated to active when another key with the same algorithm is already active for a KAS")
		}
	}

	// if extend we need to merge the metadata
	metadataJSON, metadata, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
		a, err := c.GetKey(ctx, &kasregistry.GetKeyRequest_Id{
			Id: r.GetId(),
		})
		if err != nil {
			return nil, err
		}
		return a.GetMetadata(), nil
	})
	if err != nil {
		return nil, err
	}

	count, err := c.Queries.UpdateKey(ctx, UpdateKeyParams{
		ID:        keyID,
		KeyStatus: pgtypeInt4(int32(keyStatus), keyStatus != policy.KeyStatus_KEY_STATUS_UNSPECIFIED),
		Metadata:  metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	} else if count > 1 {
		c.logger.Warn("UpdateKey updated more than one row", "count", count)
	}

	return &policy.AsymmetricKey{
		Id:        keyID,
		KeyStatus: r.GetKeyStatus(),
		Metadata:  metadata,
	}, nil
}

func (c PolicyDBClient) ListKeys(ctx context.Context, r *kasregistry.ListKeysRequest) (*kasregistry.ListKeysResponse, error) {
	limit, offset := c.getRequestedLimitOffset(r.GetPagination())
	maxLimit := c.listCfg.limitMax
	if maxLimit > 0 && limit > maxLimit {
		return nil, db.ErrListLimitTooLarge
	}

	kasID := pgtypeUUID(r.GetKasId())
	kasURI := pgtypeText(r.GetKasUri())
	kasName := pgtypeText(strings.ToLower(r.GetKasName()))
	algo := pgtypeInt4(int32(r.GetKeyAlgorithm()), r.GetKeyAlgorithm() != policy.Algorithm_ALGORITHM_UNSPECIFIED)

	params := ListKeysParams{
		KeyAlgorithm: algo,
		KasID:        kasID,
		KasUri:       kasURI,
		KasName:      kasName,
		Offset:       offset,
		Limit:        limit,
	}

	listRows, err := c.Queries.ListKeys(ctx, params)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	keys := make([]*policy.AsymmetricKey, len(listRows))
	for i, key := range listRows {
		var providerConfig *policy.KeyProviderConfig
		if key.ProviderConfigID.Valid {
			providerConfig = &policy.KeyProviderConfig{}
			providerConfig.Id = UUIDToString(key.ProviderConfigID)
			providerConfig.Name = key.ProviderName.String
			providerConfig.ConfigJson = key.ProviderConfig
			providerConfig.Metadata = &common.Metadata{}
			if err := unmarshalMetadata(key.PcMetadata, providerConfig.GetMetadata()); err != nil {
				return nil, err
			}
		}

		metadata := &common.Metadata{}
		if err := unmarshalMetadata(key.Metadata, metadata); err != nil {
			return nil, err
		}

		keys[i] = &policy.AsymmetricKey{
			Id:             key.ID,
			KeyId:          key.KeyID,
			KeyStatus:      policy.KeyStatus(key.KeyStatus),
			KeyAlgorithm:   policy.Algorithm(key.KeyAlgorithm),
			KeyMode:        policy.KeyMode(key.KeyMode),
			PublicKeyCtx:   key.PublicKeyCtx,
			PrivateKeyCtx:  key.PrivateKeyCtx,
			ProviderConfig: providerConfig,
			Metadata:       metadata,
		}
	}
	var total int32
	var nextOffset int32
	if len(listRows) > 0 {
		total = int32(listRows[0].Total)
		nextOffset = getNextOffset(offset, limit, total)
	}

	return &kasregistry.ListKeysResponse{
		Keys: keys,
		Pagination: &policy.PageResponse{
			CurrentOffset: params.Offset,
			Total:         total,
			NextOffset:    nextOffset,
		},
	}, nil
}

// We don't currently expose this at the Service layer, but it is used by test code.
func (c PolicyDBClient) DeleteKey(ctx context.Context, id string) (*policy.AsymmetricKey, error) {
	if !pgtypeUUID(id).Valid {
		return nil, db.ErrUUIDInvalid
	}

	count, err := c.Queries.DeleteKey(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	// return the key that was deleted
	return &policy.AsymmetricKey{
		Id: id,
	}, nil
}
