package db

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/keymanagement"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/wellknownconfiguration"
	"google.golang.org/protobuf/encoding/protojson"
)

type rotatedMappingIDs struct {
	NamespaceIDs      []string
	AttributeDefIDs   []string
	AttributeValueIDs []string
}

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

		var keys []*policy.KasKey
		if len(kas.Keys) > 0 {
			keys, err = db.KasKeysProtoJSON(kas.Keys)
			if err != nil {
				return nil, errors.New("failed to unmarshal keys")
			}
		}

		keyAccessServer.Id = kas.ID
		keyAccessServer.Uri = kas.Uri
		keyAccessServer.PublicKey = publicKey
		keyAccessServer.Name = kas.KasName.String
		keyAccessServer.Metadata = metadata
		keyAccessServer.KasKeys = keys
		keyAccessServer.SourceType = policy.SourceType(policy.SourceType_value[kas.SourceType.String])

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

	var keys []*policy.KasKey
	if len(kas.Keys) > 0 {
		keys, err = db.KasKeysProtoJSON(kas.Keys)
		if err != nil {
			return nil, errors.New("failed to unmarshal keys")
		}
	}

	return &policy.KeyAccessServer{
		Id:         kas.ID,
		Uri:        kas.Uri,
		PublicKey:  publicKey,
		Name:       kas.Name.String,
		Metadata:   metadata,
		SourceType: policy.SourceType(policy.SourceType_value[kas.SourceType.String]),
		KasKeys:    keys,
	}, nil
}

func (c PolicyDBClient) CreateKeyAccessServer(ctx context.Context, r *kasregistry.CreateKeyAccessServerRequest) (*policy.KeyAccessServer, error) {
	uri := r.GetUri()
	publicKey := r.GetPublicKey()
	name := strings.ToLower(r.GetName())
	sourceType := pgtypeText(r.GetSourceType().String()) // Can we make this required and be backwards compatible? And not unspecified?

	metadataJSON, metadata, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}

	publicKeyJSON, err := protojson.Marshal(publicKey)
	if err != nil {
		return nil, err
	}

	createdID, err := c.Queries.CreateKeyAccessServer(ctx, CreateKeyAccessServerParams{
		Uri:        uri,
		PublicKey:  publicKeyJSON,
		Name:       pgtypeText(name),
		Metadata:   metadataJSON,
		SourceType: sourceType,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &policy.KeyAccessServer{
		Id:         createdID,
		Uri:        uri,
		PublicKey:  publicKey,
		Name:       name,
		Metadata:   metadata,
		SourceType: r.GetSourceType(),
	}, nil
}

func (c PolicyDBClient) isInvalidUpdateKASSourceType(r *kasregistry.UpdateKeyAccessServerRequest) error {
	if r.GetSourceType() == policy.SourceType_SOURCE_TYPE_UNSPECIFIED && r.GetMetadata() == nil && r.GetMetadataUpdateBehavior() == common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_UNSPECIFIED &&
		r.GetPublicKey() == nil && r.GetName() == "" && r.GetUri() == "" {
		return db.ErrCannotUpdateToUnspecified
	}
	return nil
}

func (c PolicyDBClient) UpdateKeyAccessServer(ctx context.Context, id string, r *kasregistry.UpdateKeyAccessServerRequest) (*policy.KeyAccessServer, error) {
	uri := r.GetUri()
	publicKey := r.GetPublicKey()
	name := strings.ToLower(r.GetName())
	sourceType := pgtypeText(r.GetSourceType().String())
	if r.GetSourceType() == policy.SourceType_SOURCE_TYPE_UNSPECIFIED {
		sourceType = pgtypeText("")
	}

	// Check if trying to update source type to unspecified
	if err := c.isInvalidUpdateKASSourceType(r); err != nil {
		return nil, err
	}

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
		ID:         id,
		Uri:        pgtypeText(uri),
		Name:       pgtypeText(name),
		PublicKey:  publicKeyJSON,
		Metadata:   metadataJSON,
		SourceType: sourceType,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.KeyAccessServer{
		Id:         id,
		Uri:        uri,
		Name:       name,
		PublicKey:  publicKey,
		Metadata:   metadata,
		SourceType: r.GetSourceType(),
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

func isValidBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

/*
* Key Access Server Keys
 */
func (c PolicyDBClient) CreateKey(ctx context.Context, r *kasregistry.CreateKeyRequest) (*kasregistry.CreateKeyResponse, error) {
	keyID := r.GetKeyId()
	algo := int32(r.GetKeyAlgorithm())
	mode := int32(r.GetKeyMode())
	providerConfigID := r.GetProviderConfigId()
	keyStatus := int32(policy.KeyStatus_KEY_STATUS_ACTIVE)
	kasID := r.GetKasId()

	if !isValidBase64(r.GetPublicKeyCtx().GetPem()) {
		return nil, errors.Join(errors.New("public key ctx"), db.ErrExpectedBase64EncodedValue)
	}
	if (mode == int32(policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY) || mode == int32(policy.KeyMode_KEY_MODE_PROVIDER_ROOT_KEY)) && !isValidBase64(r.GetPrivateKeyCtx().GetWrappedKey()) {
		return nil, errors.Join(errors.New("private key ctx"), db.ErrExpectedBase64EncodedValue)
	}

	// Especially if we need to verify the connection and get the public key.
	// Need provider logic to validate connection to remote provider.
	var pc *policy.KeyProviderConfig
	var err error
	if providerConfigID != "" {
		pc, err = c.GetProviderConfig(ctx, &keymanagement.GetProviderConfigRequest_Id{Id: providerConfigID})
		if err != nil {
			return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, kasID)
		}
	}

	// Marshal private key and public key context
	pubCtx, err := json.Marshal(r.GetPublicKeyCtx())
	if err != nil {
		return nil, db.ErrMarshalValueFailed
	}
	var privateCtx []byte
	if r.GetPrivateKeyCtx() != nil {
		privateCtx, err = json.Marshal(r.GetPrivateKeyCtx())
		if err != nil {
			return nil, db.ErrMarshalValueFailed
		}
	}

	metadataJSON, _, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}

	key, err := c.Queries.createKey(ctx, createKeyParams{
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

	publicKeyCtx, privateKeyCtx, err := unmarshalPrivatePublicKeyContext(key.PublicKeyCtx, key.PrivateKeyCtx)
	if err != nil {
		return nil, err
	}

	return &kasregistry.CreateKeyResponse{
		KasKey: &policy.KasKey{
			KasId: key.KeyAccessServerID,
			Key: &policy.AsymmetricKey{
				Id:             key.ID,
				KeyId:          key.KeyID,
				KeyStatus:      policy.KeyStatus(key.KeyStatus),
				KeyAlgorithm:   policy.Algorithm(key.KeyAlgorithm),
				KeyMode:        policy.KeyMode(key.KeyMode),
				PrivateKeyCtx:  privateKeyCtx,
				PublicKeyCtx:   publicKeyCtx,
				ProviderConfig: pc,
				Metadata:       metadata,
			},
		},
	}, nil
}

func (c PolicyDBClient) GetKey(ctx context.Context, identifier any) (*policy.KasKey, error) {
	var params getKeyParams

	switch i := identifier.(type) {
	case *kasregistry.GetKeyRequest_Id:
		pgUUID := pgtypeUUID(i.Id)
		if !pgUUID.Valid {
			return nil, db.ErrUUIDInvalid
		}
		params = getKeyParams{ID: pgUUID}
	case *kasregistry.GetKeyRequest_Key:
		keyID := pgtypeText(i.Key.GetKid())
		if !keyID.Valid {
			return nil, db.ErrSelectIdentifierInvalid
		}

		switch i.Key.GetIdentifier().(type) {
		case *kasregistry.KasKeyIdentifier_KasId:
			kasID := pgtypeUUID(i.Key.GetKasId())
			if !kasID.Valid {
				return nil, db.ErrSelectIdentifierInvalid
			}
			params = getKeyParams{KasID: kasID, KeyID: keyID}
		case *kasregistry.KasKeyIdentifier_Uri:
			kasURI := pgtypeText(i.Key.GetUri())
			if !kasURI.Valid {
				return nil, db.ErrSelectIdentifierInvalid
			}
			params = getKeyParams{KasUri: kasURI, KeyID: keyID}
		case *kasregistry.KasKeyIdentifier_Name:
			kasName := pgtypeText(i.Key.GetName())
			if !kasName.Valid {
				return nil, db.ErrSelectIdentifierInvalid
			}
			params = getKeyParams{KasName: kasName, KeyID: keyID}
		default:
			return nil, errors.Join(db.ErrUnknownSelectIdentifier, fmt.Errorf("type [%T] value [%v]", i, i))
		}

	default:
		return nil, errors.Join(db.ErrUnknownSelectIdentifier, fmt.Errorf("type [%T] value [%v]", i, i))
	}

	key, err := c.Queries.getKey(ctx, params)
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

	publicKeyCtx, privateKeyCtx, err := unmarshalPrivatePublicKeyContext(key.PublicKeyCtx, key.PrivateKeyCtx)
	if err != nil {
		return nil, err
	}

	return &policy.KasKey{
		KasId: key.KeyAccessServerID,
		Key: &policy.AsymmetricKey{
			Id:             key.ID,
			KeyId:          key.KeyID,
			KeyStatus:      policy.KeyStatus(key.KeyStatus),
			KeyAlgorithm:   policy.Algorithm(key.KeyAlgorithm),
			KeyMode:        policy.KeyMode(key.KeyMode),
			PrivateKeyCtx:  privateKeyCtx,
			PublicKeyCtx:   publicKeyCtx,
			ProviderConfig: providerConfig,
			Metadata:       metadata,
		},
	}, nil
}

func (c PolicyDBClient) UpdateKey(ctx context.Context, r *kasregistry.UpdateKeyRequest) (*policy.KasKey, error) {
	id := r.GetId()
	if !pgtypeUUID(id).Valid {
		return nil, db.ErrUUIDInvalid
	}

	// Add check to see if a key exists with the updated keys given algo and if that key is active.
	// If so, return an error.
	keyStatus := r.GetKeyStatus()
	if keyStatus == policy.KeyStatus_KEY_STATUS_ACTIVE {
		activeKeyExists, err := c.Queries.isUpdateKeySafe(ctx, isUpdateKeySafeParams{
			ID:        r.GetId(),
			KeyStatus: int32(keyStatus),
		})
		if err != nil {
			return nil, db.WrapIfKnownInvalidQueryErr(err)
		} else if activeKeyExists {
			return nil, errors.New("key cannot be updated to active when another key with the same algorithm is already active for a KAS")
		}
	}

	// if extend we need to merge the metadata
	metadataJSON, _, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
		a, err := c.GetKey(ctx, &kasregistry.GetKeyRequest_Id{
			Id: r.GetId(),
		})
		if err != nil {
			return nil, err
		}
		return a.GetKey().GetMetadata(), nil
	})
	if err != nil {
		return nil, err
	}

	count, err := c.Queries.updateKey(ctx, updateKeyParams{
		ID:        id,
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

	return c.GetKey(ctx, &kasregistry.GetKeyRequest_Id{
		Id: id,
	})
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

	params := listKeysParams{
		KeyAlgorithm: algo,
		KasID:        kasID,
		KasUri:       kasURI,
		KasName:      kasName,
		Offset:       offset,
		Limit:        limit,
	}

	listRows, err := c.Queries.listKeys(ctx, params)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	keys := make([]*policy.KasKey, len(listRows))
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

		publicKeyCtx, privateKeyCtx, err := unmarshalPrivatePublicKeyContext(key.PublicKeyCtx, key.PrivateKeyCtx)
		if err != nil {
			return nil, err
		}

		keys[i] = &policy.KasKey{
			KasId: key.KeyAccessServerID,
			Key: &policy.AsymmetricKey{
				Id:             key.ID,
				KeyId:          key.KeyID,
				KeyStatus:      policy.KeyStatus(key.KeyStatus),
				KeyAlgorithm:   policy.Algorithm(key.KeyAlgorithm),
				KeyMode:        policy.KeyMode(key.KeyMode),
				PublicKeyCtx:   publicKeyCtx,
				PrivateKeyCtx:  privateKeyCtx,
				ProviderConfig: providerConfig,
				Metadata:       metadata,
			},
		}
	}
	var total int32
	var nextOffset int32
	if len(listRows) > 0 {
		total = int32(listRows[0].Total)
		nextOffset = getNextOffset(offset, limit, total)
	}

	return &kasregistry.ListKeysResponse{
		KasKeys: keys,
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

	count, err := c.Queries.deleteKey(ctx, id)
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

func (c PolicyDBClient) RotateKey(ctx context.Context, activeKey *policy.KasKey, newKey *kasregistry.RotateKeyRequest_NewKey) (*kasregistry.RotateKeyResponse, error) {
	rotateKeyResp := &kasregistry.RotateKeyResponse{
		RotatedResources: &kasregistry.RotatedResources{
			AttributeDefinitionMappings: make([]*kasregistry.ChangeMappings, 0),
			AttributeValueMappings:      make([]*kasregistry.ChangeMappings, 0),
			NamespaceMappings:           make([]*kasregistry.ChangeMappings, 0),
		},
	}

	// Step 1: Update old key to inactive.
	rotatedOutKey, err := c.UpdateKey(ctx, &kasregistry.UpdateKeyRequest{
		Id:        activeKey.GetKey().GetId(),
		KeyStatus: policy.KeyStatus_KEY_STATUS_INACTIVE,
	})
	if err != nil {
		return nil, err
	}

	// Step 2: Create new key.
	newKasKey, err := c.CreateKey(ctx, &kasregistry.CreateKeyRequest{
		KasId:            activeKey.GetKasId(),
		KeyId:            newKey.GetKeyId(),
		KeyAlgorithm:     newKey.GetAlgorithm(),
		KeyMode:          newKey.GetKeyMode(),
		PublicKeyCtx:     newKey.GetPublicKeyCtx(),
		PrivateKeyCtx:    newKey.GetPrivateKeyCtx(),
		ProviderConfigId: newKey.GetProviderConfigId(),
		Metadata:         newKey.GetMetadata(),
	})
	if err != nil {
		return nil, err
	}

	// Step 3: Check if the rotated out key is currently a default key. If so, update.
	err = c.rotateDefaultKey(ctx, rotatedOutKey.GetKey().GetId(), newKasKey.GetKasKey().GetKey().GetId())
	if err != nil {
		return nil, err
	}

	// Step 4: Update Namespace/Attribute/Value tables to use the new key.
	rotatedIDs, err := c.rotatePublicKeyTables(ctx, activeKey.GetKey().GetId(), newKasKey.GetKasKey().GetKey().GetId())
	if err != nil {
		return nil, err
	}

	// Step 5: Populate the rotated resources.
	if err := c.populateChangeMappings(ctx, rotatedIDs, rotateKeyResp.GetRotatedResources()); err != nil {
		return nil, err
	}
	rotateKeyResp.RotatedResources.RotatedOutKey = rotatedOutKey

	// Step 6: Populate the new key
	rotateKeyResp.KasKey = newKasKey.GetKasKey()

	return rotateKeyResp, nil
}

func (c PolicyDBClient) populateChangeMappings(ctx context.Context, rotatedIDs rotatedMappingIDs, rotatedResources *kasregistry.RotatedResources) error {
	for _, id := range rotatedIDs.NamespaceIDs {
		mapping := &kasregistry.ChangeMappings{
			Id: id,
		}
		ns, err := c.GetNamespace(ctx, &namespaces.GetNamespaceRequest_NamespaceId{
			NamespaceId: id,
		})
		if err != nil {
			return err
		}
		mapping.Fqn = ns.GetFqn()
		rotatedResources.NamespaceMappings = append(rotatedResources.GetNamespaceMappings(), mapping)
	}
	for _, id := range rotatedIDs.AttributeDefIDs {
		mapping := &kasregistry.ChangeMappings{
			Id: id,
		}
		attrDef, err := c.GetAttribute(ctx, &attributes.GetAttributeRequest_AttributeId{
			AttributeId: id,
		})
		if err != nil {
			return err
		}
		mapping.Fqn = attrDef.GetFqn()
		rotatedResources.AttributeDefinitionMappings = append(rotatedResources.GetAttributeDefinitionMappings(), mapping)
	}
	for _, id := range rotatedIDs.AttributeValueIDs {
		mapping := &kasregistry.ChangeMappings{
			Id: id,
		}
		attrVal, err := c.GetAttributeValue(ctx, &attributes.GetAttributeValueRequest_ValueId{
			ValueId: id,
		})
		if err != nil {
			return err
		}
		mapping.Fqn = attrVal.GetFqn()
		rotatedResources.AttributeValueMappings = append(rotatedResources.GetAttributeValueMappings(), mapping)
	}

	return nil
}

/**
* Rotate the public key in the Namespace, AttributeDefinition, and AttributeValue tables.
 */
func (c PolicyDBClient) rotatePublicKeyTables(ctx context.Context, oldKeyID, newKeyID string) (rotatedMappingIDs, error) {
	var err error
	rotatedIDs := rotatedMappingIDs{
		NamespaceIDs:      make([]string, 0),
		AttributeDefIDs:   make([]string, 0),
		AttributeValueIDs: make([]string, 0),
	}

	rotatedIDs.NamespaceIDs, err = c.rotatePublicKeyForNamespace(ctx, rotatePublicKeyForNamespaceParams{
		OldKeyID: oldKeyID,
		NewKeyID: newKeyID,
	})
	if err != nil {
		return rotatedIDs, db.WrapIfKnownInvalidQueryErr(err)
	}

	rotatedIDs.AttributeDefIDs, err = c.rotatePublicKeyForAttributeDefinition(ctx, rotatePublicKeyForAttributeDefinitionParams{
		OldKeyID: oldKeyID,
		NewKeyID: newKeyID,
	})
	if err != nil {
		return rotatedIDs, db.WrapIfKnownInvalidQueryErr(err)
	}

	rotatedIDs.AttributeValueIDs, err = c.rotatePublicKeyForAttributeValue(ctx, rotatePublicKeyForAttributeValueParams{
		OldKeyID: oldKeyID,
		NewKeyID: newKeyID,
	})
	if err != nil {
		return rotatedIDs, db.WrapIfKnownInvalidQueryErr(err)
	}

	return rotatedIDs, nil
}

func (c PolicyDBClient) rotateDefaultKey(ctx context.Context, rotatedOutKeyID, newKeyID string) error {
	defaultKeys, err := c.GetDefaultKeysByID(ctx, rotatedOutKeyID)
	if err != nil {
		return db.WrapIfKnownInvalidQueryErr(err)
	}
	// It's possible that the rotated out key was mapped to both modes: ztdf/nano.
	// If the key algorithm is of type ECC.
	for _, defaultKey := range defaultKeys {
		tdfType, ok := kasregistry.TdfType_value[defaultKey.GetTdfType()]
		if !ok {
			return fmt.Errorf("invalid TDF type: %s", defaultKey.GetTdfType())
		}

		_, err = c.SetDefaultKey(ctx, &kasregistry.SetDefaultKeyRequest{
			ActiveKey: &kasregistry.SetDefaultKeyRequest_Id{
				Id: newKeyID,
			},
			TdfType: kasregistry.TdfType(tdfType),
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func (c PolicyDBClient) GetDefaultKasKeys(ctx context.Context) ([]*kasregistry.DefaultKasKey, error) {
	keys, err := c.Queries.getDefaultKeys(ctx)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	var defaultKeys []*kasregistry.DefaultKasKey
	if len(keys) > 0 {
		defaultKeys, err = db.DefaultKasKeysProtoJSON(keys)
		if err != nil {
			return nil, err
		}
	}

	return defaultKeys, nil
}

func (c PolicyDBClient) GetDefaultKeysByID(ctx context.Context, id string) ([]*kasregistry.DefaultKasKey, error) {
	keys, err := c.Queries.getDefaultKeysById(ctx, pgtypeUUID(id))
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	var defaultKeys []*kasregistry.DefaultKasKey
	if len(keys) > 0 {
		defaultKeys, err = db.DefaultKasKeysProtoJSON(keys)
		if err != nil {
			return nil, err
		}
	}

	return defaultKeys, nil
}

func (c PolicyDBClient) GetDefaultKasKeyByMode(ctx context.Context, tdfType kasregistry.TdfType) (*kasregistry.DefaultKasKey, error) {
	key, err := c.getDefaultKasKeyByMode(ctx, pgtypeText(tdfType.String()))
	if err != nil && !errors.Is(db.WrapIfKnownInvalidQueryErr(err), db.ErrNotFound) {
		c.logger.Error("GetDefaultKasKeyByMode", "error", err)
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	var defaultKey *kasregistry.DefaultKasKey
	if len(key) > 0 {
		defaultKey = &kasregistry.DefaultKasKey{}
		err = db.UnmarshalDefaultKasKey(key, defaultKey)
		if err != nil {
			return nil, err
		}
	}

	return defaultKey, nil
}

func isAlgValidForNano(alg policy.Algorithm) bool {
	switch alg {
	case policy.Algorithm_ALGORITHM_EC_P256, policy.Algorithm_ALGORITHM_EC_P384, policy.Algorithm_ALGORITHM_EC_P521:
		return true
	case policy.Algorithm_ALGORITHM_RSA_2048, policy.Algorithm_ALGORITHM_RSA_4096, policy.Algorithm_ALGORITHM_UNSPECIFIED:
		return false
	default:
		return false
	}
}

func (c PolicyDBClient) SetDefaultKey(ctx context.Context, r *kasregistry.SetDefaultKeyRequest) (*kasregistry.SetDefaultKeyResponse, error) {
	var identifier any
	switch r.GetActiveKey().(type) {
	case *kasregistry.SetDefaultKeyRequest_Id:
		identifier = &kasregistry.GetKeyRequest_Id{
			Id: r.GetId(),
		}
	case *kasregistry.SetDefaultKeyRequest_Key:
		identifier = &kasregistry.GetKeyRequest_Key{
			Key: r.GetKey(),
		}
	}
	keyToSet, err := c.GetKey(ctx, identifier)
	if err != nil {
		return nil, err
	}

	if keyToSet.GetKey().GetKeyMode() == policy.KeyMode_KEY_MODE_PUBLIC_KEY_ONLY {
		return nil, fmt.Errorf("cannot set key of mode %s as default key", keyToSet.GetKey().GetKeyMode().String())
	}

	previousDefaultKey, err := c.GetDefaultKasKeyByMode(ctx, r.GetTdfType())
	if err != nil {
		return nil, err
	}

	// If default key is nano, cipher must be ECC.
	if r.GetTdfType() == kasregistry.TdfType_TDF_TYPE_NANO && !isAlgValidForNano(keyToSet.GetKey().GetKeyAlgorithm()) {
		return nil, fmt.Errorf("key algorithm %s is not valid for TDF type NANO", keyToSet.GetKey().GetKeyAlgorithm().String())
	}

	// A trigger is set for BEFORE INSERT which will update the
	// the key reference to the one being inserted, if present.
	// If not, the insert will continue.
	_, err = c.Queries.setDefaultKasKey(ctx, setDefaultKasKeyParams{
		KeyAccessServerKeyID: pgtypeUUID(keyToSet.GetKey().GetId()),
		TdfType:              r.GetTdfType().String(),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	// Get the new default key.
	newDefaultKey, err := c.GetDefaultKasKeyByMode(ctx, r.GetTdfType())
	if err != nil {
		return nil, err
	}

	// Set wellknown config
	if err := c.SetDefaultKeyOnWellKnownConfig(ctx); err != nil {
		return nil, err
	}

	return &kasregistry.SetDefaultKeyResponse{
		NewDefaultKasKey:      newDefaultKey,
		PreviousDefaultKasKey: previousDefaultKey,
	}, nil
}

func (c PolicyDBClient) SetDefaultKeyOnWellKnownConfig(ctx context.Context) error {
	defaultKeys, err := c.GetDefaultKasKeys(ctx)
	if err != nil {
		return err
	}

	defaultKeyArr := make([]any, len(defaultKeys))
	for i, key := range defaultKeys {
		defaultKeyArr[i] = key
	}

	keyMapBytes, err := json.Marshal(defaultKeyArr)
	if err != nil {
		return err
	}

	genericKeyArr := make([]any, len(defaultKeyArr))
	err = json.Unmarshal(keyMapBytes, &genericKeyArr)
	if err != nil {
		return err
	}

	return wellknownconfiguration.UpdateConfigurationDefaultKey(genericKeyArr)
}

/*
**********************
TESTING ONLY
************************
*/
func (c PolicyDBClient) DeleteAllDefaultKeys(ctx context.Context) error {
	_, err := c.Queries.deleteAllDefaultKasKeys(ctx)
	if err != nil {
		return db.WrapIfKnownInvalidQueryErr(err)
	}

	return nil
}
