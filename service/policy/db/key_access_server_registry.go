package db

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/wellknownconfiguration"
	"google.golang.org/protobuf/encoding/protojson"
)

type rotatedMappingIDs struct {
	NamespaceIDs      []string
	AttributeDefIDs   []string
	AttributeValueIDs []string
}

type kasParams struct {
	KasID   pgtype.UUID
	KasURI  pgtype.Text
	KasName pgtype.Text
}

func (c PolicyDBClient) ListKeyAccessServers(ctx context.Context, r *kasregistry.ListKeyAccessServersRequest) (*kasregistry.ListKeyAccessServersResponse, error) {
	limit, offset := c.getRequestedLimitOffset(r.GetPagination())

	maxLimit := c.listCfg.limitMax
	if maxLimit > 0 && limit > maxLimit {
		return nil, db.ErrListLimitTooLarge
	}

	list, err := c.queries.listKeyAccessServers(ctx, listKeyAccessServersParams{
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

		var keys []*policy.SimpleKasKey
		if len(kas.Keys) > 0 {
			keys, err = db.SimpleKasKeysProtoJSON(kas.Keys)
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
		kas    getKeyAccessServerRow
		err    error
		params getKeyAccessServerParams
	)

	switch i := identifier.(type) {
	case *kasregistry.GetKeyAccessServerRequest_KasId:
		id := pgtypeUUID(i.KasId)
		if !id.Valid {
			return nil, db.ErrUUIDInvalid
		}
		params = getKeyAccessServerParams{ID: id}
	case *kasregistry.GetKeyAccessServerRequest_Name:
		name := pgtypeText(i.Name)
		if !name.Valid {
			return nil, db.ErrSelectIdentifierInvalid
		}
		params = getKeyAccessServerParams{Name: name}
	case *kasregistry.GetKeyAccessServerRequest_Uri:
		uri := pgtypeText(i.Uri)
		if !uri.Valid {
			return nil, db.ErrSelectIdentifierInvalid
		}
		params = getKeyAccessServerParams{Uri: uri}
	case string:
		id := pgtypeUUID(i)
		if !id.Valid {
			return nil, db.ErrUUIDInvalid
		}
		params = getKeyAccessServerParams{ID: id}
	default:
		// unexpected type
		return nil, errors.Join(db.ErrUnknownSelectIdentifier, fmt.Errorf("type [%T] value [%v]", i, i))
	}

	kas, err = c.queries.getKeyAccessServer(ctx, params)
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

	var keys []*policy.SimpleKasKey
	if len(kas.Keys) > 0 {
		keys, err = db.SimpleKasKeysProtoJSON(kas.Keys)
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

	createdID, err := c.queries.createKeyAccessServer(ctx, createKeyAccessServerParams{
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

	count, err := c.queries.updateKeyAccessServer(ctx, updateKeyAccessServerParams{
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
	count, err := c.queries.deleteKeyAccessServer(ctx, id)
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

	params := listKeyAccessServerGrantsParams{
		KasID:   pgtypeUUID(r.GetKasId()),
		KasUri:  pgtypeText(r.GetKasUri()),
		KasName: pgtypeText(r.GetKasName()),
		Offset:  offset,
		Limit:   limit,
	}
	listRows, err := c.queries.listKeyAccessServerGrants(ctx, params)
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
	providerConfigID := r.GetProviderConfigId()
	keyStatus := int32(policy.KeyStatus_KEY_STATUS_ACTIVE)
	kasID := r.GetKasId()

	if !isValidBase64(r.GetPublicKeyCtx().GetPem()) {
		return nil, errors.Join(errors.New("public key ctx"), db.ErrExpectedBase64EncodedValue)
	}
	if (mode == int32(policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY) || mode == int32(policy.KeyMode_KEY_MODE_PROVIDER_ROOT_KEY)) && !isValidBase64(r.GetPrivateKeyCtx().GetWrappedKey()) {
		return nil, errors.Join(errors.New("private key ctx"), db.ErrExpectedBase64EncodedValue)
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

	id, err := c.queries.createKey(ctx, createKeyParams{
		KeyAccessServerID: kasID,
		KeyAlgorithm:      algo,
		KeyID:             keyID,
		KeyMode:           mode,
		KeyStatus:         keyStatus,
		Metadata:          metadataJSON,
		PrivateKeyCtx:     privateCtx,
		PublicKeyCtx:      pubCtx,
		ProviderConfigID:  pgtypeUUID(providerConfigID),
		Legacy:            r.GetLegacy(),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	key, err := c.GetKey(ctx, &kasregistry.GetKeyRequest_Id{
		Id: id,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &kasregistry.CreateKeyResponse{
		KasKey: key,
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

	key, err := c.queries.getKey(ctx, params)
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
		providerConfig.Manager = key.PcManager.String
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
		KasId:  key.KeyAccessServerID,
		KasUri: key.KasUri,
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
			Legacy:         key.Legacy,
		},
	}, nil
}

func (c PolicyDBClient) UpdateKey(ctx context.Context, r *kasregistry.UpdateKeyRequest) (*policy.KasKey, error) {
	id := r.GetId()
	if !pgtypeUUID(id).Valid {
		return nil, db.ErrUUIDInvalid
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

	return c.updateKeyInternal(ctx, updateKeyParams{
		ID:       id,
		Metadata: metadataJSON,
	})
}

func (c PolicyDBClient) ListKeys(ctx context.Context, r *kasregistry.ListKeysRequest) (*kasregistry.ListKeysResponse, error) {
	limit, offset := c.getRequestedLimitOffset(r.GetPagination())
	maxLimit := c.listCfg.limitMax
	if maxLimit > 0 && limit > maxLimit {
		return nil, db.ErrListLimitTooLarge
	}

	var (
		kasID   pgtype.UUID
		kasURI  pgtype.Text
		kasName pgtype.Text
	)
	hasKasFilter := false

	switch f := r.GetKasFilter().(type) {
	case *kasregistry.ListKeysRequest_KasId:
		hasKasFilter = true
		kasID = pgtypeUUID(f.KasId)
		if !kasID.Valid {
			return nil, db.ErrUUIDInvalid
		}
	case *kasregistry.ListKeysRequest_KasUri:
		hasKasFilter = true
		kasURI = pgtypeText(f.KasUri)
		if !kasURI.Valid {
			return nil, db.ErrSelectIdentifierInvalid
		}
	case *kasregistry.ListKeysRequest_KasName:
		hasKasFilter = true
		kasName = pgtypeText(strings.ToLower(f.KasName))
		if !kasName.Valid {
			return nil, db.ErrSelectIdentifierInvalid
		}
	}

	if hasKasFilter {
		exists, err := c.queries.keyAccessServerExists(ctx, keyAccessServerExistsParams{
			KasID:   kasID,
			KasName: kasName,
			KasUri:  kasURI,
		})
		if err != nil {
			return nil, db.WrapIfKnownInvalidQueryErr(err)
		}
		if !exists {
			return nil, db.ErrNotFound
		}
	}
	algo := pgtypeInt4(int32(r.GetKeyAlgorithm()), r.GetKeyAlgorithm() != policy.Algorithm_ALGORITHM_UNSPECIFIED)

	var legacy pgtype.Bool

	if r.Legacy == nil {
		legacy = pgtype.Bool{Valid: false}
	} else {
		legacy = pgtypeBool(r.GetLegacy())
	}

	params := listKeysParams{
		Legacy:       legacy,
		KeyAlgorithm: algo,
		KasID:        kasID,
		KasUri:       kasURI,
		KasName:      kasName,
		Offset:       offset,
		Limit:        limit,
	}

	listRows, err := c.queries.listKeys(ctx, params)
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
			KasId:  key.KeyAccessServerID,
			KasUri: key.KasUri,
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
				Legacy:         key.Legacy,
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

func (c PolicyDBClient) UnsafeDeleteKey(ctx context.Context, toDelete *policy.KasKey, r *unsafe.UnsafeDeleteKasKeyRequest) (*policy.AsymmetricKey, error) {
	id := r.GetId()
	kasURI := r.GetKasUri()
	kid := r.GetKid()

	if !pgtypeUUID(id).Valid {
		return nil, db.ErrUUIDInvalid
	}

	if toDelete.GetKasUri() != kasURI {
		return nil, errors.Join(db.ErrKasURIMismatch, fmt.Errorf("KAS URI mismatch: expected %s, got %s", toDelete.GetKasUri(), kasURI))
	}
	if toDelete.GetKey().GetKeyId() != kid {
		return nil, errors.Join(db.ErrKIDMismatch, fmt.Errorf("key ID mismatch: expected %s, got %s", toDelete.GetKey().GetKeyId(), kid))
	}

	count, err := c.queries.deleteKey(ctx, id)
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

	rotatedOutKey, err := c.updateKeyInternal(ctx, updateKeyParams{
		ID:        activeKey.GetKey().GetId(),
		KeyStatus: pgtypeInt4(int32(policy.KeyStatus_KEY_STATUS_ROTATED), true),
	})
	if err != nil {
		return nil, err
	}

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

	err = c.rotateBaseKey(ctx, rotatedOutKey, newKasKey.GetKasKey().GetKey().GetId())
	if err != nil {
		return nil, err
	}

	rotatedIDs, err := c.rotatePublicKeyTables(ctx, activeKey.GetKey().GetId(), newKasKey.GetKasKey().GetKey().GetId())
	if err != nil {
		return nil, err
	}

	if err := c.populateChangeMappings(ctx, rotatedIDs, rotateKeyResp.GetRotatedResources()); err != nil {
		return nil, err
	}
	rotateKeyResp.RotatedResources.RotatedOutKey = rotatedOutKey

	// Step 6: Populate the new key
	rotateKeyResp.KasKey = newKasKey.GetKasKey()

	return rotateKeyResp, nil
}

func (c PolicyDBClient) GetBaseKey(ctx context.Context) (*policy.SimpleKasKey, error) {
	key, err := c.queries.getBaseKey(ctx)
	if err != nil && !errors.Is(db.WrapIfKnownInvalidQueryErr(err), db.ErrNotFound) {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	baseKey, err := db.UnmarshalSimpleKasKey(key)
	if err != nil {
		return nil, err
	}

	return baseKey, nil
}

func (c PolicyDBClient) SetBaseKey(ctx context.Context, r *kasregistry.SetBaseKeyRequest) (*kasregistry.SetBaseKeyResponse, error) {
	var identifier any
	switch r.GetActiveKey().(type) {
	case *kasregistry.SetBaseKeyRequest_Id:
		identifier = &kasregistry.GetKeyRequest_Id{
			Id: r.GetId(),
		}
	case *kasregistry.SetBaseKeyRequest_Key:
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
	if keyToSet.GetKey().GetKeyStatus() != policy.KeyStatus_KEY_STATUS_ACTIVE {
		return nil, fmt.Errorf("cannot set key of status %s as default key", keyToSet.GetKey().GetKeyStatus().String())
	}

	previousDefaultKey, err := c.GetBaseKey(ctx)
	if err != nil {
		return nil, err
	}

	// A trigger is set for BEFORE INSERT which will update the
	// the key reference to the one being inserted, if present.
	// If not, the insert will continue.
	_, err = c.queries.setBaseKey(ctx, pgtypeUUID(keyToSet.GetKey().GetId()))
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	// Get the new default key.
	newBaseKey, err := c.GetBaseKey(ctx)
	if err != nil {
		return nil, err
	}

	// Set wellknown config
	if err := c.SetBaseKeyOnWellKnownConfig(ctx); err != nil {
		return nil, err
	}

	return &kasregistry.SetBaseKeyResponse{
		NewBaseKey:      newBaseKey,
		PreviousBaseKey: previousDefaultKey,
	}, nil
}

func (c PolicyDBClient) SetBaseKeyOnWellKnownConfig(ctx context.Context) error {
	baseKey, err := c.GetBaseKey(ctx)
	if err != nil {
		return err
	}

	keyMapBytes, err := json.Marshal(baseKey)
	if err != nil {
		return err
	}

	var keyMap map[string]any
	if err := json.Unmarshal(keyMapBytes, &keyMap); err != nil {
		return err
	}

	if baseKey != nil {
		algorithm, err := db.FormatAlg(baseKey.GetPublicKey().GetAlgorithm())
		if err != nil {
			return fmt.Errorf("failed to format algorithm: %w", err)
		}
		publicKey, ok := keyMap["public_key"].(map[string]any)
		if !ok {
			return errors.New("failed to cast public_key")
		}
		publicKey["algorithm"] = algorithm
		keyMap["public_key"] = publicKey
	}

	wellknownconfiguration.UpdateConfigurationBaseKey(keyMap)
	return nil
}

func (c PolicyDBClient) ListKeyMappings(ctx context.Context, r *kasregistry.ListKeyMappingsRequest) (*kasregistry.ListKeyMappingsResponse, error) {
	limit, offset := c.getRequestedLimitOffset(r.GetPagination())
	maxLimit := c.listCfg.limitMax
	if maxLimit > 0 && limit > maxLimit {
		return nil, db.ErrListLimitTooLarge
	}

	params := listKeyMappingsParams{
		Offset: offset,
		Limit:  limit,
	}

	if r.GetIdentifier() != nil {
		switch i := r.GetIdentifier().(type) {
		case *kasregistry.ListKeyMappingsRequest_Id:
			pgUUID := pgtypeUUID(i.Id)
			if !pgUUID.Valid {
				return nil, db.ErrUUIDInvalid
			}
			params.ID = pgUUID
		case *kasregistry.ListKeyMappingsRequest_Key:
			keyID := pgtypeText(i.Key.GetKid())
			if !keyID.Valid {
				return nil, db.ErrSelectIdentifierInvalid
			}
			kasParams, err := getParamsFromKeyIdentifier(i.Key)
			if err != nil {
				return nil, err
			}
			params.KasID = kasParams.KasID
			params.KasUri = kasParams.KasURI
			params.KasName = kasParams.KasName
			params.Kid = keyID
		default:
			return nil, errors.Join(db.ErrUnknownSelectIdentifier, fmt.Errorf("type [%T] value [%v]", i, i))
		}
	}

	mappingRows, err := c.queries.listKeyMappings(ctx, params)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	// Need to build a json object
	mappings := make([]*kasregistry.KeyMapping, len(mappingRows))
	for i, mapping := range mappingRows {
		namespaceMappings, err := db.MappedPolicyObjectProtoJSON(mapping.NamespaceMappings)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal namespace mappings: %w", err)
		}
		definitionMappings, err := db.MappedPolicyObjectProtoJSON(mapping.AttributeMappings)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal attribute definition mappings: %w", err)
		}
		valueMappings, err := db.MappedPolicyObjectProtoJSON(mapping.ValueMappings)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal attribute value mappings: %w", err)
		}

		mappings[i] = &kasregistry.KeyMapping{
			Kid:               mapping.Kid,
			KasUri:            mapping.KasUri,
			NamespaceMappings: namespaceMappings,
			AttributeMappings: definitionMappings,
			ValueMappings:     valueMappings,
		}
	}

	var total int32
	var nextOffset int32
	if len(mappingRows) > 0 {
		total = int32(mappingRows[0].Total)
		nextOffset = getNextOffset(offset, limit, total)
	}

	return &kasregistry.ListKeyMappingsResponse{
		KeyMappings: mappings,
		Pagination: &policy.PageResponse{
			CurrentOffset: offset,
			Total:         total,
			NextOffset:    nextOffset,
		},
	}, nil
}

func (c PolicyDBClient) updateKeyInternal(ctx context.Context, params updateKeyParams) (*policy.KasKey, error) {
	count, err := c.queries.updateKey(ctx, params)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	} else if count > 1 {
		c.logger.Warn("updateKey updated more than one row", slog.Int64("count", count))
	}

	return c.GetKey(ctx, &kasregistry.GetKeyRequest_Id{
		Id: params.ID,
	})
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

	rotatedIDs.NamespaceIDs, err = c.queries.rotatePublicKeyForNamespace(ctx, rotatePublicKeyForNamespaceParams{
		OldKeyID: oldKeyID,
		NewKeyID: newKeyID,
	})
	if err != nil {
		return rotatedIDs, db.WrapIfKnownInvalidQueryErr(err)
	}

	rotatedIDs.AttributeDefIDs, err = c.queries.rotatePublicKeyForAttributeDefinition(ctx, rotatePublicKeyForAttributeDefinitionParams{
		OldKeyID: oldKeyID,
		NewKeyID: newKeyID,
	})
	if err != nil {
		return rotatedIDs, db.WrapIfKnownInvalidQueryErr(err)
	}

	rotatedIDs.AttributeValueIDs, err = c.queries.rotatePublicKeyForAttributeValue(ctx, rotatePublicKeyForAttributeValueParams{
		OldKeyID: oldKeyID,
		NewKeyID: newKeyID,
	})
	if err != nil {
		return rotatedIDs, db.WrapIfKnownInvalidQueryErr(err)
	}

	return rotatedIDs, nil
}

func (c PolicyDBClient) rotateBaseKey(ctx context.Context, rotatedOutKeyID *policy.KasKey, newKeyID string) error {
	baseKey, err := c.GetBaseKey(ctx)
	if err != nil {
		return err
	}
	if baseKey.GetPublicKey().GetKid() == rotatedOutKeyID.GetKey().GetKeyId() && baseKey.GetKasUri() == rotatedOutKeyID.GetKasUri() {
		_, err := c.SetBaseKey(ctx, &kasregistry.SetBaseKeyRequest{
			ActiveKey: &kasregistry.SetBaseKeyRequest_Id{
				Id: newKeyID,
			},
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func (c PolicyDBClient) verifyKeyIsActive(ctx context.Context, id string) error {
	key, err := c.GetKey(ctx, &kasregistry.GetKeyRequest_Id{
		Id: id,
	})
	if err != nil {
		return err
	}

	if key.GetKey().GetKeyStatus() != policy.KeyStatus_KEY_STATUS_ACTIVE {
		return fmt.Errorf("key with id %s is not active", id)
	}

	return nil
}

func isValidBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

func getParamsFromKeyIdentifier(i *kasregistry.KasKeyIdentifier) (*kasParams, error) {
	if i == nil {
		return nil, db.ErrSelectIdentifierInvalid
	}

	kasParams := &kasParams{}
	switch i.GetIdentifier().(type) {
	case *kasregistry.KasKeyIdentifier_KasId:
		kasID := pgtypeUUID(i.GetKasId())
		if !kasID.Valid {
			return nil, db.ErrSelectIdentifierInvalid
		}
		kasParams.KasID = kasID
	case *kasregistry.KasKeyIdentifier_Uri:
		kasURI := pgtypeText(i.GetUri())
		if !kasURI.Valid {
			return nil, db.ErrSelectIdentifierInvalid
		}
		kasParams.KasURI = kasURI
	case *kasregistry.KasKeyIdentifier_Name:
		kasName := pgtypeText(i.GetName())
		if !kasName.Valid {
			return nil, db.ErrSelectIdentifierInvalid
		}
		kasParams.KasName = kasName
	default:
		return nil, errors.Join(db.ErrUnknownSelectIdentifier, fmt.Errorf("type [%T] value [%v]", i, i))
	}

	return kasParams, nil
}
