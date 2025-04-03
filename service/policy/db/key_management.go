package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/keymanagement"
	"github.com/opentdf/platform/service/pkg/db"
)

func (c PolicyDBClient) CreateProviderConfig(ctx context.Context, r *keymanagement.CreateProviderConfigRequest) (*policy.KeyProviderConfig, error) {
	name := strings.ToLower(r.GetName())
	config := r.GetConfigJson()

	metadataJSON, _, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}

	providerConfig, err := c.Queries.CreateProviderConfig(ctx, CreateProviderConfigParams{
		ProviderName: name,
		Config:       config,
		Metadata:     metadataJSON})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	metadata := &common.Metadata{}
	if err = unmarshalMetadata(providerConfig.Metadata, metadata); err != nil {
		return nil, err
	}

	return &policy.KeyProviderConfig{
		Id:         providerConfig.ID,
		Name:       providerConfig.ProviderName,
		ConfigJson: providerConfig.Config,
		Metadata:   metadata,
	}, nil
}

func (c PolicyDBClient) GetProviderConfig(ctx context.Context, identifier any) (*policy.KeyProviderConfig, error) {
	var params GetProviderConfigParams

	switch i := identifier.(type) {
	case *keymanagement.GetProviderConfigRequest_Id:
		id := pgtypeUUID(i.Id)
		if !id.Valid {
			return nil, db.ErrUUIDInvalid
		}
		params = GetProviderConfigParams{ID: id}
	case *keymanagement.GetProviderConfigRequest_Name:
		name := pgtypeText(i.Name)
		if !name.Valid {
			return nil, db.ErrSelectIdentifierInvalid
		}
		params = GetProviderConfigParams{Name: name}
	default:
		// unexpected type
		return nil, errors.Join(db.ErrUnknownSelectIdentifier, fmt.Errorf("type [%T] value [%v]", i, i))
	}

	pcRow, err := c.Queries.GetProviderConfig(ctx, params)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	mappedMetadata := make(map[string]any)
	if err = json.Unmarshal(pcRow.Metadata, &mappedMetadata); err != nil {
		return nil, err
	}

	metadata := &common.Metadata{}
	if err = unmarshalMetadata(pcRow.Metadata, metadata); err != nil {
		return nil, err
	}

	return &policy.KeyProviderConfig{
		Id:         pcRow.ID,
		Name:       pcRow.ProviderName,
		ConfigJson: pcRow.Config,
		Metadata:   metadata,
	}, nil
}

func (c PolicyDBClient) ListProviderConfigs(ctx context.Context, page *policy.PageRequest) (*keymanagement.ListProviderConfigsResponse, error) {
	limit, offset := c.getRequestedLimitOffset(page)
	maxLimit := c.listCfg.limitMax

	if maxLimit > 0 && limit > maxLimit {
		return nil, db.ErrListLimitTooLarge
	}

	providerConfigs, err := c.Queries.ListProviderConfigs(ctx, ListProviderConfigsParams{
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	var pcs []*policy.KeyProviderConfig
	for _, pcRow := range providerConfigs {
		metadata := &common.Metadata{}
		if err = unmarshalMetadata(pcRow.Metadata, metadata); err != nil {
			return nil, err
		}

		pcs = append(pcs, &policy.KeyProviderConfig{
			Id:         pcRow.ID,
			Name:       pcRow.ProviderName,
			ConfigJson: pcRow.Config,
			Metadata:   metadata,
		})
	}

	var total int32
	var nextOffset int32
	if len(providerConfigs) > 0 {
		total = int32(providerConfigs[0].Total)
		nextOffset = getNextOffset(offset, limit, total)
	}

	return &keymanagement.ListProviderConfigsResponse{
		ProviderConfigs: pcs,
		Pagination: &policy.PageResponse{
			CurrentOffset: offset,
			Total:         total,
			NextOffset:    nextOffset,
		},
	}, nil
}

func (c PolicyDBClient) UpdateProviderConfig(ctx context.Context, r *keymanagement.UpdateProviderConfigRequest) (*policy.KeyProviderConfig, error) {
	name := strings.ToLower(r.GetName())
	config := r.GetConfigJson()
	id := r.GetId()

	// if extend we need to merge the metadata
	metadataJSON, metadata, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
		a, err := c.GetProviderConfig(ctx, &keymanagement.GetProviderConfigRequest_Id{
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

	count, err := c.Queries.UpdateProviderConfig(ctx, UpdateProviderConfigParams{
		ID:           id,
		ProviderName: pgtypeText(name),
		Config:       config,
		Metadata:     metadataJSON})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	if count == 0 {
		return nil, db.ErrNotFound
	} else if count > 1 {
		c.logger.Warn("UpdateProviderConfig updated more than one row", "count", count)
	}

	return &policy.KeyProviderConfig{
		Id:         id,
		Name:       name,
		ConfigJson: config,
		Metadata:   metadata,
	}, nil
}

func (c PolicyDBClient) DeleteProviderConfig(ctx context.Context, id string) (*policy.KeyProviderConfig, error) {
	pgID := pgtypeUUID(id)
	if !pgID.Valid {
		return nil, db.ErrUUIDInvalid
	}

	_, err := c.Queries.DeleteProviderConfig(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &policy.KeyProviderConfig{
		Id: id,
	}, nil
}
