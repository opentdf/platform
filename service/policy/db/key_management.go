package db

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/keymanagement"
	"github.com/opentdf/platform/service/pkg/db"
)

func (c PolicyDBClient) CreateProviderConfig(ctx context.Context, r *keymanagement.CreateProviderConfigRequest) (*policy.KeyProviderConfig, error) {
	name := strings.ToLower(r.GetName())
	config := r.GetConfigJson()
	manager := r.GetManager()

	metadataJSON, _, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}

	providerConfig, err := c.Queries.createProviderConfig(ctx, createProviderConfigParams{
		ProviderName: name,
		Manager:      manager,
		Config:       config,
		Metadata:     metadataJSON,
	})
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
		Manager:    providerConfig.Manager,
		ConfigJson: providerConfig.Config,
		Metadata:   metadata,
	}, nil
}

func (c PolicyDBClient) GetProviderConfig(ctx context.Context, identifier any) (*policy.KeyProviderConfig, error) {
	var params getProviderConfigParams

	switch i := identifier.(type) {
	case *keymanagement.GetProviderConfigRequest_Id:
		id := pgtypeUUID(i.Id)
		if !id.Valid {
			return nil, db.ErrUUIDInvalid
		}
		params = getProviderConfigParams{ID: id}
	case *keymanagement.GetProviderConfigRequest_Name:
		name := pgtypeText(strings.ToLower(i.Name))
		if !name.Valid {
			return nil, db.ErrSelectIdentifierInvalid
		}
		params = getProviderConfigParams{Name: name}
	default:
		// unexpected type
		return nil, errors.Join(db.ErrUnknownSelectIdentifier, fmt.Errorf("type [%T] value [%v]", i, i))
	}

	pcRow, err := c.Queries.getProviderConfig(ctx, params)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	metadata := &common.Metadata{}
	if err = unmarshalMetadata(pcRow.Metadata, metadata); err != nil {
		return nil, err
	}

	return &policy.KeyProviderConfig{
		Id:         pcRow.ID,
		Name:       pcRow.ProviderName,
		Manager:    pcRow.Manager,
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

	providerConfigs, err := c.Queries.listProviderConfigs(ctx, listProviderConfigsParams{
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
			Manager:    pcRow.Manager,
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
	manager := r.GetManager()
	id := r.GetId()

	// if extend we need to merge the metadata
	metadataJSON, _, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
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

	count, err := c.Queries.updateProviderConfig(ctx, updateProviderConfigParams{
		ID:           id,
		ProviderName: pgtypeText(name),
		Manager:      pgtypeText(manager),
		Config:       config,
		Metadata:     metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	if count == 0 {
		return nil, db.ErrNotFound
	} else if count > 1 {
		c.logger.Warn("updateProviderConfig updated more than one row", slog.Int64("count", count))
	}

	return c.GetProviderConfig(ctx, &keymanagement.GetProviderConfigRequest_Id{
		Id: id,
	})
}

func (c PolicyDBClient) DeleteProviderConfig(ctx context.Context, id string) (*policy.KeyProviderConfig, error) {
	pgID := pgtypeUUID(id)
	if !pgID.Valid {
		return nil, db.ErrUUIDInvalid
	}

	_, err := c.Queries.deleteProviderConfig(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &policy.KeyProviderConfig{
		Id: id,
	}, nil
}
