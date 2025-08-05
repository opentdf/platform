package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/opentdf/platform/service/pkg/db"
	"google.golang.org/protobuf/encoding/protojson"
)

func unmarshalObligationValuesProto(valuesJSON []byte, values []*policy.ObligationValue) error {
	if valuesJSON == nil {
		return nil
	}

	raw := []json.RawMessage{}
	if err := json.Unmarshal(valuesJSON, &raw); err != nil {
		return fmt.Errorf("failed to unmarshal values array [%s]: %w", string(valuesJSON), err)
	}

	for _, r := range raw {
		v := &policy.ObligationValue{}
		if err := protojson.Unmarshal(r, v); err != nil {
			return fmt.Errorf("failed to unmarshal value [%s]: %w", string(r), err)
		}
		values = append(values, v)
	}

	return nil
}

func unmarshalNamespace(namespaceJSON []byte, namespace *policy.Namespace) error {
	if namespaceJSON != nil {
		if err := protojson.Unmarshal(namespaceJSON, namespace); err != nil {
			return fmt.Errorf("failed to unmarshal namespaceJSON [%s]: %w", string(namespaceJSON), err)
		}
	}
	return nil
}

///
/// Obligation Definitions
///

func (c PolicyDBClient) CreateObligation(ctx context.Context, r *obligations.CreateObligationRequest) (*policy.Obligation, error) {
	metadataJSON, _, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}
	name := r.GetName()
	values := r.GetValues()
	queryParams := createObligationParams{
		NamespaceID:  r.GetId(),
		NamespaceFqn: r.GetFqn(),
		Name:         name,
		Metadata:     metadataJSON,
		Values:       values,
	}
	row, err := c.queries.createObligation(ctx, queryParams)

	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	oblVals := make([]*policy.ObligationValue, 0, len(values))
	if err := unmarshalObligationValuesProto(row.Values, oblVals); err != nil {
		return nil, fmt.Errorf("failed to unmarshal obligation values: %w", err)
	}

	namespace := &policy.Namespace{}
	if err := unmarshalNamespace(row.Namespace, namespace); err != nil {
		return nil, fmt.Errorf("failed to unmarshal obligation namespace: %w", err)
	}

	metadata := &common.Metadata{}
	if err := unmarshalMetadata(row.Metadata, metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal obligation metadata: %w", err)
	}

	return &policy.Obligation{
		Id:        row.ID,
		Name:      name,
		Metadata:  metadata,
		Namespace: namespace,
		Values:    oblVals,
	}, nil
}

func splitOblFQN(fqn string) (string, string) {
	nsFQN := strings.Split(fqn, "/obl/")[0]
	parts := strings.Split(fqn, "/")
	oblName := parts[len(parts)-1]
	return nsFQN, oblName
}

func (c PolicyDBClient) GetObligation(ctx context.Context, r *obligations.GetObligationRequest) (*policy.Obligation, error) {
	nsFQN, oblName := splitOblFQN(r.GetFqn())
	queryParams := getObligationParams{
		ID:           r.GetId(),
		Name:         oblName,
		NamespaceFqn: nsFQN,
	}

	row, err := c.queries.getObligation(ctx, queryParams)

	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	oblVals := make([]*policy.ObligationValue, 0)
	if err := unmarshalObligationValuesProto(row.Values, oblVals); err != nil {
		return nil, fmt.Errorf("failed to unmarshal obligation values: %w", err)
	}

	namespace := &policy.Namespace{}
	if err := unmarshalNamespace(row.Namespace, namespace); err != nil {
		return nil, fmt.Errorf("failed to unmarshal obligation namespace: %w", err)
	}

	metadata := &common.Metadata{}
	if err := unmarshalMetadata(row.Metadata, metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal obligation metadata: %w", err)
	}

	return &policy.Obligation{
		Id:        row.ID,
		Name:      row.Name,
		Metadata:  metadata,
		Namespace: namespace,
		Values:    oblVals,
	}, nil
}

func (c PolicyDBClient) ListObligations(ctx context.Context, r *obligations.ListObligationsRequest) ([]*policy.Obligation, *policy.PageResponse, error) {
	limit, offset := c.getRequestedLimitOffset(r.GetPagination())

	maxLimit := c.listCfg.limitMax
	if maxLimit > 0 && limit > maxLimit {
		return nil, nil, db.ErrListLimitTooLarge
	}

	list, err := c.queries.listObligations(ctx, listObligationsParams{
		NamespaceID:  r.GetId(),
		NamespaceFqn: r.GetFqn(),
		Limit:        limit,
		Offset:       offset,
	})
	if err != nil {
		return nil, nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	oblList := make([]*policy.Obligation, len(list))

	for i, r := range list {
		metadata := &common.Metadata{}
		if err = unmarshalMetadata(r.Metadata, metadata); err != nil {
			return nil, nil, err
		}

		namespace := &policy.Namespace{}
		if err := unmarshalNamespace(r.Namespace, namespace); err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal obligation namespace: %w", err)
		}

		values := []*policy.ObligationValue{}
		if err = unmarshalObligationValuesProto(r.Values, values); err != nil {
			return nil, nil, err
		}

		oblList[i] = &policy.Obligation{
			Id:        r.ID,
			Name:      r.Name,
			Metadata:  metadata,
			Namespace: namespace,
			Values:    values,
		}
	}

	var total int32
	var nextOffset int32
	if len(list) > 0 {
		total = int32(list[0].Total)
		nextOffset = getNextOffset(offset, limit, total)
	}

	pagination := &policy.PageResponse{
		CurrentOffset: offset,
		Total:         total,
		NextOffset:    nextOffset,
	}

	return oblList, pagination, nil
}

func (c PolicyDBClient) UpdateObligationDefinition(ctx context.Context, r *obligations.UpdateObligationRequest) (*policy.Obligation, error) {
	return nil, errors.New("UpdateObligationDefinition is not implemented in PolicyDBClient")
}

func (c PolicyDBClient) DeleteObligationDefinition(ctx context.Context, r *obligations.DeleteObligationRequest) (*policy.Obligation, error) {
	return nil, errors.New("DeleteObligationDefinition is not implemented in PolicyDBClient")
}
