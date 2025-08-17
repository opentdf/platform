package db

import (
	"context"
	"fmt"
	"strings"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/opentdf/platform/service/pkg/db"
)

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
	if err := unmarshalObligationValues(row.Values, oblVals); err != nil {
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

func breakOblFQN(fqn string) (string, string) {
	nsFQN := strings.Split(fqn, "/obl/")[0]
	parts := strings.Split(fqn, "/")
	oblName := parts[len(parts)-1]
	return nsFQN, oblName
}

func BuildOblFQN(nsFQN, oblName string) string {
	return nsFQN + "/obl/" + oblName
}

func (c PolicyDBClient) GetObligation(ctx context.Context, r *obligations.GetObligationRequest) (*policy.Obligation, error) {
	nsFQN, oblName := breakOblFQN(r.GetFqn())
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
	if err := unmarshalObligationValues(row.Values, oblVals); err != nil {
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

func (c PolicyDBClient) GetObligationsByFQNs(ctx context.Context, r *obligations.GetObligationsByFQNsRequest) ([]*policy.Obligation, error) {
	nsFQNs := make([]string, 0, len(r.GetFqns()))
	oblNames := make([]string, 0, len(r.GetFqns()))
	for _, fqn := range r.GetFqns() {
		nsFQN, oblName := breakOblFQN(fqn)
		nsFQNs = append(nsFQNs, nsFQN)
		oblNames = append(oblNames, oblName)
	}

	queryParams := getObligationsByFQNsParams{
		NamespaceFqns:   nsFQNs,
		ObligationNames: oblNames,
	}

	list, err := c.queries.getObligationsByFQNs(ctx, queryParams)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	obls := make([]*policy.Obligation, len(list))

	for i, r := range list {
		metadata := &common.Metadata{}
		if err = unmarshalMetadata(r.Metadata, metadata); err != nil {
			return nil, err
		}

		namespace := &policy.Namespace{}
		if err := unmarshalNamespace(r.Namespace, namespace); err != nil {
			return nil, fmt.Errorf("failed to unmarshal obligation namespace: %w", err)
		}

		values := []*policy.ObligationValue{}
		if err = unmarshalObligationValues(r.Values, values); err != nil {
			return nil, err
		}

		obls[i] = &policy.Obligation{
			Id:        r.ID,
			Name:      r.Name,
			Metadata:  metadata,
			Namespace: namespace,
			Values:    values,
		}
	}

	return obls, nil
}

func (c PolicyDBClient) ListObligations(ctx context.Context, r *obligations.ListObligationsRequest) ([]*policy.Obligation, *policy.PageResponse, error) {
	limit, offset := c.getRequestedLimitOffset(r.GetPagination())

	maxLimit := c.listCfg.limitMax
	if maxLimit > 0 && limit > maxLimit {
		return nil, nil, db.ErrListLimitTooLarge
	}

	rows, err := c.queries.listObligations(ctx, listObligationsParams{
		NamespaceID:  r.GetId(),
		NamespaceFqn: r.GetFqn(),
		Limit:        limit,
		Offset:       offset,
	})
	if err != nil {
		return nil, nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	obls := make([]*policy.Obligation, len(rows))

	for i, r := range rows {
		metadata := &common.Metadata{}
		if err = unmarshalMetadata(r.Metadata, metadata); err != nil {
			return nil, nil, err
		}

		namespace := &policy.Namespace{}
		if err := unmarshalNamespace(r.Namespace, namespace); err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal obligation namespace: %w", err)
		}

		values := []*policy.ObligationValue{}
		if err = unmarshalObligationValues(r.Values, values); err != nil {
			return nil, nil, err
		}

		obls[i] = &policy.Obligation{
			Id:        r.ID,
			Name:      r.Name,
			Metadata:  metadata,
			Namespace: namespace,
			Values:    values,
		}
	}

	var total int32
	var nextOffset int32
	if len(rows) > 0 {
		total = int32(rows[0].Total)
		nextOffset = getNextOffset(offset, limit, total)
	}

	pagination := &policy.PageResponse{
		CurrentOffset: offset,
		Total:         total,
		NextOffset:    nextOffset,
	}

	return obls, pagination, nil
}

func (c PolicyDBClient) UpdateObligation(ctx context.Context, r *obligations.UpdateObligationRequest) (*policy.Obligation, error) {
	id := r.GetId()
	name := r.GetName()
	obl, err := c.GetObligation(ctx, &obligations.GetObligationRequest{
		Identifier: &obligations.GetObligationRequest_Id{
			Id: id,
		},
	})
	if err != nil {
		return nil, err
	}
	if name == "" {
		name = obl.GetName()
	}
	metadataJSON, metadata, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
		return obl.GetMetadata(), nil
	})
	if err != nil {
		return nil, err
	}

	count, err := c.queries.updateObligation(ctx, updateObligationParams{
		ID:       id,
		Name:     name,
		Metadata: metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.Obligation{
		Id:        id,
		Name:      name,
		Metadata:  metadata,
		Namespace: obl.GetNamespace(),
		Values:    obl.GetValues(),
	}, nil
}

func (c PolicyDBClient) DeleteObligation(ctx context.Context, r *obligations.DeleteObligationRequest) (*policy.Obligation, error) {
	id := r.GetId()
	nsFQN, oblName := breakOblFQN(r.GetFqn())
	queryParams := deleteObligationParams{
		ID:           id,
		NamespaceFqn: nsFQN,
		Name:         oblName,
	}

	count, err := c.queries.deleteObligation(ctx, queryParams)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.Obligation{
		Id: id,
	}, nil
}
