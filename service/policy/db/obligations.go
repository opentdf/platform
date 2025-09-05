package db

import (
	"context"
	"fmt"
	"strings"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/opentdf/platform/service/pkg/db"
	"google.golang.org/protobuf/types/known/timestamppb"
)

///
/// Obligation Definitions
///

// TODO: convert names and values to lowercase

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
	now := timestamppb.Now()
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	oblVals, err := unmarshalObligationValues(row.Values)
	if err != nil {
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
	metadata.CreatedAt = now
	metadata.UpdatedAt = now

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

func breakOblValFQN(fqn string) (string, string, string) {
	parts := strings.Split(fqn, "/value/")
	nsFQN, oblName := breakOblFQN(parts[0])
	oblVal := parts[len(parts)-1]
	return nsFQN, oblName, oblVal
}

func BuildOblFQN(nsFQN, oblName string) string {
	return nsFQN + "/obl/" + oblName
}

func BuildOblValFQN(nsFQN, oblName, oblVal string) string {
	return nsFQN + "/obl/" + oblName + "/value/" + oblVal
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

	oblVals, err := unmarshalObligationValues(row.Values)
	if err != nil {
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
		NamespaceFqns: nsFQNs,
		Names:         oblNames,
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

		values, err := unmarshalObligationValues(r.Values)
		if err != nil {
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

		values, err := unmarshalObligationValues(r.Values)
		if err != nil {
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
	now := timestamppb.Now()
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}
	if metadata == nil {
		metadata = &common.Metadata{}
	}
	metadata.CreatedAt = obl.GetMetadata().GetCreatedAt()
	metadata.UpdatedAt = now

	return &policy.Obligation{
		Id:        id,
		Name:      name,
		Metadata:  metadata,
		Namespace: obl.GetNamespace(),
		Values:    obl.GetValues(),
	}, nil
}

func (c PolicyDBClient) DeleteObligation(ctx context.Context, r *obligations.DeleteObligationRequest) (*policy.Obligation, error) {
	nsFQN, oblName := breakOblFQN(r.GetFqn())
	queryParams := deleteObligationParams{
		ID:           r.GetId(),
		NamespaceFqn: nsFQN,
		Name:         oblName,
	}

	id, err := c.queries.deleteObligation(ctx, queryParams)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if id == "" {
		return nil, db.ErrNotFound
	}

	return &policy.Obligation{
		Id: id,
	}, nil
}

///
/// Obligation Values
///

func (c PolicyDBClient) CreateObligationValue(ctx context.Context, r *obligations.CreateObligationValueRequest) (*policy.ObligationValue, error) {
	nsFQN, oblName := breakOblFQN(r.GetFqn())
	value := r.GetValue()
	metadataJSON, _, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}

	queryParams := createObligationValueParams{
		ID:           r.GetId(),
		Name:         oblName,
		NamespaceFqn: nsFQN,
		Value:        value,
		Metadata:     metadataJSON,
	}

	row, err := c.queries.createObligationValue(ctx, queryParams)
	now := timestamppb.Now()
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	namespace := &policy.Namespace{}
	if err := unmarshalNamespace(row.Namespace, namespace); err != nil {
		return nil, fmt.Errorf("failed to unmarshal obligation namespace: %w", err)
	}

	metadata := &common.Metadata{}
	if err := unmarshalMetadata(row.Metadata, metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal obligation metadata: %w", err)
	}

	metadata.CreatedAt = now
	metadata.UpdatedAt = now

	obl := &policy.Obligation{
		Id:        row.ObligationID,
		Name:      row.Name,
		Namespace: namespace,
	}

	return &policy.ObligationValue{
		Id:         row.ID,
		Obligation: obl,
		Value:      value,
		Metadata:   metadata,
	}, nil
}

func (c PolicyDBClient) GetObligationValue(ctx context.Context, r *obligations.GetObligationValueRequest) (*policy.ObligationValue, error) {
	nsFQN, oblName, oblVal := breakOblValFQN(r.GetFqn())
	queryParams := getObligationValueParams{
		ID:           r.GetId(),
		Name:         oblName,
		Value:        oblVal,
		NamespaceFqn: nsFQN,
	}

	row, err := c.queries.getObligationValue(ctx, queryParams)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	namespace := &policy.Namespace{}
	if err := unmarshalNamespace(row.Namespace, namespace); err != nil {
		return nil, fmt.Errorf("failed to unmarshal obligation namespace: %w", err)
	}

	metadata := &common.Metadata{}
	if err := unmarshalMetadata(row.Metadata, metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal obligation metadata: %w", err)
	}

	obl := &policy.Obligation{
		Id:        row.ObligationID,
		Name:      row.Name,
		Namespace: namespace,
	}

	return &policy.ObligationValue{
		Id:         row.ID,
		Obligation: obl,
		Value:      row.Value,
		Metadata:   metadata,
	}, nil
}

func (c PolicyDBClient) GetObligationValuesByFQNs(ctx context.Context, r *obligations.GetObligationValuesByFQNsRequest) ([]*policy.ObligationValue, error) {
	nsFQNs := make([]string, 0, len(r.GetFqns()))
	oblNames := make([]string, 0, len(r.GetFqns()))
	oblVals := make([]string, 0, len(r.GetFqns()))
	for _, fqn := range r.GetFqns() {
		nsFQN, oblName, oblVal := breakOblValFQN(fqn)
		nsFQNs = append(nsFQNs, nsFQN)
		oblNames = append(oblNames, oblName)
		oblVals = append(oblVals, oblVal)
	}

	queryParams := getObligationValuesByFQNsParams{
		NamespaceFqns: nsFQNs,
		Names:         oblNames,
		Values:        oblVals,
	}

	list, err := c.queries.getObligationValuesByFQNs(ctx, queryParams)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	vals := make([]*policy.ObligationValue, len(list))

	for i, r := range list {
		metadata := &common.Metadata{}
		if err = unmarshalMetadata(r.Metadata, metadata); err != nil {
			return nil, err
		}

		namespace := &policy.Namespace{}
		if err := unmarshalNamespace(r.Namespace, namespace); err != nil {
			return nil, fmt.Errorf("failed to unmarshal obligation namespace: %w", err)
		}

		obl := &policy.Obligation{
			Id:        r.ObligationID,
			Name:      r.Name,
			Namespace: namespace,
		}

		vals[i] = &policy.ObligationValue{
			Id:         r.ID,
			Value:      r.Value,
			Metadata:   metadata,
			Obligation: obl,
		}
	}

	return vals, nil
}

func (c PolicyDBClient) UpdateObligationValue(ctx context.Context, r *obligations.UpdateObligationValueRequest) (*policy.ObligationValue, error) {
	id := r.GetId()
	value := r.GetValue()
	oblVal, err := c.GetObligationValue(ctx, &obligations.GetObligationValueRequest{
		Identifier: &obligations.GetObligationValueRequest_Id{
			Id: id,
		},
	})
	if err != nil {
		return nil, err
	}
	if value == "" {
		value = oblVal.GetValue()
	}
	metadataJSON, metadata, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
		return oblVal.GetMetadata(), nil
	})
	if err != nil {
		return nil, err
	}

	count, err := c.queries.updateObligationValue(ctx, updateObligationValueParams{
		ID:       id,
		Value:    value,
		Metadata: metadataJSON,
	})
	now := timestamppb.Now()
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}
	if metadata == nil {
		metadata = &common.Metadata{}
	}
	metadata.CreatedAt = oblVal.GetMetadata().GetCreatedAt()
	metadata.UpdatedAt = now

	return &policy.ObligationValue{
		Id:         id,
		Value:      value,
		Metadata:   metadata,
		Obligation: oblVal.GetObligation(),
	}, nil
}

func (c PolicyDBClient) DeleteObligationValue(ctx context.Context, r *obligations.DeleteObligationValueRequest) (*policy.ObligationValue, error) {
	nsFQN, oblName, valName := breakOblValFQN(r.GetFqn())
	queryParams := deleteObligationValueParams{
		ID:           r.GetId(),
		NamespaceFqn: nsFQN,
		Name:         oblName,
		Value:        valName,
	}

	id, err := c.queries.deleteObligationValue(ctx, queryParams)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if id == "" {
		return nil, db.ErrNotFound
	}

	return &policy.ObligationValue{
		Id: id,
	}, nil
}
