package db

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/opentdf/platform/lib/identifier"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/opentdf/platform/service/pkg/db"
	"google.golang.org/protobuf/types/known/timestamppb"
)

///
/// Obligation Definitions
///

func (c PolicyDBClient) CreateObligation(ctx context.Context, r *obligations.CreateObligationRequest) (*policy.Obligation, error) {
	metadataJSON, _, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}
	name := strings.ToLower(r.GetName())
	values := r.GetValues()
	for idx, val := range values {
		values[idx] = strings.ToLower(val)
	}
	queryParams := createObligationParams{
		NamespaceID:  r.GetNamespaceId(),
		NamespaceFqn: r.GetNamespaceFqn(),
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

	for idx, val := range oblVals {
		val.Fqn = identifier.BuildOblValFQN(namespace.GetFqn(), name, val.GetValue())
		oblVals[idx] = val
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
		Fqn:       identifier.BuildOblFQN(namespace.GetFqn(), name),
	}, nil
}

func (c PolicyDBClient) GetObligation(ctx context.Context, r *obligations.GetObligationRequest) (*policy.Obligation, error) {
	nsFQN, oblName := identifier.BreakOblFQN(r.GetFqn())
	queryParams := getObligationParams{
		ID:           r.GetId(),
		Name:         oblName,
		NamespaceFqn: nsFQN,
	}

	row, err := c.queries.getObligation(ctx, queryParams)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	name := row.Name
	oblVals, err := unmarshalObligationValues(row.Values)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal obligation values: %w", err)
	}

	namespace := &policy.Namespace{}
	if err := unmarshalNamespace(row.Namespace, namespace); err != nil {
		return nil, fmt.Errorf("failed to unmarshal obligation namespace: %w", err)
	}

	for idx, val := range oblVals {
		val.Fqn = identifier.BuildOblValFQN(namespace.GetFqn(), name, val.GetValue())
		oblVals[idx] = val
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
		Fqn:       identifier.BuildOblFQN(namespace.GetFqn(), name),
	}, nil
}

func (c PolicyDBClient) GetObligationsByFQNs(ctx context.Context, r *obligations.GetObligationsByFQNsRequest) ([]*policy.Obligation, error) {
	nsFQNs := make([]string, 0, len(r.GetFqns()))
	oblNames := make([]string, 0, len(r.GetFqns()))
	for _, fqn := range r.GetFqns() {
		nsFQN, oblName := identifier.BreakOblFQN(fqn)
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
		name := r.Name
		for idx, val := range values {
			val.Fqn = identifier.BuildOblValFQN(namespace.GetFqn(), name, val.GetValue())
			values[idx] = val
		}

		obls[i] = &policy.Obligation{
			Id:        r.ID,
			Name:      name,
			Metadata:  metadata,
			Namespace: namespace,
			Values:    values,
			Fqn:       identifier.BuildOblFQN(namespace.GetFqn(), name),
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
		NamespaceID:  r.GetNamespaceId(),
		NamespaceFqn: r.GetNamespaceFqn(),
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

		name := r.Name
		values, err := unmarshalObligationValues(r.Values)
		if err != nil {
			return nil, nil, err
		}

		for idx, val := range values {
			val.Fqn = identifier.BuildOblValFQN(namespace.GetFqn(), name, val.GetValue())
			values[idx] = val
		}

		obls[i] = &policy.Obligation{
			Id:        r.ID,
			Name:      name,
			Metadata:  metadata,
			Namespace: namespace,
			Values:    values,
			Fqn:       identifier.BuildOblFQN(namespace.GetFqn(), name),
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
	name := strings.ToLower(r.GetName())
	obl, err := c.GetObligation(ctx, &obligations.GetObligationRequest{Id: id})
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
		Fqn:       identifier.BuildOblFQN(obl.GetNamespace().GetFqn(), name),
	}, nil
}

func (c PolicyDBClient) DeleteObligation(ctx context.Context, r *obligations.DeleteObligationRequest) (*policy.Obligation, error) {
	nsFQN, oblName := identifier.BreakOblFQN(r.GetFqn())
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
	nsFQN, oblName := identifier.BreakOblFQN(r.GetObligationFqn())
	value := strings.ToLower(r.GetValue())
	metadataJSON, _, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}

	queryParams := createObligationValueParams{
		ID:           r.GetObligationId(),
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

	// Create triggers for obligation value if provided
	triggers := make([]*policy.ObligationTrigger, len(r.GetTriggers()))
	if len(r.GetTriggers()) > 0 {
		for i, trigger := range r.GetTriggers() {
			createdTrigger, err := c.CreateObligationTrigger(ctx, &obligations.AddObligationTriggerRequest{
				ObligationValue: &common.IdFqnIdentifier{Id: row.ID},
				Action:          trigger.GetAction(),
				AttributeValue:  trigger.GetAttributeValue(),
				Context:         trigger.GetContext(),
			})
			if err != nil {
				return nil, err
			}
			triggers[i] = createdTrigger
		}
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

	name := row.Name
	obl := &policy.Obligation{
		Id:        row.ObligationID,
		Name:      name,
		Namespace: namespace,
	}

	return &policy.ObligationValue{
		Id:         row.ID,
		Obligation: obl,
		Value:      value,
		Metadata:   metadata,
		Triggers:   triggers,
		Fqn:        identifier.BuildOblValFQN(namespace.GetFqn(), name, value),
	}, nil
}

func (c PolicyDBClient) GetObligationValue(ctx context.Context, r *obligations.GetObligationValueRequest) (*policy.ObligationValue, error) {
	nsFQN, oblName, oblVal := identifier.BreakOblValFQN(r.GetFqn())
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

	triggers, err := unmarshalObligationTriggers(row.Triggers)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal obligation triggers: %w", err)
	}

	name := row.Name
	value := row.Value
	obl := &policy.Obligation{
		Id:        row.ObligationID,
		Name:      name,
		Namespace: namespace,
	}

	return &policy.ObligationValue{
		Id:         row.ID,
		Obligation: obl,
		Value:      value,
		Metadata:   metadata,
		Triggers:   triggers,
		Fqn:        identifier.BuildOblValFQN(namespace.GetFqn(), name, value),
	}, nil
}

func (c PolicyDBClient) GetObligationValuesByFQNs(ctx context.Context, r *obligations.GetObligationValuesByFQNsRequest) ([]*policy.ObligationValue, error) {
	nsFQNs := make([]string, 0, len(r.GetFqns()))
	oblNames := make([]string, 0, len(r.GetFqns()))
	oblVals := make([]string, 0, len(r.GetFqns()))
	for _, fqn := range r.GetFqns() {
		nsFQN, oblName, oblVal := identifier.BreakOblValFQN(fqn)
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

		triggers, err := unmarshalObligationTriggers(r.Triggers)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal obligation triggers: %w", err)
		}

		name := r.Name
		value := r.Value
		obl := &policy.Obligation{
			Id:        r.ObligationID,
			Name:      name,
			Namespace: namespace,
		}

		vals[i] = &policy.ObligationValue{
			Id:         r.ID,
			Value:      value,
			Metadata:   metadata,
			Obligation: obl,
			Triggers:   triggers,
			Fqn:        identifier.BuildOblValFQN(namespace.GetFqn(), name, value),
		}
	}

	return vals, nil
}

func (c PolicyDBClient) UpdateObligationValue(ctx context.Context, r *obligations.UpdateObligationValueRequest) (*policy.ObligationValue, error) {
	id := r.GetId()
	value := strings.ToLower(r.GetValue())
	oblVal, err := c.GetObligationValue(ctx, &obligations.GetObligationValueRequest{Id: id})
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

	// Update triggers for obligation value if provided
	triggers := oblVal.GetTriggers()
	if len(r.GetTriggers()) > 0 {
		// Delete all existing triggers for this obligation value
		_, err := c.queries.deleteAllObligationTriggersForValue(ctx, id)
		if err != nil {
			return nil, db.WrapIfKnownInvalidQueryErr(err)
		}

		// Create new triggers
		triggers = make([]*policy.ObligationTrigger, len(r.GetTriggers()))
		for i, trigger := range r.GetTriggers() {
			createdTrigger, err := c.CreateObligationTrigger(ctx, &obligations.AddObligationTriggerRequest{
				ObligationValue: &common.IdFqnIdentifier{Id: id},
				Action:          trigger.GetAction(),
				AttributeValue:  trigger.GetAttributeValue(),
				Context:         trigger.GetContext(),
			})
			if err != nil {
				return nil, err
			}
			triggers[i] = createdTrigger
		}
	}

	obl := oblVal.GetObligation()
	name := obl.GetName()
	return &policy.ObligationValue{
		Id:         id,
		Value:      value,
		Metadata:   metadata,
		Obligation: obl,
		Triggers:   triggers,
		Fqn:        identifier.BuildOblValFQN(obl.GetNamespace().GetFqn(), name, value),
	}, nil
}

func (c PolicyDBClient) DeleteObligationValue(ctx context.Context, r *obligations.DeleteObligationValueRequest) (*policy.ObligationValue, error) {
	nsFQN, oblName, valName := identifier.BreakOblValFQN(r.GetFqn())
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

// ********************************************
// ! Obligation Triggers
// ********************************************

func (c PolicyDBClient) CreateObligationTrigger(ctx context.Context, r *obligations.AddObligationTriggerRequest) (*policy.ObligationTrigger, error) {
	metadataJSON, _, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}

	// Get obligation
	var oblValReq *obligations.GetObligationValueRequest
	if r.GetObligationValue().GetId() != "" {
		oblValReq = &obligations.GetObligationValueRequest{
			Id: r.GetObligationValue().GetId(),
		}
	} else {
		oblValReq = &obligations.GetObligationValueRequest{
			Fqn: r.GetObligationValue().GetFqn(),
		}
	}

	oblVal, err := c.GetObligationValue(ctx, oblValReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get obligation value: %w", err)
	}

	params := createObligationTriggerParams{
		ObligationValueID: oblVal.GetId(),
		ActionName:        r.GetAction().GetName(),
		ActionID:          r.GetAction().GetId(),
		AttributeValueID:  r.GetAttributeValue().GetId(),
		AttributeValueFqn: r.GetAttributeValue().GetFqn(),
		ClientID:          r.GetContext().GetPep().GetClientId(),
		Metadata:          metadataJSON,
	}
	row, err := c.queries.createObligationTrigger(ctx, params)
	if err != nil {
		wrappedErr := db.WrapIfKnownInvalidQueryErr(err)
		if errors.Is(wrappedErr, db.ErrNotNullViolation) {
			return nil, errors.Join(db.ErrInvalidOblTriParam, wrappedErr)
		}
		return nil, wrappedErr
	}

	metadata := &common.Metadata{}
	if err := unmarshalMetadata(row.Metadata, metadata); err != nil {
		return nil, err
	}

	trigger, err := unmarshalObligationTrigger(row.Trigger)
	if err != nil {
		return nil, err
	}

	trigger.Metadata = metadata

	return trigger, nil
}

func (c PolicyDBClient) DeleteObligationTrigger(ctx context.Context, r *obligations.RemoveObligationTriggerRequest) (*policy.ObligationTrigger, error) {
	id, err := c.queries.deleteObligationTrigger(ctx, r.GetId())
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if id == "" {
		return nil, db.ErrNotFound
	}

	return &policy.ObligationTrigger{
		Id: id,
	}, nil
}
