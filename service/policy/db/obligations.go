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

func setOblValFQNs(values []*policy.ObligationValue, nsFQN, name string) []*policy.ObligationValue {
	for i, v := range values {
		v.Fqn = identifier.BuildOblValFQN(nsFQN, name, v.GetValue())
		values[i] = v
	}
	return values
}

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
	queryParams := UnifiedCreateObligationParams{
		NamespaceID:  r.GetNamespaceId(),
		NamespaceFqn: r.GetNamespaceFqn(),
		Name:         name,
		Metadata:     metadataJSON,
		Values:       values,
	}
	row, err := c.router.CreateObligation(ctx, queryParams)
	now := timestamppb.Now()
	if err != nil {
		return nil, c.WrapError(err)
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

	nsFQN := namespace.GetFqn()
	oblVals = setOblValFQNs(oblVals, nsFQN, name)

	return &policy.Obligation{
		Id:        row.ID,
		Name:      name,
		Metadata:  metadata,
		Namespace: namespace,
		Values:    oblVals,
		Fqn:       identifier.BuildOblFQN(nsFQN, name),
	}, nil
}

func (c PolicyDBClient) GetObligation(ctx context.Context, r *obligations.GetObligationRequest) (*policy.Obligation, error) {
	nsFQN, oblName := identifier.BreakOblFQN(r.GetFqn())
	queryParams := UnifiedGetObligationParams{
		ID:           r.GetId(),
		Name:         oblName,
		NamespaceFqn: nsFQN,
	}

	row, err := c.router.GetObligation(ctx, queryParams)
	if err != nil {
		return nil, c.WrapError(err)
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

	nsFQN = namespace.GetFqn()
	oblVals = setOblValFQNs(oblVals, nsFQN, name)

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
		Fqn:       identifier.BuildOblFQN(nsFQN, name),
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

	list, err := c.router.GetObligationsByFQNs(ctx, nsFQNs, oblNames)
	if err != nil {
		return nil, c.WrapError(err)
	}
	obls := make([]*policy.Obligation, len(list))

	for i, row := range list {
		metadata := &common.Metadata{}
		if err = unmarshalMetadata(row.Metadata, metadata); err != nil {
			return nil, err
		}

		namespace := &policy.Namespace{}
		if err := unmarshalNamespace(row.Namespace, namespace); err != nil {
			return nil, fmt.Errorf("failed to unmarshal obligation namespace: %w", err)
		}

		values, err := unmarshalObligationValues(row.Values)
		if err != nil {
			return nil, err
		}
		name := row.Name
		nsFQN := namespace.GetFqn()
		values = setOblValFQNs(values, nsFQN, name)

		obls[i] = &policy.Obligation{
			Id:        row.ID,
			Name:      name,
			Metadata:  metadata,
			Namespace: namespace,
			Values:    values,
			Fqn:       identifier.BuildOblFQN(nsFQN, name),
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

	rows, err := c.router.ListObligations(ctx, UnifiedListObligationsParams{
		NamespaceID:  r.GetNamespaceId(),
		NamespaceFqn: r.GetNamespaceFqn(),
		Limit:        limit,
		Offset:       offset,
	})
	if err != nil {
		return nil, nil, c.WrapError(err)
	}
	obls := make([]*policy.Obligation, len(rows))

	for i, row := range rows {
		metadata := &common.Metadata{}
		if err = unmarshalMetadata(row.Metadata, metadata); err != nil {
			return nil, nil, err
		}

		namespace := &policy.Namespace{}
		if err := unmarshalNamespace(row.Namespace, namespace); err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal obligation namespace: %w", err)
		}

		values, err := unmarshalObligationValues(row.Values)
		if err != nil {
			return nil, nil, err
		}

		name := row.Name
		nsFQN := namespace.GetFqn()
		values = setOblValFQNs(values, nsFQN, name)

		obls[i] = &policy.Obligation{
			Id:        row.ID,
			Name:      name,
			Metadata:  metadata,
			Namespace: namespace,
			Values:    values,
			Fqn:       identifier.BuildOblFQN(nsFQN, name),
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

	count, err := c.router.UpdateObligation(ctx, id, name, metadataJSON)
	now := timestamppb.Now()
	if err != nil {
		return nil, c.WrapError(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}
	if metadata == nil {
		metadata = &common.Metadata{}
	}
	metadata.CreatedAt = obl.GetMetadata().GetCreatedAt()
	metadata.UpdatedAt = now
	namespace := obl.GetNamespace()
	nsFQN := namespace.GetFqn()
	values := obl.GetValues()
	values = setOblValFQNs(values, nsFQN, name)

	return &policy.Obligation{
		Id:        id,
		Name:      name,
		Metadata:  metadata,
		Namespace: namespace,
		Values:    values,
		Fqn:       identifier.BuildOblFQN(nsFQN, name),
	}, nil
}

func (c PolicyDBClient) DeleteObligation(ctx context.Context, r *obligations.DeleteObligationRequest) (*policy.Obligation, error) {
	nsFQN, oblName := identifier.BreakOblFQN(r.GetFqn())

	id, err := c.router.DeleteObligation(ctx, r.GetId(), nsFQN, oblName)
	if err != nil {
		return nil, c.WrapError(err)
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

	queryParams := UnifiedCreateObligationValueParams{
		ObligationID: r.GetObligationId(),
		Name:         oblName,
		NamespaceFqn: nsFQN,
		Value:        value,
		Metadata:     metadataJSON,
	}

	row, err := c.router.CreateObligationValue(ctx, queryParams)
	now := timestamppb.Now()
	if err != nil {
		return nil, c.WrapError(err)
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
	nsFQN = namespace.GetFqn()
	obl := &policy.Obligation{
		Id:        row.ObligationID,
		Name:      name,
		Namespace: namespace,
		Fqn:       identifier.BuildOblFQN(nsFQN, name),
	}

	return &policy.ObligationValue{
		Id:         row.ID,
		Obligation: obl,
		Value:      value,
		Metadata:   metadata,
		Triggers:   triggers,
		Fqn:        identifier.BuildOblValFQN(nsFQN, name, value),
	}, nil
}

func (c PolicyDBClient) GetObligationValue(ctx context.Context, r *obligations.GetObligationValueRequest) (*policy.ObligationValue, error) {
	nsFQN, oblName, oblVal := identifier.BreakOblValFQN(r.GetFqn())
	queryParams := UnifiedGetObligationValueParams{
		ID:           r.GetId(),
		Name:         oblName,
		Value:        oblVal,
		NamespaceFqn: nsFQN,
	}

	row, err := c.router.GetObligationValue(ctx, queryParams)
	if err != nil {
		return nil, c.WrapError(err)
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
	nsFQN = namespace.GetFqn()
	obl := &policy.Obligation{
		Id:        row.ObligationID,
		Name:      name,
		Namespace: namespace,
		Fqn:       identifier.BuildOblFQN(nsFQN, name),
	}

	return &policy.ObligationValue{
		Id:         row.ID,
		Obligation: obl,
		Value:      value,
		Metadata:   metadata,
		Triggers:   triggers,
		Fqn:        identifier.BuildOblValFQN(nsFQN, name, value),
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

	list, err := c.router.GetObligationValuesByFQNs(ctx, nsFQNs, oblNames, oblVals)
	if err != nil {
		return nil, c.WrapError(err)
	}
	vals := make([]*policy.ObligationValue, len(list))

	for i, row := range list {
		metadata := &common.Metadata{}
		if err = unmarshalMetadata(row.Metadata, metadata); err != nil {
			return nil, err
		}

		namespace := &policy.Namespace{}
		if err := unmarshalNamespace(row.Namespace, namespace); err != nil {
			return nil, fmt.Errorf("failed to unmarshal obligation namespace: %w", err)
		}

		triggers, err := unmarshalObligationTriggers(row.Triggers)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal obligation triggers: %w", err)
		}

		name := row.Name
		value := row.Value
		nsFQN := namespace.GetFqn()
		obl := &policy.Obligation{
			Id:        row.ObligationID,
			Name:      name,
			Namespace: namespace,
			Fqn:       identifier.BuildOblFQN(nsFQN, name),
		}

		vals[i] = &policy.ObligationValue{
			Id:         row.ID,
			Value:      value,
			Metadata:   metadata,
			Obligation: obl,
			Triggers:   triggers,
			Fqn:        identifier.BuildOblValFQN(nsFQN, name, value),
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

	count, err := c.router.UpdateObligationValue(ctx, id, value, metadataJSON)
	now := timestamppb.Now()
	if err != nil {
		return nil, c.WrapError(err)
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
		_, err := c.router.DeleteAllObligationTriggersForValue(ctx, id)
		if err != nil {
			return nil, c.WrapError(err)
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
	namespace := obl.GetNamespace()
	nsFQN := namespace.GetFqn()
	obl.Fqn = identifier.BuildOblFQN(nsFQN, name)
	return &policy.ObligationValue{
		Id:         id,
		Value:      value,
		Metadata:   metadata,
		Obligation: obl,
		Triggers:   triggers,
		Fqn:        identifier.BuildOblValFQN(nsFQN, name, value),
	}, nil
}

func (c PolicyDBClient) DeleteObligationValue(ctx context.Context, r *obligations.DeleteObligationValueRequest) (*policy.ObligationValue, error) {
	nsFQN, oblName, valName := identifier.BreakOblValFQN(r.GetFqn())

	id, err := c.router.DeleteObligationValue(ctx, r.GetId(), nsFQN, oblName, valName)
	if err != nil {
		return nil, c.WrapError(err)
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

	params := UnifiedCreateObligationTriggerParams{
		ObligationValueID: oblVal.GetId(),
		ActionName:        r.GetAction().GetName(),
		ActionID:          r.GetAction().GetId(),
		AttributeValueID:  r.GetAttributeValue().GetId(),
		AttributeValueFqn: r.GetAttributeValue().GetFqn(),
		ClientID:          r.GetContext().GetPep().GetClientId(),
		Metadata:          metadataJSON,
	}
	row, err := c.router.CreateObligationTrigger(ctx, params)
	if err != nil {
		wrappedErr := c.WrapError(err)
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

	if returnedOblVal := trigger.GetObligationValue(); returnedOblVal != nil {
		returnedOblVal.Fqn = oblVal.GetFqn()
	}

	trigger.Metadata = metadata

	return trigger, nil
}

func (c PolicyDBClient) DeleteObligationTrigger(ctx context.Context, r *obligations.RemoveObligationTriggerRequest) (*policy.ObligationTrigger, error) {
	id, err := c.router.DeleteObligationTrigger(ctx, r.GetId())
	if err != nil {
		return nil, c.WrapError(err)
	}
	if id == "" {
		return nil, db.ErrNotFound
	}

	return &policy.ObligationTrigger{
		Id: id,
	}, nil
}

func (c PolicyDBClient) ListObligationTriggers(ctx context.Context, r *obligations.ListObligationTriggersRequest) ([]*policy.ObligationTrigger, *policy.PageResponse, error) {
	limit, offset := c.getRequestedLimitOffset(r.GetPagination())

	maxLimit := c.listCfg.limitMax
	if maxLimit > 0 && limit > maxLimit {
		return nil, nil, db.ErrListLimitTooLarge
	}

	rows, err := c.router.ListObligationTriggers(ctx, UnifiedListObligationTriggersParams{
		NamespaceID:  r.GetNamespaceId(),
		NamespaceFqn: r.GetNamespaceFqn(),
		Offset:       offset,
		Limit:        limit,
	})
	if err != nil {
		return nil, nil, c.WrapError(err)
	}

	var result []*policy.ObligationTrigger
	for _, row := range rows {
		metadata := &common.Metadata{}
		if err := unmarshalMetadata(row.Metadata, metadata); err != nil {
			return nil, nil, err
		}

		obligationTrigger, err := unmarshalObligationTrigger(row.Trigger)
		if err != nil {
			return nil, nil, err
		}

		if returnedOblVal := obligationTrigger.GetObligationValue(); returnedOblVal != nil {
			returnedOblVal.Fqn = identifier.BuildOblValFQN(returnedOblVal.GetObligation().GetNamespace().GetFqn(), returnedOblVal.GetObligation().GetName(), returnedOblVal.GetValue())
		}
		obligationTrigger.Metadata = metadata
		result = append(result, obligationTrigger)
	}

	var total int32
	var nextOffset int32
	if len(rows) > 0 {
		total = int32(rows[0].Total)
		nextOffset = getNextOffset(offset, limit, total)
	}

	pageResult := &policy.PageResponse{
		CurrentOffset: offset,
		Total:         total,
		NextOffset:    nextOffset,
	}

	return result, pageResult, nil
}
