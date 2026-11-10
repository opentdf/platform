package handlers

import (
	"context"

	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
)

// ParseToIDFqnIdentifier creates an IdFqnIdentifier based on whether the input is a UUID or FQN
func ParseToIDFqnIdentifier(value string) *common.IdFqnIdentifier {
	_, err := uuid.Parse(value)
	if err != nil {
		return &common.IdFqnIdentifier{Fqn: value}
	}
	return &common.IdFqnIdentifier{Id: value}
}

// ParseToIDNameIdentifier creates an IdNameIdentifier based on whether the input is a UUID or name
func ParseToIDNameIdentifier(value string) *common.IdNameIdentifier {
	_, err := uuid.Parse(value)
	if err != nil {
		return &common.IdNameIdentifier{Name: value}
	}
	return &common.IdNameIdentifier{Id: value}
}

//
// Obligations
//

func (h Handler) CreateObligation(ctx context.Context, namespace, name string, values []string, metadata *common.MetadataMutable) (*policy.Obligation, error) {
	req := &obligations.CreateObligationRequest{
		Name:     name,
		Values:   values,
		Metadata: metadata,
	}

	_, err := uuid.Parse(namespace)
	if err != nil {
		req.NamespaceFqn = namespace
	} else {
		req.NamespaceId = namespace
	}

	resp, err := h.sdk.Obligations.CreateObligation(ctx, req)
	if err != nil {
		return nil, err
	}

	return resp.GetObligation(), nil
}

func (h Handler) GetObligation(ctx context.Context, id, fqn string) (*policy.Obligation, error) {
	req := &obligations.GetObligationRequest{}
	if id != "" {
		req.Id = id
	} else {
		req.Fqn = fqn
	}

	resp, err := h.sdk.Obligations.GetObligation(ctx, req)
	if err != nil {
		return nil, err
	}

	return resp.GetObligation(), nil
}

func (h Handler) ListObligations(ctx context.Context, limit, offset int32, namespace string) (*obligations.ListObligationsResponse, error) {
	req := &obligations.ListObligationsRequest{
		Pagination: &policy.PageRequest{
			Limit:  limit,
			Offset: offset,
		},
	}
	if namespace != "" {
		_, err := uuid.Parse(namespace)
		if err != nil {
			req.NamespaceFqn = namespace
		} else {
			req.NamespaceId = namespace
		}
	}
	return h.sdk.Obligations.ListObligations(ctx, req)
}

func (h Handler) UpdateObligation(ctx context.Context, id, name string, metadata *common.MetadataMutable, behavior common.MetadataUpdateEnum) (*policy.Obligation, error) {
	res, err := h.sdk.Obligations.UpdateObligation(ctx, &obligations.UpdateObligationRequest{
		Id:                     id,
		Name:                   name,
		Metadata:               metadata,
		MetadataUpdateBehavior: behavior,
	})
	if err != nil {
		return nil, err
	}

	return res.GetObligation(), nil
}

func (h Handler) DeleteObligation(ctx context.Context, id, fqn string) error {
	req := &obligations.DeleteObligationRequest{}
	if id != "" {
		req.Id = id
	} else {
		req.Fqn = fqn
	}
	_, err := h.sdk.Obligations.DeleteObligation(ctx, req)
	if err != nil {
		return err
	}

	return nil
}

//
// Obligation Values
//

func (h Handler) CreateObligationValue(ctx context.Context, obligation, value string, triggers []*obligations.ValueTriggerRequest, metadata *common.MetadataMutable) (*policy.ObligationValue, error) {
	req := &obligations.CreateObligationValueRequest{
		Value:    value,
		Triggers: triggers,
		Metadata: metadata,
	}

	_, err := uuid.Parse(obligation)
	if err != nil {
		req.ObligationFqn = obligation
	} else {
		req.ObligationId = obligation
	}

	resp, err := h.sdk.Obligations.CreateObligationValue(ctx, req)
	if err != nil {
		return nil, err
	}

	return resp.GetValue(), nil
}

func (h Handler) GetObligationValue(ctx context.Context, id, fqn string) (*policy.ObligationValue, error) {
	req := &obligations.GetObligationValueRequest{}
	if id != "" {
		req.Id = id
	} else {
		req.Fqn = fqn
	}

	resp, err := h.sdk.Obligations.GetObligationValue(ctx, req)
	if err != nil {
		return nil, err
	}

	return resp.GetValue(), nil
}

func (h Handler) UpdateObligationValue(ctx context.Context, id, value string, triggers []*obligations.ValueTriggerRequest, metadata *common.MetadataMutable, behavior common.MetadataUpdateEnum) (*policy.ObligationValue, error) {
	res, err := h.sdk.Obligations.UpdateObligationValue(ctx, &obligations.UpdateObligationValueRequest{
		Id:                     id,
		Value:                  value,
		Triggers:               triggers,
		Metadata:               metadata,
		MetadataUpdateBehavior: behavior,
	})
	if err != nil {
		return nil, err
	}

	return res.GetValue(), nil
}

func (h Handler) DeleteObligationValue(ctx context.Context, id, fqn string) error {
	req := &obligations.DeleteObligationValueRequest{}
	if id != "" {
		req.Id = id
	} else {
		req.Fqn = fqn
	}
	_, err := h.sdk.Obligations.DeleteObligationValue(ctx, req)
	if err != nil {
		return err
	}

	return nil
}

// ******
// Obligation Triggers
// ******
func (h Handler) CreateObligationTrigger(ctx context.Context, attributeValue, action, obligationValue, clientID string, metadata *common.MetadataMutable) (*policy.ObligationTrigger, error) {
	req := &obligations.AddObligationTriggerRequest{
		Metadata: metadata,
	}

	req.AttributeValue = ParseToIDFqnIdentifier(attributeValue)
	req.Action = ParseToIDNameIdentifier(action)
	req.ObligationValue = ParseToIDFqnIdentifier(obligationValue)

	if clientID != "" {
		req.Context = &policy.RequestContext{
			Pep: &policy.PolicyEnforcementPoint{
				ClientId: clientID,
			},
		}
	}

	resp, err := h.sdk.Obligations.AddObligationTrigger(ctx, req)
	if err != nil {
		return nil, err
	}

	return resp.GetTrigger(), nil
}

func (h Handler) DeleteObligationTrigger(ctx context.Context, id string) (*policy.ObligationTrigger, error) {
	req := &obligations.RemoveObligationTriggerRequest{
		Id: id,
	}
	resp, err := h.sdk.Obligations.RemoveObligationTrigger(ctx, req)
	if err != nil {
		return nil, err
	}

	return resp.GetTrigger(), nil
}

func (h Handler) ListObligationTriggers(ctx context.Context, namespace string, limit, offset int32) (*obligations.ListObligationTriggersResponse, error) {
	req := &obligations.ListObligationTriggersRequest{
		Pagination: &policy.PageRequest{
			Limit:  limit,
			Offset: offset,
		},
	}

	if namespace != "" {
		_, err := uuid.Parse(namespace)
		if err != nil {
			req.NamespaceFqn = namespace
		} else {
			req.NamespaceId = namespace
		}
	}

	return h.sdk.Obligations.ListObligationTriggers(ctx, req)
}
