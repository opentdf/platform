package db

import (
	"context"
	"errors"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
)

///
/// Obligation Definitions
///

func (c PolicyDBClient) CreateObligationDefinition(ctx context.Context, r *obligations.CreateObligationRequest) (*policy.Obligation, error) {
	return &policy.Obligation{}, errors.New("CreateObligationDefinition is not implemented in PolicyDBClient")
}

func (c PolicyDBClient) GetObligationDefinition(ctx context.Context, r *obligations.GetObligationRequest) (*policy.Obligation, error) {
	return nil, errors.New("GetObligationDefinition is not implemented in PolicyDBClient")
}

func (c PolicyDBClient) ListObligationDefinitions(ctx context.Context, r *obligations.ListObligationsRequest) ([]*policy.Obligation, error) {
	return nil, errors.New("ListObligationDefinitions is not implemented in PolicyDBClient")
}

func (c PolicyDBClient) UpdateObligationDefinition(ctx context.Context, r *obligations.UpdateObligationRequest) (*policy.Obligation, error) {
	return nil, errors.New("UpdateObligationDefinition is not implemented in PolicyDBClient")
}

func (c PolicyDBClient) DeleteObligationDefinition(ctx context.Context, r *obligations.DeleteObligationRequest) (*policy.Obligation, error) {
	return nil, errors.New("DeleteObligationDefinition is not implemented in PolicyDBClient")
}
