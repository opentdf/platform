package db

import (
	"context"
	"errors"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/opentdf/platform/service/pkg/db"
)

///
/// Obligation Definitions
///

func (c PolicyDBClient) CreateObligation(ctx context.Context, r *obligations.CreateObligationRequest) (*policy.Obligation, error) {
	if r.GetFqn() != "" {
		return nil, errors.New("namespace identifier by FQN is not supported yet")
	}
	metadataJSON, _, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}
	queryParams := createObligationDefinitionParams{
		NamespaceID: r.GetId(),
		Name:        r.GetName(),
		Metadata:    metadataJSON,
	}
	id, err := c.queries.createObligationDefinition(ctx, queryParams)
	if err != nil {
		return nil, err
	}
	return &policy.Obligation{
		Id:   id,
		Name: r.GetName(),
	}, nil
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
