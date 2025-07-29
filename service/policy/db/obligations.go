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

func (c PolicyDBClient) CreateObligationByNamespaceID(ctx context.Context, namespaceID, name string, metadata []byte) (*policy.Obligation, error) {
	queryParams := createObligationByNamespaceIdParams{
		NamespaceID: namespaceID,
		Name:        name,
		Metadata:    metadata,
	}
	id, err := c.queries.createObligationByNamespaceId(ctx, queryParams)
	if err != nil {
		return nil, err
	}
	return &policy.Obligation{
		Id:   id,
		Name: name,
	}, nil
}

func (c PolicyDBClient) CreateObligationByNamespaceFQN(ctx context.Context, fqn, name string, metadata []byte) (*policy.Obligation, error) {
	queryParams := createObligationByNamespaceFQNParams{
		Fqn:      fqn,
		Name:     name,
		Metadata: metadata,
	}
	id, err := c.queries.createObligationByNamespaceFQN(ctx, queryParams)
	if err != nil {
		return nil, err
	}
	return &policy.Obligation{
		Id:   id,
		Name: name,
	}, nil
}

func (c PolicyDBClient) CreateObligation(ctx context.Context, r *obligations.CreateObligationRequest) (*policy.Obligation, error) {
	metadataJSON, _, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}
	if r.GetId() != "" {
		return c.CreateObligationByNamespaceID(ctx, r.GetId(), r.GetName(), metadataJSON)
	}
	return c.CreateObligationByNamespaceFQN(ctx, r.GetFqn(), r.GetName(), metadataJSON)
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
