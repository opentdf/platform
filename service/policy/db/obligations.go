package db

import (
	"context"
	"errors"
)

///
/// Obligation Definitions
///

func (c PolicyDBClient) CreateObligation(ctx context.Context, r any) (any, error) {
	return nil, errors.New("CreateObligation is not implemented in PolicyDBClient")
}

func (c PolicyDBClient) GetObligationDefinition(ctx context.Context) (any, error) {
	return nil, errors.New("GetObligationDefinition is not implemented in PolicyDBClient")
}

func (c PolicyDBClient) ListObligationDefinitions(ctx context.Context) (any, error) {
	return nil, errors.New("ListObligationDefinitions is not implemented in PolicyDBClient")
}

func (c PolicyDBClient) UpdateObligationDefinitions(ctx context.Context) (any, error) {
	return nil, errors.New("UpdateObligationDefinitions is not implemented in PolicyDBClient")
}

func (c PolicyDBClient) DeleteObligationDefinition(ctx context.Context, id string) (any, error) {
	return nil, errors.New("DeleteObligationDefinition is not implemented in PolicyDBClient")
}
