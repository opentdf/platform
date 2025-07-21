package db

import (
	"context"
	"errors"
)

///
/// Obligation Definitions
///

func (c PolicyDBClient) CreateObligationDefinition(_ context.Context, r any) (any, error) {
	return nil, errors.New("CreateObligationDefinition is not implemented in PolicyDBClient")
}

func (c PolicyDBClient) GetObligationDefinition(_ context.Context) (any, error) {
	return nil, errors.New("GetObligationDefinition is not implemented in PolicyDBClient")
}

func (c PolicyDBClient) ListObligationDefinitions(_ context.Context) (any, error) {
	return nil, errors.New("ListObligationDefinitions is not implemented in PolicyDBClient")
}

func (c PolicyDBClient) UpdateObligationDefinition(_ context.Context) (any, error) {
	return nil, errors.New("UpdateObligationDefinition is not implemented in PolicyDBClient")
}

func (c PolicyDBClient) DeleteObligationDefinition(_ context.Context, id string) (any, error) {
	return nil, errors.New("DeleteObligationDefinition is not implemented in PolicyDBClient")
}
