package db

import (
	"errors"

	"github.com/opentdf/platform/protocol/go/policy"
)

///
/// Obligation Definitions
///

func (c PolicyDBClient) CreateObligationDefinition() (*policy.Obligation, error) {
	return &policy.Obligation{}, errors.New("CreateObligationDefinition is not implemented in PolicyDBClient")
}

func (c PolicyDBClient) GetObligationDefinition() (*policy.Obligation, error) {
	return nil, errors.New("GetObligationDefinition is not implemented in PolicyDBClient")
}

func (c PolicyDBClient) ListObligationDefinitions() ([]*policy.Obligation, error) {
	return nil, errors.New("ListObligationDefinitions is not implemented in PolicyDBClient")
}

func (c PolicyDBClient) UpdateObligationDefinition() (*policy.Obligation, error) {
	return nil, errors.New("UpdateObligationDefinition is not implemented in PolicyDBClient")
}

func (c PolicyDBClient) DeleteObligationDefinition() (*policy.Obligation, error) {
	return nil, errors.New("DeleteObligationDefinition is not implemented in PolicyDBClient")
}
