package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/opentdf/platform/service/pkg/db"
	"google.golang.org/protobuf/encoding/protojson"
)

func unmarshalObligationValuesProto(valuesJSON []byte, values []*policy.ObligationValue) error {
	if valuesJSON == nil {
		return nil
	}

	raw := []json.RawMessage{}
	if err := json.Unmarshal(valuesJSON, &raw); err != nil {
		return fmt.Errorf("failed to unmarshal values array [%s]: %w", string(valuesJSON), err)
	}

	for _, r := range raw {
		v := &policy.ObligationValue{}
		if err := protojson.Unmarshal(r, v); err != nil {
			return fmt.Errorf("failed to unmarshal value [%s]: %w", string(r), err)
		}
		values = append(values, v)
	}

	return nil
}

func unmarshalNamespace(namespaceJSON []byte, namespace *policy.Namespace) error {
	if namespaceJSON != nil {
		if err := protojson.Unmarshal(namespaceJSON, namespace); err != nil {
			return fmt.Errorf("failed to unmarshal namespaceJSON [%s]: %w", string(namespaceJSON), err)
		}
	}
	return nil
}

///
/// Obligation Definitions
///

// func (c PolicyDBClient) CreateObligationByNamespaceID(ctx context.Context, namespaceID, name string, values []string, metadataJSON []byte) (*policy.Obligation, error) {
// 	queryParams := createObligationByNamespaceIDParams{
// 		NamespaceID: namespaceID,
// 		Name:        name,
// 		Metadata:    metadataJSON,
// 		Values:      values,
// 	}
// 	row, err := c.queries.createObligationByNamespaceID(ctx, queryParams)
// 	if err != nil {
// 		return nil, err
// 	}
// 	oblVals := make([]*policy.ObligationValue, 0, len(values))
// 	if err := unmarshalObligationValuesProto(row.Values, oblVals); err != nil {
// 		return nil, fmt.Errorf("failed to unmarshal obligation values: %w", err)
// 	}

// 	return &policy.Obligation{
// 		Id:   row.ID,
// 		Name: name,
// 		Metadata: &common.Metadata{
// 			Labels: metadata.GetLabels(),
// 		},
// 		Namespace: &policy.Namespace{
// 			Id: namespaceID,
// 		},
// 		Values: oblVals,
// 	}, nil
// }

// func (c PolicyDBClient) CreateObligationByNamespaceFQN(ctx context.Context, fqn, name string, values []string, metadataJSON []byte) (createObligationByNamespaceFQNRow, error) {
// 	queryParams := createObligationByNamespaceFQNParams{
// 		Fqn:      fqn,
// 		Name:     name,
// 		Metadata: metadataJSON,
// 		Values:   values,
// 	}
// 	return c.queries.createObligationByNamespaceFQN(ctx, queryParams)
// 	// return &policy.Obligation{
// 	// 	Id:   row.ID,
// 	// 	Name: name,
// 	// 	Metadata: &common.Metadata{
// 	// 		Labels: metadata.GetLabels(),
// 	// 	},
// 	// 	Namespace: &policy.Namespace{
// 	// 		Fqn: fqn,
// 	// 	},
// 	// }, nil
// }

func (c PolicyDBClient) CreateObligation(ctx context.Context, r *obligations.CreateObligationRequest) (*policy.Obligation, error) {
	metadata := r.GetMetadata()
	metadataJSON, _, err := db.MarshalCreateMetadata(metadata)
	if err != nil {
		return nil, err
	}
	// if r.GetId() != "" {
	// 	queryParams := createObligationByNamespaceIDParams{
	// 		NamespaceID: namespaceID,
	// 		Name:        name,
	// 		Metadata:    metadataJSON,
	// 		Values:      values,
	// 	}
	// 	row, err := c.queries.createObligationByNamespaceID(ctx, queryParams)
	// } else {
	// 	queryParams := createObligationByNamespaceFQNParams{
	// 		Fqn:      fqn,
	// 		Name:     name,
	// 		Metadata: metadataJSON,
	// 		Values:   values,
	// 	}
	// 	row, err := c.queries.createObligationByNamespaceFQN(ctx, queryParams)
	// }
	name := r.GetName()
	values := r.GetValues()
	// namespaceID := r.GetId()
	// namespaceFQN := r.GetFqn()
	queryParams := createObligationParams{
		NamespaceID:  r.GetId(),
		NamespaceFqn: r.GetFqn(),
		Name:         name,
		Metadata:     metadataJSON,
		Values:       values,
	}
	row, err := c.queries.createObligation(ctx, queryParams)

	if err != nil {
		return nil, fmt.Errorf("failed to create obligation: %w", err)
	}
	oblVals := make([]*policy.ObligationValue, 0, len(values))
	if err := unmarshalObligationValuesProto(row.Values, oblVals); err != nil {
		return nil, fmt.Errorf("failed to unmarshal obligation values: %w", err)
	}

	var namespace policy.Namespace
	if err := unmarshalNamespace(row.Namespace, &namespace); err != nil {
		return nil, fmt.Errorf("failed to unmarshal obligation namespace: %w", err)
	}

	return &policy.Obligation{
		Id:   row.ID,
		Name: name,
		Metadata: &common.Metadata{
			Labels: metadata.GetLabels(),
		},
		Namespace: &namespace,
		Values:    oblVals,
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
