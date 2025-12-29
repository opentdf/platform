package db

import (
	"context"

	"github.com/google/uuid"
	"github.com/opentdf/platform/service/policy/db/sqlite"
)

// UnifiedFqnRow is the unified result for FQN upsert operations.
type UnifiedFqnRow struct {
	NamespaceID string
	AttributeID string
	ValueID     string
	Fqn         string
}

// UpsertAttributeNamespaceFqn routes to the appropriate database backend.
// For PostgreSQL, this returns all FQNs (namespace, definitions, values) in one call.
// For SQLite, this emulates the same behavior by making multiple calls.
func (r *QueryRouter) UpsertAttributeNamespaceFqn(ctx context.Context, namespaceID string) ([]UnifiedFqnRow, error) {
	if r.IsSQLite() {
		return r.upsertAttributeNamespaceFqnSQLite(ctx, namespaceID)
	}
	return r.upsertAttributeNamespaceFqnPostgres(ctx, namespaceID)
}

func (r *QueryRouter) upsertAttributeNamespaceFqnPostgres(ctx context.Context, namespaceID string) ([]UnifiedFqnRow, error) {
	rows, err := r.postgres.upsertAttributeNamespaceFqn(ctx, namespaceID)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedFqnRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedFqnRow{
			NamespaceID: row.NamespaceID,
			AttributeID: row.AttributeID,
			ValueID:     row.ValueID,
			Fqn:         row.Fqn,
		}
	}

	return result, nil
}

func (r *QueryRouter) upsertAttributeNamespaceFqnSQLite(ctx context.Context, namespaceID string) ([]UnifiedFqnRow, error) {
	var result []UnifiedFqnRow

	// 1. Upsert the namespace FQN
	nsRow, err := r.sqlite.UpsertAttributeNamespaceFqn(ctx, sqlite.UpsertAttributeNamespaceFqnParams{
		ID:          uuid.NewString(),
		NamespaceID: namespaceID,
	})
	if err != nil {
		return nil, err
	}
	result = append(result, UnifiedFqnRow{
		NamespaceID: nsRow.NamespaceID,
		AttributeID: nsRow.AttributeID,
		ValueID:     nsRow.ValueID,
		Fqn:         nsRow.Fqn,
	})

	// 2. Get and upsert all definition FQNs for this namespace
	defFqns, err := r.sqlite.GetDefinitionFqnsByNamespace(ctx, namespaceID)
	if err != nil {
		return nil, err
	}
	for _, defFqn := range defFqns {
		defRow, err := r.sqlite.UpsertAttributeDefinitionFqn(ctx, sqlite.UpsertAttributeDefinitionFqnParams{
			ID:          uuid.NewString(),
			AttributeID: defFqn.AttributeID,
		})
		if err != nil {
			return nil, err
		}
		result = append(result, UnifiedFqnRow{
			NamespaceID: defRow.NamespaceID,
			AttributeID: defRow.AttributeID.String,
			ValueID:     defRow.ValueID,
			Fqn:         defRow.Fqn,
		})
	}

	// 3. Get and upsert all value FQNs for this namespace
	valFqns, err := r.sqlite.GetValueFqnsByNamespace(ctx, namespaceID)
	if err != nil {
		return nil, err
	}
	for _, valFqn := range valFqns {
		valRow, err := r.sqlite.UpsertAttributeValueFqn(ctx, sqlite.UpsertAttributeValueFqnParams{
			ID:      uuid.NewString(),
			ValueID: valFqn.ValueID,
		})
		if err != nil {
			return nil, err
		}
		result = append(result, UnifiedFqnRow{
			NamespaceID: valRow.NamespaceID,
			AttributeID: valRow.AttributeID.String,
			ValueID:     valRow.ValueID.String,
			Fqn:         valRow.Fqn,
		})
	}

	return result, nil
}
