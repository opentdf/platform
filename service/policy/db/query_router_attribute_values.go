package db

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/opentdf/platform/service/policy/db/sqlite"
)

// UnifiedCreateAttributeValueParams is the unified parameters for creating an attribute value.
type UnifiedCreateAttributeValueParams struct {
	AttributeDefinitionID string
	Value                 string
	Metadata              []byte
}

// CreateAttributeValue routes to the appropriate database backend and returns the created ID.
func (r *QueryRouter) CreateAttributeValue(ctx context.Context, params UnifiedCreateAttributeValueParams) (string, error) {
	if r.IsSQLite() {
		return r.createAttributeValueSQLite(ctx, params)
	}
	return r.createAttributeValuePostgres(ctx, params)
}

func (r *QueryRouter) createAttributeValuePostgres(ctx context.Context, params UnifiedCreateAttributeValueParams) (string, error) {
	pgParams := createAttributeValueParams{
		AttributeDefinitionID: params.AttributeDefinitionID,
		Value:                 params.Value,
		Metadata:              params.Metadata,
	}
	return r.postgres.createAttributeValue(ctx, pgParams)
}

func (r *QueryRouter) createAttributeValueSQLite(ctx context.Context, params UnifiedCreateAttributeValueParams) (string, error) {
	id := uuid.NewString()
	sqliteParams := sqlite.CreateAttributeValueParams{
		ID:                    id,
		AttributeDefinitionID: params.AttributeDefinitionID,
		Value:                 params.Value,
	}
	if params.Metadata != nil {
		sqliteParams.Metadata = sql.NullString{String: string(params.Metadata), Valid: true}
	}
	_, err := r.sqlite.CreateAttributeValue(ctx, sqliteParams)
	if err != nil {
		return "", err
	}
	return id, nil
}

// UpsertAttributeValueFqn routes to the appropriate database backend.
// Returns only error since callers discard the result.
func (r *QueryRouter) UpsertAttributeValueFqn(ctx context.Context, valueID string) error {
	if r.IsSQLite() {
		return r.upsertAttributeValueFqnSQLite(ctx, valueID)
	}
	return r.upsertAttributeValueFqnPostgres(ctx, valueID)
}

func (r *QueryRouter) upsertAttributeValueFqnPostgres(ctx context.Context, valueID string) error {
	_, err := r.postgres.upsertAttributeValueFqn(ctx, valueID)
	return err
}

func (r *QueryRouter) upsertAttributeValueFqnSQLite(ctx context.Context, valueID string) error {
	_, err := r.sqlite.UpsertAttributeValueFqn(ctx, sqlite.UpsertAttributeValueFqnParams{
		ID:      uuid.NewString(),
		ValueID: valueID,
	})
	return err
}

// UnifiedGetAttributeValueParams is the unified parameters for getting an attribute value.
type UnifiedGetAttributeValueParams struct {
	ID  string // UUID as string (empty if not used)
	Fqn string // FQN (empty if not used)
}

// UnifiedGetAttributeValueRow is the unified result for getting an attribute value.
type UnifiedGetAttributeValueRow struct {
	ID                    string
	Value                 string
	Active                bool
	Metadata              []byte
	AttributeDefinitionID string
	Fqn                   string
	Grants                []byte
	Keys                  []byte
	Obligations           []byte
}

// GetAttributeValue routes to the appropriate database backend and normalizes the result.
func (r *QueryRouter) GetAttributeValue(ctx context.Context, params UnifiedGetAttributeValueParams) (UnifiedGetAttributeValueRow, error) {
	if r.IsSQLite() {
		return r.getAttributeValueSQLite(ctx, params)
	}
	return r.getAttributeValuePostgres(ctx, params)
}

func (r *QueryRouter) getAttributeValuePostgres(ctx context.Context, params UnifiedGetAttributeValueParams) (UnifiedGetAttributeValueRow, error) {
	pgParams := getAttributeValueParams{}
	if params.ID != "" {
		pgParams.ID = pgtypeUUID(params.ID)
	}
	if params.Fqn != "" {
		pgParams.Fqn = pgtypeText(params.Fqn)
	}

	row, err := r.postgres.getAttributeValue(ctx, pgParams)
	if err != nil {
		return UnifiedGetAttributeValueRow{}, err
	}

	return UnifiedGetAttributeValueRow{
		ID:                    row.ID,
		Value:                 row.Value,
		Active:                row.Active,
		Metadata:              row.Metadata,
		AttributeDefinitionID: row.AttributeDefinitionID,
		Fqn:                   row.Fqn.String,
		Grants:                row.Grants,
		Keys:                  row.Keys,
		Obligations:           row.Obligations,
	}, nil
}

func (r *QueryRouter) getAttributeValueSQLite(ctx context.Context, params UnifiedGetAttributeValueParams) (UnifiedGetAttributeValueRow, error) {
	var idParam, fqnParam interface{}
	if params.ID != "" {
		idParam = params.ID
	}
	if params.Fqn != "" {
		fqnParam = params.Fqn
	}

	sqliteParams := sqlite.GetAttributeValueParams{
		ID:  idParam,
		Fqn: fqnParam,
	}

	row, err := r.sqlite.GetAttributeValue(ctx, sqliteParams)
	if err != nil {
		return UnifiedGetAttributeValueRow{}, err
	}

	return UnifiedGetAttributeValueRow{
		ID:                    row.ID,
		Value:                 row.Value,
		Active:                row.Active != 0,
		Metadata:              sqliteMetadataToBytes(row.Metadata),
		AttributeDefinitionID: row.AttributeDefinitionID,
		Fqn:                   row.Fqn.String,
		Grants:                sqliteMetadataToBytes(row.Grants),
		Keys:                  sqliteMetadataToBytes(row.Keys),
		Obligations:           sqliteMetadataToBytes(row.Obligations),
	}, nil
}

// UnifiedListAttributeValuesParams is the unified parameters for listing attribute values.
type UnifiedListAttributeValuesParams struct {
	AttributeDefinitionID string
	Active                *bool // nil = any, true/false = filter by active state
	Limit                 int32
	Offset                int32
}

// UnifiedListAttributeValuesRow is the unified result row for listing attribute values.
type UnifiedListAttributeValuesRow struct {
	Total                 int64
	ID                    string
	Value                 string
	Active                bool
	Metadata              []byte
	AttributeDefinitionID string
	Fqn                   string
}

// ListAttributeValues routes to the appropriate database backend and normalizes the result.
func (r *QueryRouter) ListAttributeValues(ctx context.Context, params UnifiedListAttributeValuesParams) ([]UnifiedListAttributeValuesRow, error) {
	if r.IsSQLite() {
		return r.listAttributeValuesSQLite(ctx, params)
	}
	return r.listAttributeValuesPostgres(ctx, params)
}

func (r *QueryRouter) listAttributeValuesPostgres(ctx context.Context, params UnifiedListAttributeValuesParams) ([]UnifiedListAttributeValuesRow, error) {
	pgParams := listAttributeValuesParams{
		AttributeDefinitionID: params.AttributeDefinitionID,
		Active:                pgtypeBoolFromPtr(params.Active),
		Limit:                 params.Limit,
		Offset:                params.Offset,
	}

	rows, err := r.postgres.listAttributeValues(ctx, pgParams)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListAttributeValuesRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListAttributeValuesRow{
			Total:                 row.Total,
			ID:                    row.ID,
			Value:                 row.Value,
			Active:                row.Active,
			Metadata:              row.Metadata,
			AttributeDefinitionID: row.AttributeDefinitionID,
			Fqn:                   row.Fqn.String,
		}
	}

	return result, nil
}

func (r *QueryRouter) listAttributeValuesSQLite(ctx context.Context, params UnifiedListAttributeValuesParams) ([]UnifiedListAttributeValuesRow, error) {
	var activeFilter interface{}
	if params.Active != nil {
		// SQLite uses 0/1 for booleans
		if *params.Active {
			activeFilter = int64(1)
		} else {
			activeFilter = int64(0)
		}
	}

	sqliteParams := sqlite.ListAttributeValuesParams{
		AttributeDefinitionID: params.AttributeDefinitionID,
		Active:                activeFilter,
		Limit:                 int64(params.Limit),
		Offset:                int64(params.Offset),
	}

	rows, err := r.sqlite.ListAttributeValues(ctx, sqliteParams)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListAttributeValuesRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListAttributeValuesRow{
			Total:                 row.Total,
			ID:                    row.ID,
			Value:                 row.Value,
			Active:                row.Active != 0,
			Metadata:              sqliteMetadataToBytes(row.Metadata),
			AttributeDefinitionID: row.AttributeDefinitionID,
			Fqn:                   row.Fqn.String,
		}
	}

	return result, nil
}

// UpdateAttributeValue routes to the appropriate database backend.
// Returns the number of rows affected.
func (r *QueryRouter) UpdateAttributeValue(ctx context.Context, id string, value *string, active *bool, metadata []byte) (int64, error) {
	if r.IsSQLite() {
		return r.updateAttributeValueSQLite(ctx, id, value, active, metadata)
	}
	return r.updateAttributeValuePostgres(ctx, id, value, active, metadata)
}

func (r *QueryRouter) updateAttributeValuePostgres(ctx context.Context, id string, value *string, active *bool, metadata []byte) (int64, error) {
	params := updateAttributeValueParams{
		ID: id,
	}
	if value != nil {
		params.Value = pgtypeText(*value)
	}
	if active != nil {
		params.Active = pgtypeBool(*active)
	}
	if metadata != nil {
		params.Metadata = metadata
	}
	return r.postgres.updateAttributeValue(ctx, params)
}

func (r *QueryRouter) updateAttributeValueSQLite(ctx context.Context, id string, value *string, active *bool, metadata []byte) (int64, error) {
	params := sqlite.UpdateAttributeValueParams{
		ID: id,
	}
	if value != nil {
		params.Value = sql.NullString{String: *value, Valid: true}
	}
	if active != nil {
		if *active {
			params.Active = sql.NullInt64{Int64: 1, Valid: true}
		} else {
			params.Active = sql.NullInt64{Int64: 0, Valid: true}
		}
	}
	if metadata != nil {
		params.Metadata = sql.NullString{String: string(metadata), Valid: true}
	}
	return r.sqlite.UpdateAttributeValue(ctx, params)
}

// DeleteAttributeValue routes to the appropriate database backend.
// Returns the number of rows affected.
func (r *QueryRouter) DeleteAttributeValue(ctx context.Context, id string) (int64, error) {
	if r.IsSQLite() {
		return r.sqlite.DeleteAttributeValue(ctx, id)
	}
	return r.postgres.deleteAttributeValue(ctx, id)
}

// UnifiedValueKeyResult is the unified result for assigning a public key to an attribute value.
type UnifiedValueKeyResult struct {
	ValueID string
	KeyID   string
}

// AssignPublicKeyToAttributeValue routes to the appropriate database backend.
func (r *QueryRouter) AssignPublicKeyToAttributeValue(ctx context.Context, valueID, keyID string) (UnifiedValueKeyResult, error) {
	if r.IsSQLite() {
		return r.assignPublicKeyToAttributeValueSQLite(ctx, valueID, keyID)
	}
	return r.assignPublicKeyToAttributeValuePostgres(ctx, valueID, keyID)
}

func (r *QueryRouter) assignPublicKeyToAttributeValuePostgres(ctx context.Context, valueID, keyID string) (UnifiedValueKeyResult, error) {
	result, err := r.postgres.assignPublicKeyToAttributeValue(ctx, assignPublicKeyToAttributeValueParams{
		ValueID:              valueID,
		KeyAccessServerKeyID: keyID,
	})
	if err != nil {
		return UnifiedValueKeyResult{}, err
	}
	return UnifiedValueKeyResult{
		ValueID: result.ValueID,
		KeyID:   result.KeyAccessServerKeyID,
	}, nil
}

func (r *QueryRouter) assignPublicKeyToAttributeValueSQLite(ctx context.Context, valueID, keyID string) (UnifiedValueKeyResult, error) {
	result, err := r.sqlite.AssignPublicKeyToAttributeValue(ctx, sqlite.AssignPublicKeyToAttributeValueParams{
		ValueID:              valueID,
		KeyAccessServerKeyID: keyID,
	})
	if err != nil {
		return UnifiedValueKeyResult{}, err
	}
	return UnifiedValueKeyResult{
		ValueID: result.ValueID,
		KeyID:   result.KeyAccessServerKeyID,
	}, nil
}

// RemovePublicKeyFromAttributeValue routes to the appropriate database backend.
// Returns the number of rows affected.
func (r *QueryRouter) RemovePublicKeyFromAttributeValue(ctx context.Context, valueID, keyID string) (int64, error) {
	if r.IsSQLite() {
		return r.sqlite.RemovePublicKeyFromAttributeValue(ctx, sqlite.RemovePublicKeyFromAttributeValueParams{
			ValueID:              valueID,
			KeyAccessServerKeyID: keyID,
		})
	}
	return r.postgres.removePublicKeyFromAttributeValue(ctx, removePublicKeyFromAttributeValueParams{
		ValueID:              valueID,
		KeyAccessServerKeyID: keyID,
	})
}

// RemoveKeyAccessServerFromAttributeValue routes to the appropriate database backend.
// Returns the number of rows affected.
func (r *QueryRouter) RemoveKeyAccessServerFromAttributeValue(ctx context.Context, valueID, kasID string) (int64, error) {
	if r.IsSQLite() {
		return r.sqlite.RemoveKeyAccessServerFromAttributeValue(ctx, sqlite.RemoveKeyAccessServerFromAttributeValueParams{
			AttributeValueID:  valueID,
			KeyAccessServerID: kasID,
		})
	}
	return r.postgres.removeKeyAccessServerFromAttributeValue(ctx, removeKeyAccessServerFromAttributeValueParams{
		AttributeValueID:  valueID,
		KeyAccessServerID: kasID,
	})
}
