package db

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/opentdf/platform/service/policy/db/sqlite"
)

// UnifiedGetRegisteredResourceParams is the unified parameters for getting a registered resource.
type UnifiedGetRegisteredResourceParams struct {
	ID   string
	Name string
}

// UnifiedGetRegisteredResourceRow is the unified result for getting a registered resource.
type UnifiedGetRegisteredResourceRow struct {
	ID       string
	Name     string
	Metadata []byte
	Values   []byte
}

// GetRegisteredResource routes to the appropriate database backend and normalizes the result.
func (r *QueryRouter) GetRegisteredResource(ctx context.Context, params UnifiedGetRegisteredResourceParams) (UnifiedGetRegisteredResourceRow, error) {
	if r.IsSQLite() {
		return r.getRegisteredResourceSQLite(ctx, params)
	}
	return r.getRegisteredResourcePostgres(ctx, params)
}

func (r *QueryRouter) getRegisteredResourcePostgres(ctx context.Context, params UnifiedGetRegisteredResourceParams) (UnifiedGetRegisteredResourceRow, error) {
	pgParams := getRegisteredResourceParams{
		ID:   params.ID,
		Name: params.Name,
	}

	row, err := r.postgres.getRegisteredResource(ctx, pgParams)
	if err != nil {
		return UnifiedGetRegisteredResourceRow{}, err
	}

	return UnifiedGetRegisteredResourceRow{
		ID:       row.ID,
		Name:     row.Name,
		Metadata: row.Metadata,
		Values:   row.Values,
	}, nil
}

func (r *QueryRouter) getRegisteredResourceSQLite(ctx context.Context, params UnifiedGetRegisteredResourceParams) (UnifiedGetRegisteredResourceRow, error) {
	sqliteParams := sqlite.GetRegisteredResourceParams{
		ID:   params.ID,
		Name: params.Name,
	}

	row, err := r.sqlite.GetRegisteredResource(ctx, sqliteParams)
	if err != nil {
		return UnifiedGetRegisteredResourceRow{}, err
	}

	return UnifiedGetRegisteredResourceRow{
		ID:       row.ID,
		Name:     row.Name,
		Metadata: sqliteMetadataToBytes(row.Metadata),
		Values:   sqliteMetadataToBytes(row.Values),
	}, nil
}

// UnifiedListRegisteredResourcesParams is the unified parameters for listing registered resources.
type UnifiedListRegisteredResourcesParams struct {
	Limit  int32
	Offset int32
}

// UnifiedListRegisteredResourcesRow is the unified result row for listing registered resources.
type UnifiedListRegisteredResourcesRow struct {
	ID       string
	Name     string
	Metadata []byte
	Values   []byte
	Total    int64
}

// ListRegisteredResources routes to the appropriate database backend and normalizes the result.
func (r *QueryRouter) ListRegisteredResources(ctx context.Context, params UnifiedListRegisteredResourcesParams) ([]UnifiedListRegisteredResourcesRow, error) {
	if r.IsSQLite() {
		return r.listRegisteredResourcesSQLite(ctx, params)
	}
	return r.listRegisteredResourcesPostgres(ctx, params)
}

func (r *QueryRouter) listRegisteredResourcesPostgres(ctx context.Context, params UnifiedListRegisteredResourcesParams) ([]UnifiedListRegisteredResourcesRow, error) {
	pgParams := listRegisteredResourcesParams{
		Limit:  params.Limit,
		Offset: params.Offset,
	}

	rows, err := r.postgres.listRegisteredResources(ctx, pgParams)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListRegisteredResourcesRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListRegisteredResourcesRow{
			ID:       row.ID,
			Name:     row.Name,
			Metadata: row.Metadata,
			Values:   row.Values,
			Total:    row.Total,
		}
	}

	return result, nil
}

func (r *QueryRouter) listRegisteredResourcesSQLite(ctx context.Context, params UnifiedListRegisteredResourcesParams) ([]UnifiedListRegisteredResourcesRow, error) {
	sqliteParams := sqlite.ListRegisteredResourcesParams{
		Limit:  int64(params.Limit),
		Offset: int64(params.Offset),
	}

	rows, err := r.sqlite.ListRegisteredResources(ctx, sqliteParams)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListRegisteredResourcesRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListRegisteredResourcesRow{
			ID:       row.ID,
			Name:     row.Name,
			Metadata: sqliteMetadataToBytes(row.Metadata),
			Values:   sqliteMetadataToBytes(row.Values),
			Total:    row.Total,
		}
	}

	return result, nil
}

// UnifiedCreateRegisteredResourceParams is the unified parameters for creating a registered resource.
type UnifiedCreateRegisteredResourceParams struct {
	Name     string
	Metadata []byte
}

// CreateRegisteredResource routes to the appropriate database backend and returns the created ID.
func (r *QueryRouter) CreateRegisteredResource(ctx context.Context, params UnifiedCreateRegisteredResourceParams) (string, error) {
	if r.IsSQLite() {
		return r.createRegisteredResourceSQLite(ctx, params)
	}
	return r.createRegisteredResourcePostgres(ctx, params)
}

func (r *QueryRouter) createRegisteredResourcePostgres(ctx context.Context, params UnifiedCreateRegisteredResourceParams) (string, error) {
	pgParams := createRegisteredResourceParams{
		Name:     params.Name,
		Metadata: params.Metadata,
	}
	return r.postgres.createRegisteredResource(ctx, pgParams)
}

func (r *QueryRouter) createRegisteredResourceSQLite(ctx context.Context, params UnifiedCreateRegisteredResourceParams) (string, error) {
	id := uuid.NewString()
	sqliteParams := sqlite.CreateRegisteredResourceParams{
		ID:   id,
		Name: params.Name,
	}
	if params.Metadata != nil {
		sqliteParams.Metadata = sql.NullString{String: string(params.Metadata), Valid: true}
	}
	_, err := r.sqlite.CreateRegisteredResource(ctx, sqliteParams)
	if err != nil {
		return "", err
	}
	return id, nil
}

// UpdateRegisteredResource routes to the appropriate database backend.
func (r *QueryRouter) UpdateRegisteredResource(ctx context.Context, id string, name *string, metadata []byte) (int64, error) {
	if r.IsSQLite() {
		return r.updateRegisteredResourceSQLite(ctx, id, name, metadata)
	}
	return r.updateRegisteredResourcePostgres(ctx, id, name, metadata)
}

func (r *QueryRouter) updateRegisteredResourcePostgres(ctx context.Context, id string, name *string, metadata []byte) (int64, error) {
	params := updateRegisteredResourceParams{
		ID: id,
	}
	if name != nil {
		params.Name = pgtypeText(*name)
	}
	if metadata != nil {
		params.Metadata = metadata
	}
	return r.postgres.updateRegisteredResource(ctx, params)
}

func (r *QueryRouter) updateRegisteredResourceSQLite(ctx context.Context, id string, name *string, metadata []byte) (int64, error) {
	params := sqlite.UpdateRegisteredResourceParams{
		ID: id,
	}
	if name != nil {
		params.Name = sql.NullString{String: *name, Valid: true}
	}
	if metadata != nil {
		params.Metadata = sql.NullString{String: string(metadata), Valid: true}
	}
	return r.sqlite.UpdateRegisteredResource(ctx, params)
}

// DeleteRegisteredResource routes to the appropriate database backend.
func (r *QueryRouter) DeleteRegisteredResource(ctx context.Context, id string) (int64, error) {
	if r.IsSQLite() {
		return r.sqlite.DeleteRegisteredResource(ctx, id)
	}
	return r.postgres.deleteRegisteredResource(ctx, id)
}

// UnifiedGetRegisteredResourceValueParams is the unified parameters for getting a registered resource value.
type UnifiedGetRegisteredResourceValueParams struct {
	ID    string
	Name  string
	Value string
}

// UnifiedGetRegisteredResourceValueRow is the unified result for getting a registered resource value.
type UnifiedGetRegisteredResourceValueRow struct {
	ID                    string
	RegisteredResourceID  string
	Value                 string
	Metadata              []byte
	ActionAttributeValues []byte
}

// GetRegisteredResourceValue routes to the appropriate database backend and normalizes the result.
func (r *QueryRouter) GetRegisteredResourceValue(ctx context.Context, params UnifiedGetRegisteredResourceValueParams) (UnifiedGetRegisteredResourceValueRow, error) {
	if r.IsSQLite() {
		return r.getRegisteredResourceValueSQLite(ctx, params)
	}
	return r.getRegisteredResourceValuePostgres(ctx, params)
}

func (r *QueryRouter) getRegisteredResourceValuePostgres(ctx context.Context, params UnifiedGetRegisteredResourceValueParams) (UnifiedGetRegisteredResourceValueRow, error) {
	pgParams := getRegisteredResourceValueParams{
		ID:    params.ID,
		Name:  params.Name,
		Value: params.Value,
	}

	row, err := r.postgres.getRegisteredResourceValue(ctx, pgParams)
	if err != nil {
		return UnifiedGetRegisteredResourceValueRow{}, err
	}

	return UnifiedGetRegisteredResourceValueRow{
		ID:                    row.ID,
		RegisteredResourceID:  row.RegisteredResourceID,
		Value:                 row.Value,
		Metadata:              row.Metadata,
		ActionAttributeValues: row.ActionAttributeValues,
	}, nil
}

func (r *QueryRouter) getRegisteredResourceValueSQLite(ctx context.Context, params UnifiedGetRegisteredResourceValueParams) (UnifiedGetRegisteredResourceValueRow, error) {
	sqliteParams := sqlite.GetRegisteredResourceValueParams{
		ID:    params.ID,
		Name:  params.Name,
		Value: params.Value,
	}

	row, err := r.sqlite.GetRegisteredResourceValue(ctx, sqliteParams)
	if err != nil {
		return UnifiedGetRegisteredResourceValueRow{}, err
	}

	return UnifiedGetRegisteredResourceValueRow{
		ID:                    row.ID,
		RegisteredResourceID:  row.RegisteredResourceID,
		Value:                 row.Value,
		Metadata:              sqliteMetadataToBytes(row.Metadata),
		ActionAttributeValues: sqliteMetadataToBytes(row.ActionAttributeValues),
	}, nil
}

// UnifiedListRegisteredResourceValuesParams is the unified parameters for listing registered resource values.
type UnifiedListRegisteredResourceValuesParams struct {
	RegisteredResourceID string
	Limit                int32
	Offset               int32
}

// UnifiedListRegisteredResourceValuesRow is the unified result row for listing registered resource values.
type UnifiedListRegisteredResourceValuesRow struct {
	ID                    string
	RegisteredResourceID  string
	Value                 string
	Metadata              []byte
	ActionAttributeValues []byte
	Total                 int64
}

// ListRegisteredResourceValues routes to the appropriate database backend and normalizes the result.
func (r *QueryRouter) ListRegisteredResourceValues(ctx context.Context, params UnifiedListRegisteredResourceValuesParams) ([]UnifiedListRegisteredResourceValuesRow, error) {
	if r.IsSQLite() {
		return r.listRegisteredResourceValuesSQLite(ctx, params)
	}
	return r.listRegisteredResourceValuesPostgres(ctx, params)
}

func (r *QueryRouter) listRegisteredResourceValuesPostgres(ctx context.Context, params UnifiedListRegisteredResourceValuesParams) ([]UnifiedListRegisteredResourceValuesRow, error) {
	pgParams := listRegisteredResourceValuesParams{
		RegisteredResourceID: params.RegisteredResourceID,
		Limit:                params.Limit,
		Offset:               params.Offset,
	}

	rows, err := r.postgres.listRegisteredResourceValues(ctx, pgParams)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListRegisteredResourceValuesRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListRegisteredResourceValuesRow{
			ID:                    row.ID,
			RegisteredResourceID:  row.RegisteredResourceID,
			Value:                 row.Value,
			Metadata:              row.Metadata,
			ActionAttributeValues: row.ActionAttributeValues,
			Total:                 row.Total,
		}
	}

	return result, nil
}

func (r *QueryRouter) listRegisteredResourceValuesSQLite(ctx context.Context, params UnifiedListRegisteredResourceValuesParams) ([]UnifiedListRegisteredResourceValuesRow, error) {
	var resourceID interface{}
	if params.RegisteredResourceID != "" {
		resourceID = params.RegisteredResourceID
	}

	sqliteParams := sqlite.ListRegisteredResourceValuesParams{
		RegisteredResourceID: resourceID,
		Limit:                int64(params.Limit),
		Offset:               int64(params.Offset),
	}

	rows, err := r.sqlite.ListRegisteredResourceValues(ctx, sqliteParams)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListRegisteredResourceValuesRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListRegisteredResourceValuesRow{
			ID:                    row.ID,
			RegisteredResourceID:  row.RegisteredResourceID,
			Value:                 row.Value,
			Metadata:              sqliteMetadataToBytes(row.Metadata),
			ActionAttributeValues: sqliteMetadataToBytes(row.ActionAttributeValues),
			Total:                 row.Total,
		}
	}

	return result, nil
}

// UnifiedCreateRegisteredResourceValueParams is the unified parameters for creating a registered resource value.
type UnifiedCreateRegisteredResourceValueParams struct {
	RegisteredResourceID string
	Value                string
	Metadata             []byte
}

// CreateRegisteredResourceValue routes to the appropriate database backend and returns the created ID.
func (r *QueryRouter) CreateRegisteredResourceValue(ctx context.Context, params UnifiedCreateRegisteredResourceValueParams) (string, error) {
	if r.IsSQLite() {
		return r.createRegisteredResourceValueSQLite(ctx, params)
	}
	return r.createRegisteredResourceValuePostgres(ctx, params)
}

func (r *QueryRouter) createRegisteredResourceValuePostgres(ctx context.Context, params UnifiedCreateRegisteredResourceValueParams) (string, error) {
	pgParams := createRegisteredResourceValueParams{
		RegisteredResourceID: params.RegisteredResourceID,
		Value:                params.Value,
		Metadata:             params.Metadata,
	}
	return r.postgres.createRegisteredResourceValue(ctx, pgParams)
}

func (r *QueryRouter) createRegisteredResourceValueSQLite(ctx context.Context, params UnifiedCreateRegisteredResourceValueParams) (string, error) {
	id := uuid.NewString()
	sqliteParams := sqlite.CreateRegisteredResourceValueParams{
		ID:                   id,
		RegisteredResourceID: params.RegisteredResourceID,
		Value:                params.Value,
	}
	if params.Metadata != nil {
		sqliteParams.Metadata = sql.NullString{String: string(params.Metadata), Valid: true}
	}
	_, err := r.sqlite.CreateRegisteredResourceValue(ctx, sqliteParams)
	if err != nil {
		return "", err
	}
	return id, nil
}

// UpdateRegisteredResourceValue routes to the appropriate database backend.
func (r *QueryRouter) UpdateRegisteredResourceValue(ctx context.Context, id string, value *string, metadata []byte) (int64, error) {
	if r.IsSQLite() {
		return r.updateRegisteredResourceValueSQLite(ctx, id, value, metadata)
	}
	return r.updateRegisteredResourceValuePostgres(ctx, id, value, metadata)
}

func (r *QueryRouter) updateRegisteredResourceValuePostgres(ctx context.Context, id string, value *string, metadata []byte) (int64, error) {
	params := updateRegisteredResourceValueParams{
		ID: id,
	}
	if value != nil {
		params.Value = pgtypeText(*value)
	}
	if metadata != nil {
		params.Metadata = metadata
	}
	return r.postgres.updateRegisteredResourceValue(ctx, params)
}

func (r *QueryRouter) updateRegisteredResourceValueSQLite(ctx context.Context, id string, value *string, metadata []byte) (int64, error) {
	params := sqlite.UpdateRegisteredResourceValueParams{
		ID: id,
	}
	if value != nil {
		params.Value = sql.NullString{String: *value, Valid: true}
	}
	if metadata != nil {
		params.Metadata = sql.NullString{String: string(metadata), Valid: true}
	}
	return r.sqlite.UpdateRegisteredResourceValue(ctx, params)
}

// DeleteRegisteredResourceValue routes to the appropriate database backend.
func (r *QueryRouter) DeleteRegisteredResourceValue(ctx context.Context, id string) (int64, error) {
	if r.IsSQLite() {
		return r.sqlite.DeleteRegisteredResourceValue(ctx, id)
	}
	return r.postgres.deleteRegisteredResourceValue(ctx, id)
}

// DeleteRegisteredResourceActionAttributeValues routes to the appropriate database backend.
func (r *QueryRouter) DeleteRegisteredResourceActionAttributeValues(ctx context.Context, registeredResourceValueID string) (int64, error) {
	if r.IsSQLite() {
		return r.sqlite.DeleteRegisteredResourceActionAttributeValues(ctx, registeredResourceValueID)
	}
	return r.postgres.deleteRegisteredResourceActionAttributeValues(ctx, registeredResourceValueID)
}

// GetAttributeValueForRegisteredResource routes to the appropriate database backend for registered resource lookups.
// This is a simplified lookup specifically for registered resource action attribute value creation.
// Uses the unified types from query_router_attribute_values.go.
func (r *QueryRouter) GetAttributeValueForRegisteredResource(ctx context.Context, params UnifiedGetAttributeValueParams) (UnifiedGetAttributeValueRow, error) {
	// Delegate to the main GetAttributeValue router
	return r.GetAttributeValue(ctx, params)
}

// CreateRegisteredResourceActionAttributeValue creates action-attribute-value associations for a registered resource value.
// For PostgreSQL, this uses the batch insert. For SQLite, this inserts one at a time.
func (r *QueryRouter) CreateRegisteredResourceActionAttributeValue(ctx context.Context, registeredResourceValueID, actionID, attributeValueID string) (string, error) {
	if r.IsSQLite() {
		id := uuid.NewString()
		params := sqlite.CreateRegisteredResourceActionAttributeValueParams{
			ID:                        id,
			RegisteredResourceValueID: registeredResourceValueID,
			ActionID:                  actionID,
			AttributeValueID:          attributeValueID,
		}
		_, err := r.sqlite.CreateRegisteredResourceActionAttributeValue(ctx, params)
		if err != nil {
			return "", err
		}
		return id, nil
	}
	// For PostgreSQL, the batch insert is used, but this provides a single-insert interface
	// The caller should use BulkInsertRegisteredResourceActionAttributeValues for batch operations
	params := []createRegisteredResourceActionAttributeValuesParams{{
		RegisteredResourceValueID: registeredResourceValueID,
		ActionID:                  actionID,
		AttributeValueID:          attributeValueID,
	}}
	count, err := r.postgres.createRegisteredResourceActionAttributeValues(ctx, params)
	if err != nil {
		return "", err
	}
	if count == 0 {
		return "", nil
	}
	// PostgreSQL doesn't return the ID for batch inserts, return empty string
	return "", nil
}
