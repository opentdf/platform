package db

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/opentdf/platform/service/policy/db/sqlite"
)

// UnifiedGetActionParams is the unified parameters for getting an action.
type UnifiedGetActionParams struct {
	ID   string // UUID as string (empty if not used)
	Name string // Action name (empty if not used)
}

// UnifiedGetActionRow is the unified result for getting an action.
type UnifiedGetActionRow struct {
	ID       string
	Name     string
	Metadata []byte
}

// GetAction routes to the appropriate database backend and normalizes the result.
func (r *QueryRouter) GetAction(ctx context.Context, params UnifiedGetActionParams) (UnifiedGetActionRow, error) {
	if r.IsSQLite() {
		return r.getActionSQLite(ctx, params)
	}
	return r.getActionPostgres(ctx, params)
}

func (r *QueryRouter) getActionPostgres(ctx context.Context, params UnifiedGetActionParams) (UnifiedGetActionRow, error) {
	pgParams := getActionParams{}
	if params.ID != "" {
		pgParams.ID = pgtypeUUID(params.ID)
	}
	if params.Name != "" {
		pgParams.Name = pgtypeText(params.Name)
	}

	row, err := r.postgres.getAction(ctx, pgParams)
	if err != nil {
		return UnifiedGetActionRow{}, err
	}

	return UnifiedGetActionRow{
		ID:       row.ID,
		Name:     row.Name,
		Metadata: row.Metadata,
	}, nil
}

func (r *QueryRouter) getActionSQLite(ctx context.Context, params UnifiedGetActionParams) (UnifiedGetActionRow, error) {
	var idParam, nameParam interface{}
	if params.ID != "" {
		idParam = params.ID
	}
	if params.Name != "" {
		nameParam = params.Name
	}

	sqliteParams := sqlite.GetActionParams{
		ID:   idParam,
		Name: nameParam,
	}

	row, err := r.sqlite.GetAction(ctx, sqliteParams)
	if err != nil {
		return UnifiedGetActionRow{}, err
	}

	return UnifiedGetActionRow{
		ID:       row.ID,
		Name:     row.Name,
		Metadata: sqliteMetadataToBytes(row.Metadata),
	}, nil
}

// UnifiedListActionsParams is the unified parameters for listing actions.
type UnifiedListActionsParams struct {
	Limit  int32
	Offset int32
}

// UnifiedListActionsRow is the unified result row for listing actions.
type UnifiedListActionsRow struct {
	ID         string
	Name       string
	Metadata   []byte
	IsStandard bool
	Total      int64
}

// ListActions routes to the appropriate database backend and normalizes the result.
func (r *QueryRouter) ListActions(ctx context.Context, params UnifiedListActionsParams) ([]UnifiedListActionsRow, error) {
	if r.IsSQLite() {
		return r.listActionsSQLite(ctx, params)
	}
	return r.listActionsPostgres(ctx, params)
}

func (r *QueryRouter) listActionsPostgres(ctx context.Context, params UnifiedListActionsParams) ([]UnifiedListActionsRow, error) {
	pgParams := listActionsParams{
		Limit:  params.Limit,
		Offset: params.Offset,
	}

	rows, err := r.postgres.listActions(ctx, pgParams)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListActionsRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListActionsRow{
			ID:         row.ID,
			Name:       row.Name,
			Metadata:   row.Metadata,
			IsStandard: row.IsStandard,
			Total:      row.Total,
		}
	}

	return result, nil
}

func (r *QueryRouter) listActionsSQLite(ctx context.Context, params UnifiedListActionsParams) ([]UnifiedListActionsRow, error) {
	sqliteParams := sqlite.ListActionsParams{
		Limit:  int64(params.Limit),
		Offset: int64(params.Offset),
	}

	rows, err := r.sqlite.ListActions(ctx, sqliteParams)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListActionsRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListActionsRow{
			ID:         row.ID,
			Name:       row.Name,
			Metadata:   sqliteMetadataToBytes(row.Metadata),
			IsStandard: row.IsStandard != 0,
			Total:      row.Total,
		}
	}

	return result, nil
}

// UnifiedCreateCustomActionParams is the unified parameters for creating a custom action.
type UnifiedCreateCustomActionParams struct {
	Name     string
	Metadata []byte
}

// CreateCustomAction routes to the appropriate database backend and returns the created ID.
func (r *QueryRouter) CreateCustomAction(ctx context.Context, params UnifiedCreateCustomActionParams) (string, error) {
	if r.IsSQLite() {
		return r.createCustomActionSQLite(ctx, params)
	}
	return r.createCustomActionPostgres(ctx, params)
}

func (r *QueryRouter) createCustomActionPostgres(ctx context.Context, params UnifiedCreateCustomActionParams) (string, error) {
	pgParams := createCustomActionParams{
		Name:     params.Name,
		Metadata: params.Metadata,
	}
	return r.postgres.createCustomAction(ctx, pgParams)
}

func (r *QueryRouter) createCustomActionSQLite(ctx context.Context, params UnifiedCreateCustomActionParams) (string, error) {
	id := uuid.NewString()
	sqliteParams := sqlite.CreateCustomActionParams{
		ID:   id,
		Name: params.Name,
	}
	if params.Metadata != nil {
		sqliteParams.Metadata = sql.NullString{String: string(params.Metadata), Valid: true}
	}
	_, err := r.sqlite.CreateCustomAction(ctx, sqliteParams)
	if err != nil {
		return "", err
	}
	return id, nil
}

// UnifiedUpdateCustomActionParams is the unified parameters for updating a custom action.
type UnifiedUpdateCustomActionParams struct {
	ID       string
	Name     *string // nil means don't update
	Metadata []byte  // nil means don't update
}

// UpdateCustomAction routes to the appropriate database backend.
func (r *QueryRouter) UpdateCustomAction(ctx context.Context, params UnifiedUpdateCustomActionParams) (int64, error) {
	if r.IsSQLite() {
		return r.updateCustomActionSQLite(ctx, params)
	}
	return r.updateCustomActionPostgres(ctx, params)
}

func (r *QueryRouter) updateCustomActionPostgres(ctx context.Context, params UnifiedUpdateCustomActionParams) (int64, error) {
	pgParams := updateCustomActionParams{
		ID: params.ID,
	}
	if params.Name != nil {
		pgParams.Name = pgtypeText(*params.Name)
	}
	if params.Metadata != nil {
		pgParams.Metadata = params.Metadata
	}
	return r.postgres.updateCustomAction(ctx, pgParams)
}

func (r *QueryRouter) updateCustomActionSQLite(ctx context.Context, params UnifiedUpdateCustomActionParams) (int64, error) {
	sqliteParams := sqlite.UpdateCustomActionParams{
		ID: params.ID,
	}
	if params.Name != nil {
		sqliteParams.Name = sql.NullString{String: *params.Name, Valid: true}
	}
	if params.Metadata != nil {
		sqliteParams.Metadata = sql.NullString{String: string(params.Metadata), Valid: true}
	}
	return r.sqlite.UpdateCustomAction(ctx, sqliteParams)
}

// DeleteCustomAction routes to the appropriate database backend.
func (r *QueryRouter) DeleteCustomAction(ctx context.Context, id string) (int64, error) {
	if r.IsSQLite() {
		return r.sqlite.DeleteCustomAction(ctx, id)
	}
	return r.postgres.deleteCustomAction(ctx, id)
}
