package db

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/opentdf/platform/service/policy/db/sqlite"
)

// UnifiedCreateProviderConfigParams is the unified parameters for creating a provider config.
type UnifiedCreateProviderConfigParams struct {
	ProviderName string
	Manager      string
	Config       []byte
	Metadata     []byte
}

// UnifiedProviderConfigRow is the unified result for provider config operations.
type UnifiedProviderConfigRow struct {
	ID           string
	ProviderName string
	Manager      string
	Config       []byte
	Metadata     []byte
}

// CreateProviderConfig routes to the appropriate database backend and returns the created config.
func (r *QueryRouter) CreateProviderConfig(ctx context.Context, params UnifiedCreateProviderConfigParams) (UnifiedProviderConfigRow, error) {
	if r.IsSQLite() {
		return r.createProviderConfigSQLite(ctx, params)
	}
	return r.createProviderConfigPostgres(ctx, params)
}

func (r *QueryRouter) createProviderConfigPostgres(ctx context.Context, params UnifiedCreateProviderConfigParams) (UnifiedProviderConfigRow, error) {
	pgParams := createProviderConfigParams{
		ProviderName: params.ProviderName,
		Manager:      params.Manager,
		Config:       params.Config,
		Metadata:     params.Metadata,
	}

	row, err := r.postgres.createProviderConfig(ctx, pgParams)
	if err != nil {
		return UnifiedProviderConfigRow{}, err
	}

	return UnifiedProviderConfigRow{
		ID:           row.ID,
		ProviderName: row.ProviderName,
		Manager:      row.Manager,
		Config:       row.Config,
		Metadata:     row.Metadata,
	}, nil
}

func (r *QueryRouter) createProviderConfigSQLite(ctx context.Context, params UnifiedCreateProviderConfigParams) (UnifiedProviderConfigRow, error) {
	id := uuid.NewString()
	sqliteParams := sqlite.CreateProviderConfigParams{
		ID:           id,
		ProviderName: params.ProviderName,
		Manager:      params.Manager,
		Config:       string(params.Config),
	}
	if params.Metadata != nil {
		sqliteParams.Metadata = sql.NullString{String: string(params.Metadata), Valid: true}
	}

	_, err := r.sqlite.CreateProviderConfig(ctx, sqliteParams)
	if err != nil {
		return UnifiedProviderConfigRow{}, err
	}

	// Fetch the created row to return full data with metadata
	return r.GetProviderConfig(ctx, UnifiedGetProviderConfigParams{ID: id})
}

// UnifiedGetProviderConfigParams is the unified parameters for getting a provider config.
type UnifiedGetProviderConfigParams struct {
	ID      string // UUID as string (empty if not used)
	Name    string // Provider name (empty if not used)
	Manager string // Manager (empty if not used)
}

// GetProviderConfig routes to the appropriate database backend and normalizes the result.
func (r *QueryRouter) GetProviderConfig(ctx context.Context, params UnifiedGetProviderConfigParams) (UnifiedProviderConfigRow, error) {
	if r.IsSQLite() {
		return r.getProviderConfigSQLite(ctx, params)
	}
	return r.getProviderConfigPostgres(ctx, params)
}

func (r *QueryRouter) getProviderConfigPostgres(ctx context.Context, params UnifiedGetProviderConfigParams) (UnifiedProviderConfigRow, error) {
	pgParams := getProviderConfigParams{}
	if params.ID != "" {
		pgParams.ID = pgtypeUUID(params.ID)
	}
	if params.Name != "" {
		pgParams.Name = pgtypeText(params.Name)
	}
	if params.Manager != "" {
		pgParams.Manager = pgtypeText(params.Manager)
	}

	row, err := r.postgres.getProviderConfig(ctx, pgParams)
	if err != nil {
		return UnifiedProviderConfigRow{}, err
	}

	return UnifiedProviderConfigRow{
		ID:           row.ID,
		ProviderName: row.ProviderName,
		Manager:      row.Manager,
		Config:       row.Config,
		Metadata:     row.Metadata,
	}, nil
}

func (r *QueryRouter) getProviderConfigSQLite(ctx context.Context, params UnifiedGetProviderConfigParams) (UnifiedProviderConfigRow, error) {
	var idParam, nameParam, managerParam interface{}
	if params.ID != "" {
		idParam = params.ID
	}
	if params.Name != "" {
		nameParam = params.Name
	}
	if params.Manager != "" {
		managerParam = params.Manager
	}

	sqliteParams := sqlite.GetProviderConfigFullParams{
		ID:      idParam,
		Name:    nameParam,
		Manager: managerParam,
	}

	row, err := r.sqlite.GetProviderConfigFull(ctx, sqliteParams)
	if err != nil {
		return UnifiedProviderConfigRow{}, err
	}

	return UnifiedProviderConfigRow{
		ID:           row.ID,
		ProviderName: row.ProviderName,
		Manager:      row.Manager,
		Config:       []byte(row.Config),
		Metadata:     sqliteMetadataToBytes(row.Metadata),
	}, nil
}

// UnifiedListProviderConfigsParams is the unified parameters for listing provider configs.
type UnifiedListProviderConfigsParams struct {
	Limit  int32
	Offset int32
}

// UnifiedListProviderConfigsRow is the unified result row for listing provider configs.
type UnifiedListProviderConfigsRow struct {
	ID           string
	ProviderName string
	Manager      string
	Config       []byte
	Metadata     []byte
	Total        int64
}

// ListProviderConfigs routes to the appropriate database backend and normalizes the result.
func (r *QueryRouter) ListProviderConfigs(ctx context.Context, params UnifiedListProviderConfigsParams) ([]UnifiedListProviderConfigsRow, error) {
	if r.IsSQLite() {
		return r.listProviderConfigsSQLite(ctx, params)
	}
	return r.listProviderConfigsPostgres(ctx, params)
}

func (r *QueryRouter) listProviderConfigsPostgres(ctx context.Context, params UnifiedListProviderConfigsParams) ([]UnifiedListProviderConfigsRow, error) {
	pgParams := listProviderConfigsParams{
		Limit:  params.Limit,
		Offset: params.Offset,
	}

	rows, err := r.postgres.listProviderConfigs(ctx, pgParams)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListProviderConfigsRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListProviderConfigsRow{
			ID:           row.ID,
			ProviderName: row.ProviderName,
			Manager:      row.Manager,
			Config:       row.Config,
			Metadata:     row.Metadata,
			Total:        row.Total,
		}
	}

	return result, nil
}

func (r *QueryRouter) listProviderConfigsSQLite(ctx context.Context, params UnifiedListProviderConfigsParams) ([]UnifiedListProviderConfigsRow, error) {
	sqliteParams := sqlite.ListProviderConfigsParams{
		Limit:  int64(params.Limit),
		Offset: int64(params.Offset),
	}

	rows, err := r.sqlite.ListProviderConfigs(ctx, sqliteParams)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListProviderConfigsRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListProviderConfigsRow{
			ID:           row.ID,
			ProviderName: row.ProviderName,
			Manager:      row.Manager,
			Config:       []byte(row.Config),
			Metadata:     sqliteMetadataToBytes(row.Metadata),
			Total:        row.Total,
		}
	}

	return result, nil
}

// UnifiedUpdateProviderConfigParams is the unified parameters for updating a provider config.
type UnifiedUpdateProviderConfigParams struct {
	ID           string
	ProviderName *string // nil means no change
	Manager      *string // nil means no change
	Config       []byte  // nil means no change
	Metadata     []byte  // nil means no change
}

// UpdateProviderConfig routes to the appropriate database backend.
func (r *QueryRouter) UpdateProviderConfig(ctx context.Context, params UnifiedUpdateProviderConfigParams) (int64, error) {
	if r.IsSQLite() {
		return r.updateProviderConfigSQLite(ctx, params)
	}
	return r.updateProviderConfigPostgres(ctx, params)
}

func (r *QueryRouter) updateProviderConfigPostgres(ctx context.Context, params UnifiedUpdateProviderConfigParams) (int64, error) {
	pgParams := updateProviderConfigParams{
		ID: params.ID,
	}
	if params.ProviderName != nil {
		pgParams.ProviderName = pgtype.Text{String: *params.ProviderName, Valid: true}
	}
	if params.Manager != nil {
		pgParams.Manager = pgtype.Text{String: *params.Manager, Valid: true}
	}
	if params.Config != nil {
		pgParams.Config = params.Config
	}
	if params.Metadata != nil {
		pgParams.Metadata = params.Metadata
	}
	return r.postgres.updateProviderConfig(ctx, pgParams)
}

func (r *QueryRouter) updateProviderConfigSQLite(ctx context.Context, params UnifiedUpdateProviderConfigParams) (int64, error) {
	sqliteParams := sqlite.UpdateProviderConfigParams{
		ID: params.ID,
	}
	if params.ProviderName != nil {
		sqliteParams.ProviderName = sql.NullString{String: *params.ProviderName, Valid: true}
	}
	if params.Manager != nil {
		sqliteParams.Manager = sql.NullString{String: *params.Manager, Valid: true}
	}
	if params.Config != nil {
		sqliteParams.Config = sql.NullString{String: string(params.Config), Valid: true}
	}
	if params.Metadata != nil {
		sqliteParams.Metadata = sql.NullString{String: string(params.Metadata), Valid: true}
	}
	return r.sqlite.UpdateProviderConfig(ctx, sqliteParams)
}

// DeleteProviderConfig routes to the appropriate database backend.
func (r *QueryRouter) DeleteProviderConfig(ctx context.Context, id string) (int64, error) {
	if r.IsSQLite() {
		return r.sqlite.DeleteProviderConfig(ctx, id)
	}
	return r.postgres.deleteProviderConfig(ctx, id)
}
