package db

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/opentdf/platform/service/policy/db/sqlite"
)

// UnifiedCreateAttributeParams is the unified parameters for creating an attribute.
type UnifiedCreateAttributeParams struct {
	NamespaceID string
	Name        string
	Rule        string
	Metadata    []byte
}

// CreateAttribute routes to the appropriate database backend and returns the created ID.
func (r *QueryRouter) CreateAttribute(ctx context.Context, params UnifiedCreateAttributeParams) (string, error) {
	if r.IsSQLite() {
		return r.createAttributeSQLite(ctx, params)
	}
	return r.createAttributePostgres(ctx, params)
}

func (r *QueryRouter) createAttributePostgres(ctx context.Context, params UnifiedCreateAttributeParams) (string, error) {
	pgParams := createAttributeParams{
		NamespaceID: params.NamespaceID,
		Name:        params.Name,
		Rule:        AttributeDefinitionRule(params.Rule),
		Metadata:    params.Metadata,
	}
	return r.postgres.createAttribute(ctx, pgParams)
}

func (r *QueryRouter) createAttributeSQLite(ctx context.Context, params UnifiedCreateAttributeParams) (string, error) {
	id := uuid.NewString()
	sqliteParams := sqlite.CreateAttributeParams{
		ID:          id,
		NamespaceID: params.NamespaceID,
		Name:        params.Name,
		Rule:        params.Rule,
	}
	if params.Metadata != nil {
		sqliteParams.Metadata = sql.NullString{String: string(params.Metadata), Valid: true}
	}
	_, err := r.sqlite.CreateAttribute(ctx, sqliteParams)
	if err != nil {
		return "", err
	}
	return id, nil
}

// UpsertAttributeDefinitionFqn routes to the appropriate database backend.
// For PostgreSQL, this returns multiple rows (attribute + all values FQNs).
// For SQLite, this emulates the same behavior by making multiple calls.
func (r *QueryRouter) UpsertAttributeDefinitionFqn(ctx context.Context, attributeID string) ([]UnifiedFqnRow, error) {
	if r.IsSQLite() {
		return r.upsertAttributeDefinitionFqnSQLite(ctx, attributeID)
	}
	return r.upsertAttributeDefinitionFqnPostgres(ctx, attributeID)
}

func (r *QueryRouter) upsertAttributeDefinitionFqnPostgres(ctx context.Context, attributeID string) ([]UnifiedFqnRow, error) {
	rows, err := r.postgres.upsertAttributeDefinitionFqn(ctx, attributeID)
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

func (r *QueryRouter) upsertAttributeDefinitionFqnSQLite(ctx context.Context, attributeID string) ([]UnifiedFqnRow, error) {
	var result []UnifiedFqnRow

	// 1. Upsert the attribute definition FQN
	defRow, err := r.sqlite.UpsertAttributeDefinitionFqn(ctx, sqlite.UpsertAttributeDefinitionFqnParams{
		ID:          uuid.NewString(),
		AttributeID: attributeID,
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

	// 2. Get and upsert all value FQNs for this definition
	valFqns, err := r.sqlite.GetValueFqnsByDefinition(ctx, attributeID)
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

// UnifiedGetAttributeParams is the unified parameters for getting an attribute.
type UnifiedGetAttributeParams struct {
	ID  string // UUID as string (empty if not used)
	Fqn string // FQN (empty if not used)
}

// UnifiedGetAttributeRow is the unified result for getting an attribute.
type UnifiedGetAttributeRow struct {
	ID            string
	AttributeName string
	Rule          string
	Metadata      []byte
	NamespaceID   string
	Active        bool
	NamespaceName sql.NullString
	Values        []byte
	Grants        []byte
	Fqn           sql.NullString
	Keys          []byte
}

// GetAttribute routes to the appropriate database backend and normalizes the result.
func (r *QueryRouter) GetAttribute(ctx context.Context, params UnifiedGetAttributeParams) (UnifiedGetAttributeRow, error) {
	if r.IsSQLite() {
		return r.getAttributeSQLite(ctx, params)
	}
	return r.getAttributePostgres(ctx, params)
}

func (r *QueryRouter) getAttributePostgres(ctx context.Context, params UnifiedGetAttributeParams) (UnifiedGetAttributeRow, error) {
	pgParams := getAttributeParams{}
	if params.ID != "" {
		pgParams.ID = pgtypeUUID(params.ID)
	}
	if params.Fqn != "" {
		pgParams.Fqn = pgtypeText(params.Fqn)
	}

	row, err := r.postgres.getAttribute(ctx, pgParams)
	if err != nil {
		return UnifiedGetAttributeRow{}, err
	}

	return UnifiedGetAttributeRow{
		ID:            row.ID,
		AttributeName: row.AttributeName,
		Rule:          string(row.Rule),
		Metadata:      row.Metadata,
		NamespaceID:   row.NamespaceID,
		Active:        row.Active,
		NamespaceName: sql.NullString{String: row.NamespaceName.String, Valid: row.NamespaceName.Valid},
		Values:        row.Values,
		Grants:        row.Grants,
		Fqn:           sql.NullString{String: row.Fqn.String, Valid: row.Fqn.Valid},
		Keys:          row.Keys,
	}, nil
}

func (r *QueryRouter) getAttributeSQLite(ctx context.Context, params UnifiedGetAttributeParams) (UnifiedGetAttributeRow, error) {
	var idParam, fqnParam interface{}
	if params.ID != "" {
		idParam = params.ID
	}
	if params.Fqn != "" {
		fqnParam = params.Fqn
	}

	sqliteParams := sqlite.GetAttributeParams{
		ID:  idParam,
		Fqn: fqnParam,
	}

	row, err := r.sqlite.GetAttribute(ctx, sqliteParams)
	if err != nil {
		return UnifiedGetAttributeRow{}, err
	}

	return UnifiedGetAttributeRow{
		ID:            row.ID,
		AttributeName: row.AttributeName,
		Rule:          row.Rule,
		Metadata:      sqliteMetadataToBytes(row.Metadata),
		NamespaceID:   row.NamespaceID,
		Active:        row.Active != 0,
		NamespaceName: row.NamespaceName,
		Values:        sqliteMetadataToBytes(row.Values),
		Grants:        sqliteMetadataToBytes(row.Grants),
		Fqn:           row.Fqn,
		Keys:          sqliteMetadataToBytes(row.Keys),
	}, nil
}

// UnifiedListAttributesDetailParams is the unified parameters for listing attributes with detail.
type UnifiedListAttributesDetailParams struct {
	Active        *bool  // nil = any
	NamespaceID   string // empty = any
	NamespaceName string // empty = any
	Limit         int32
	Offset        int32
}

// UnifiedListAttributesDetailRow is the unified result row for listing attributes.
type UnifiedListAttributesDetailRow struct {
	ID            string
	AttributeName string
	Rule          string
	Metadata      []byte
	NamespaceID   string
	Active        bool
	NamespaceName sql.NullString
	Values        []byte
	Fqn           sql.NullString
	Total         int64
}

// ListAttributesDetail routes to the appropriate database backend and normalizes the result.
func (r *QueryRouter) ListAttributesDetail(ctx context.Context, params UnifiedListAttributesDetailParams) ([]UnifiedListAttributesDetailRow, error) {
	if r.IsSQLite() {
		return r.listAttributesDetailSQLite(ctx, params)
	}
	return r.listAttributesDetailPostgres(ctx, params)
}

func (r *QueryRouter) listAttributesDetailPostgres(ctx context.Context, params UnifiedListAttributesDetailParams) ([]UnifiedListAttributesDetailRow, error) {
	pgParams := listAttributesDetailParams{
		Active:        pgtype.Bool{Valid: false},
		NamespaceID:   params.NamespaceID,
		NamespaceName: params.NamespaceName,
		Limit:         params.Limit,
		Offset:        params.Offset,
	}
	if params.Active != nil {
		pgParams.Active = pgtype.Bool{Bool: *params.Active, Valid: true}
	}

	rows, err := r.postgres.listAttributesDetail(ctx, pgParams)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListAttributesDetailRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListAttributesDetailRow{
			ID:            row.ID,
			AttributeName: row.AttributeName,
			Rule:          string(row.Rule),
			Metadata:      row.Metadata,
			NamespaceID:   row.NamespaceID,
			Active:        row.Active,
			NamespaceName: sql.NullString{String: row.NamespaceName.String, Valid: row.NamespaceName.Valid},
			Values:        row.Values,
			Fqn:           sql.NullString{String: row.Fqn.String, Valid: row.Fqn.Valid},
			Total:         row.Total,
		}
	}

	return result, nil
}

func (r *QueryRouter) listAttributesDetailSQLite(ctx context.Context, params UnifiedListAttributesDetailParams) ([]UnifiedListAttributesDetailRow, error) {
	var activeFilter interface{}
	if params.Active != nil {
		if *params.Active {
			activeFilter = int64(1)
		} else {
			activeFilter = int64(0)
		}
	}

	sqliteParams := sqlite.ListAttributesDetailParams{
		Active:        activeFilter,
		NamespaceID:   params.NamespaceID,
		NamespaceName: params.NamespaceName,
		Limit:         int64(params.Limit),
		Offset:        int64(params.Offset),
	}

	rows, err := r.sqlite.ListAttributesDetail(ctx, sqliteParams)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListAttributesDetailRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListAttributesDetailRow{
			ID:            row.ID,
			AttributeName: row.AttributeName,
			Rule:          row.Rule,
			Metadata:      sqliteMetadataToBytes(row.Metadata),
			NamespaceID:   row.NamespaceID,
			Active:        row.Active != 0,
			NamespaceName: row.NamespaceName,
			Values:        sqliteMetadataToBytes(row.Values),
			Fqn:           row.Fqn,
			Total:         row.Total,
		}
	}

	return result, nil
}

// UnifiedListAttributesSummaryParams is the unified parameters for listing attributes summary.
type UnifiedListAttributesSummaryParams struct {
	NamespaceID string
	Limit       int32
	Offset      int32
}

// UnifiedListAttributesSummaryRow is the unified result row for listing attributes summary.
type UnifiedListAttributesSummaryRow struct {
	ID            string
	AttributeName string
	Rule          string
	Metadata      []byte
	NamespaceID   string
	Active        bool
	NamespaceName sql.NullString
	Total         int64
}

// ListAttributesSummary routes to the appropriate database backend and normalizes the result.
func (r *QueryRouter) ListAttributesSummary(ctx context.Context, params UnifiedListAttributesSummaryParams) ([]UnifiedListAttributesSummaryRow, error) {
	if r.IsSQLite() {
		return r.listAttributesSummarySQLite(ctx, params)
	}
	return r.listAttributesSummaryPostgres(ctx, params)
}

func (r *QueryRouter) listAttributesSummaryPostgres(ctx context.Context, params UnifiedListAttributesSummaryParams) ([]UnifiedListAttributesSummaryRow, error) {
	pgParams := listAttributesSummaryParams{
		NamespaceID: params.NamespaceID,
		Limit:       params.Limit,
		Offset:      params.Offset,
	}

	rows, err := r.postgres.listAttributesSummary(ctx, pgParams)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListAttributesSummaryRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListAttributesSummaryRow{
			ID:            row.ID,
			AttributeName: row.AttributeName,
			Rule:          string(row.Rule),
			Metadata:      row.Metadata,
			NamespaceID:   row.NamespaceID,
			Active:        row.Active,
			NamespaceName: sql.NullString{String: row.NamespaceName.String, Valid: row.NamespaceName.Valid},
			Total:         row.Total,
		}
	}

	return result, nil
}

func (r *QueryRouter) listAttributesSummarySQLite(ctx context.Context, params UnifiedListAttributesSummaryParams) ([]UnifiedListAttributesSummaryRow, error) {
	sqliteParams := sqlite.ListAttributesSummaryParams{
		NamespaceID: params.NamespaceID,
		Limit:       int64(params.Limit),
		Offset:      int64(params.Offset),
	}

	rows, err := r.sqlite.ListAttributesSummary(ctx, sqliteParams)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListAttributesSummaryRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListAttributesSummaryRow{
			ID:            row.ID,
			AttributeName: row.AttributeName,
			Rule:          row.Rule,
			Metadata:      sqliteMetadataToBytes(row.Metadata),
			NamespaceID:   row.NamespaceID,
			Active:        row.Active != 0,
			NamespaceName: row.NamespaceName,
			Total:         row.Total,
		}
	}

	return result, nil
}

// UnifiedListAttributesByFqnsRow is the unified result row for listing attributes by FQNs.
type UnifiedListAttributesByFqnsRow struct {
	ID        string
	Name      string
	Rule      string
	Active    bool
	Namespace []byte
	Fqn       string
	Values    []byte
	Grants    []byte
	Keys      []byte
}

// ListAttributesByDefOrValueFqns routes to the appropriate database backend and normalizes the result.
func (r *QueryRouter) ListAttributesByDefOrValueFqns(ctx context.Context, fqns []string) ([]UnifiedListAttributesByFqnsRow, error) {
	if r.IsSQLite() {
		return r.listAttributesByDefOrValueFqnsSQLite(ctx, fqns)
	}
	return r.listAttributesByDefOrValueFqnsPostgres(ctx, fqns)
}

func (r *QueryRouter) listAttributesByDefOrValueFqnsPostgres(ctx context.Context, fqns []string) ([]UnifiedListAttributesByFqnsRow, error) {
	rows, err := r.postgres.listAttributesByDefOrValueFqns(ctx, fqns)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListAttributesByFqnsRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListAttributesByFqnsRow{
			ID:        row.ID,
			Name:      row.Name,
			Rule:      string(row.Rule),
			Active:    row.Active,
			Namespace: row.Namespace,
			Fqn:       row.Fqn,
			Values:    row.Values,
			Grants:    row.Grants,
			Keys:      row.Keys,
		}
	}

	return result, nil
}

func (r *QueryRouter) listAttributesByDefOrValueFqnsSQLite(ctx context.Context, fqns []string) ([]UnifiedListAttributesByFqnsRow, error) {
	// Convert slice to JSON array for SQLite json_each
	fqnsJSON, err := json.Marshal(fqns)
	if err != nil {
		return nil, err
	}

	rows, err := r.sqlite.ListAttributesByDefOrValueFqns(ctx, string(fqnsJSON))
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListAttributesByFqnsRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListAttributesByFqnsRow{
			ID:        row.ID,
			Name:      row.Name,
			Rule:      row.Rule,
			Active:    row.Active != 0,
			Namespace: sqliteMetadataToBytes(row.Namespace),
			Fqn:       row.Fqn,
			Values:    sqliteMetadataToBytes(row.Values),
			Grants:    sqliteMetadataToBytes(row.Grants),
			Keys:      sqliteMetadataToBytes(row.Keys),
		}
	}

	return result, nil
}

// UnifiedUpdateAttributeParams is the unified parameters for updating an attribute.
type UnifiedUpdateAttributeParams struct {
	ID          string
	Name        *string  // nil = don't update
	Rule        *string  // nil = don't update
	ValuesOrder []string // nil = don't update
	Metadata    []byte   // nil = don't update
	Active      *bool    // nil = don't update
}

// UpdateAttribute routes to the appropriate database backend.
func (r *QueryRouter) UpdateAttribute(ctx context.Context, params UnifiedUpdateAttributeParams) (int64, error) {
	if r.IsSQLite() {
		return r.updateAttributeSQLite(ctx, params)
	}
	return r.updateAttributePostgres(ctx, params)
}

func (r *QueryRouter) updateAttributePostgres(ctx context.Context, params UnifiedUpdateAttributeParams) (int64, error) {
	pgParams := updateAttributeParams{
		ID: params.ID,
	}
	if params.Name != nil {
		pgParams.Name = pgtypeText(*params.Name)
	}
	if params.Rule != nil {
		pgParams.Rule = NullAttributeDefinitionRule{
			AttributeDefinitionRule: AttributeDefinitionRule(*params.Rule),
			Valid:                   true,
		}
	}
	if params.ValuesOrder != nil {
		pgParams.ValuesOrder = params.ValuesOrder
	}
	if params.Metadata != nil {
		pgParams.Metadata = params.Metadata
	}
	if params.Active != nil {
		pgParams.Active = pgtypeBool(*params.Active)
	}
	return r.postgres.updateAttribute(ctx, pgParams)
}

func (r *QueryRouter) updateAttributeSQLite(ctx context.Context, params UnifiedUpdateAttributeParams) (int64, error) {
	sqliteParams := sqlite.UpdateAttributeParams{
		ID: params.ID,
	}
	if params.Name != nil {
		sqliteParams.Name = sql.NullString{String: *params.Name, Valid: true}
	}
	if params.Rule != nil {
		sqliteParams.Rule = sql.NullString{String: *params.Rule, Valid: true}
	}
	if params.ValuesOrder != nil {
		// SQLite stores values_order as JSON array string
		orderJSON, err := json.Marshal(params.ValuesOrder)
		if err != nil {
			return 0, err
		}
		sqliteParams.ValuesOrder = sql.NullString{String: string(orderJSON), Valid: true}
	}
	if params.Metadata != nil {
		sqliteParams.Metadata = sql.NullString{String: string(params.Metadata), Valid: true}
	}
	if params.Active != nil {
		if *params.Active {
			sqliteParams.Active = sql.NullInt64{Int64: 1, Valid: true}
		} else {
			sqliteParams.Active = sql.NullInt64{Int64: 0, Valid: true}
		}
	}
	return r.sqlite.UpdateAttribute(ctx, sqliteParams)
}

// DeleteAttribute routes to the appropriate database backend.
func (r *QueryRouter) DeleteAttribute(ctx context.Context, id string) (int64, error) {
	if r.IsSQLite() {
		return r.sqlite.DeleteAttribute(ctx, id)
	}
	return r.postgres.deleteAttribute(ctx, id)
}

// UnifiedRemoveKeyAccessServerFromAttributeParams is the unified parameters.
type UnifiedRemoveKeyAccessServerFromAttributeParams struct {
	AttributeDefinitionID string
	KeyAccessServerID     string
}

// RemoveKeyAccessServerFromAttribute routes to the appropriate database backend.
func (r *QueryRouter) RemoveKeyAccessServerFromAttribute(ctx context.Context, params UnifiedRemoveKeyAccessServerFromAttributeParams) (int64, error) {
	if r.IsSQLite() {
		return r.sqlite.RemoveKeyAccessServerFromAttribute(ctx, sqlite.RemoveKeyAccessServerFromAttributeParams{
			AttributeDefinitionID: params.AttributeDefinitionID,
			KeyAccessServerID:     params.KeyAccessServerID,
		})
	}
	return r.postgres.removeKeyAccessServerFromAttribute(ctx, removeKeyAccessServerFromAttributeParams{
		AttributeDefinitionID: params.AttributeDefinitionID,
		KeyAccessServerID:     params.KeyAccessServerID,
	})
}

// UnifiedAssignPublicKeyToAttributeDefinitionParams is the unified parameters.
type UnifiedAssignPublicKeyToAttributeDefinitionParams struct {
	DefinitionID         string
	KeyAccessServerKeyID string
}

// UnifiedAssignPublicKeyToAttributeDefinitionRow is the unified result.
type UnifiedAssignPublicKeyToAttributeDefinitionRow struct {
	DefinitionID         string
	KeyAccessServerKeyID string
}

// AssignPublicKeyToAttributeDefinition routes to the appropriate database backend.
func (r *QueryRouter) AssignPublicKeyToAttributeDefinition(ctx context.Context, params UnifiedAssignPublicKeyToAttributeDefinitionParams) (UnifiedAssignPublicKeyToAttributeDefinitionRow, error) {
	if r.IsSQLite() {
		row, err := r.sqlite.AssignPublicKeyToAttributeDefinition(ctx, sqlite.AssignPublicKeyToAttributeDefinitionParams{
			DefinitionID:         params.DefinitionID,
			KeyAccessServerKeyID: params.KeyAccessServerKeyID,
		})
		if err != nil {
			return UnifiedAssignPublicKeyToAttributeDefinitionRow{}, err
		}
		return UnifiedAssignPublicKeyToAttributeDefinitionRow{
			DefinitionID:         row.DefinitionID,
			KeyAccessServerKeyID: row.KeyAccessServerKeyID,
		}, nil
	}
	row, err := r.postgres.assignPublicKeyToAttributeDefinition(ctx, assignPublicKeyToAttributeDefinitionParams{
		DefinitionID:         params.DefinitionID,
		KeyAccessServerKeyID: params.KeyAccessServerKeyID,
	})
	if err != nil {
		return UnifiedAssignPublicKeyToAttributeDefinitionRow{}, err
	}
	return UnifiedAssignPublicKeyToAttributeDefinitionRow{
		DefinitionID:         row.DefinitionID,
		KeyAccessServerKeyID: row.KeyAccessServerKeyID,
	}, nil
}

// UnifiedRemovePublicKeyFromAttributeDefinitionParams is the unified parameters.
type UnifiedRemovePublicKeyFromAttributeDefinitionParams struct {
	DefinitionID         string
	KeyAccessServerKeyID string
}

// RemovePublicKeyFromAttributeDefinition routes to the appropriate database backend.
func (r *QueryRouter) RemovePublicKeyFromAttributeDefinition(ctx context.Context, params UnifiedRemovePublicKeyFromAttributeDefinitionParams) (int64, error) {
	if r.IsSQLite() {
		return r.sqlite.RemovePublicKeyFromAttributeDefinition(ctx, sqlite.RemovePublicKeyFromAttributeDefinitionParams{
			DefinitionID:         params.DefinitionID,
			KeyAccessServerKeyID: params.KeyAccessServerKeyID,
		})
	}
	return r.postgres.removePublicKeyFromAttributeDefinition(ctx, removePublicKeyFromAttributeDefinitionParams{
		DefinitionID:         params.DefinitionID,
		KeyAccessServerKeyID: params.KeyAccessServerKeyID,
	})
}
