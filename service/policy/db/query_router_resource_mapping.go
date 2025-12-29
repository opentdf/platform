package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"

	"github.com/google/uuid"
	"github.com/opentdf/platform/service/policy/db/sqlite"
)

// UnifiedGetResourceMappingGroupRow is the unified result for getting a resource mapping group.
type UnifiedGetResourceMappingGroupRow struct {
	ID          string
	NamespaceID string
	Name        string
	Metadata    []byte
}

// GetResourceMappingGroup routes to the appropriate database backend and normalizes the result.
func (r *QueryRouter) GetResourceMappingGroup(ctx context.Context, id string) (UnifiedGetResourceMappingGroupRow, error) {
	if r.IsSQLite() {
		return r.getResourceMappingGroupSQLite(ctx, id)
	}
	return r.getResourceMappingGroupPostgres(ctx, id)
}

func (r *QueryRouter) getResourceMappingGroupPostgres(ctx context.Context, id string) (UnifiedGetResourceMappingGroupRow, error) {
	row, err := r.postgres.getResourceMappingGroup(ctx, id)
	if err != nil {
		return UnifiedGetResourceMappingGroupRow{}, err
	}

	return UnifiedGetResourceMappingGroupRow{
		ID:          row.ID,
		NamespaceID: row.NamespaceID,
		Name:        row.Name,
		Metadata:    row.Metadata,
	}, nil
}

func (r *QueryRouter) getResourceMappingGroupSQLite(ctx context.Context, id string) (UnifiedGetResourceMappingGroupRow, error) {
	row, err := r.sqlite.GetResourceMappingGroup(ctx, id)
	if err != nil {
		return UnifiedGetResourceMappingGroupRow{}, err
	}

	return UnifiedGetResourceMappingGroupRow{
		ID:          row.ID,
		NamespaceID: row.NamespaceID,
		Name:        row.Name,
		Metadata:    sqliteMetadataToBytes(row.Metadata),
	}, nil
}

// UnifiedListResourceMappingGroupsParams is the unified parameters for listing resource mapping groups.
type UnifiedListResourceMappingGroupsParams struct {
	NamespaceID string
	Limit       int32
	Offset      int32
}

// UnifiedListResourceMappingGroupsRow is the unified result row for listing resource mapping groups.
type UnifiedListResourceMappingGroupsRow struct {
	ID          string
	NamespaceID string
	Name        string
	Metadata    []byte
	Total       int64
}

// ListResourceMappingGroups routes to the appropriate database backend and normalizes the result.
func (r *QueryRouter) ListResourceMappingGroups(ctx context.Context, params UnifiedListResourceMappingGroupsParams) ([]UnifiedListResourceMappingGroupsRow, error) {
	if r.IsSQLite() {
		return r.listResourceMappingGroupsSQLite(ctx, params)
	}
	return r.listResourceMappingGroupsPostgres(ctx, params)
}

func (r *QueryRouter) listResourceMappingGroupsPostgres(ctx context.Context, params UnifiedListResourceMappingGroupsParams) ([]UnifiedListResourceMappingGroupsRow, error) {
	pgParams := listResourceMappingGroupsParams{
		NamespaceID: params.NamespaceID,
		Limit:       params.Limit,
		Offset:      params.Offset,
	}

	rows, err := r.postgres.listResourceMappingGroups(ctx, pgParams)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListResourceMappingGroupsRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListResourceMappingGroupsRow{
			ID:          row.ID,
			NamespaceID: row.NamespaceID,
			Name:        row.Name,
			Metadata:    row.Metadata,
			Total:       row.Total,
		}
	}

	return result, nil
}

func (r *QueryRouter) listResourceMappingGroupsSQLite(ctx context.Context, params UnifiedListResourceMappingGroupsParams) ([]UnifiedListResourceMappingGroupsRow, error) {
	var namespaceID interface{}
	if params.NamespaceID != "" {
		namespaceID = params.NamespaceID
	}

	sqliteParams := sqlite.ListResourceMappingGroupsParams{
		NamespaceID: namespaceID,
		Limit:       int64(params.Limit),
		Offset:      int64(params.Offset),
	}

	rows, err := r.sqlite.ListResourceMappingGroups(ctx, sqliteParams)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListResourceMappingGroupsRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListResourceMappingGroupsRow{
			ID:          row.ID,
			NamespaceID: row.NamespaceID,
			Name:        row.Name,
			Metadata:    sqliteMetadataToBytes(row.Metadata),
			Total:       row.Total,
		}
	}

	return result, nil
}

// UnifiedCreateResourceMappingGroupParams is the unified parameters for creating a resource mapping group.
type UnifiedCreateResourceMappingGroupParams struct {
	NamespaceID string
	Name        string
	Metadata    []byte
}

// CreateResourceMappingGroup routes to the appropriate database backend and returns the created ID.
func (r *QueryRouter) CreateResourceMappingGroup(ctx context.Context, params UnifiedCreateResourceMappingGroupParams) (string, error) {
	if r.IsSQLite() {
		return r.createResourceMappingGroupSQLite(ctx, params)
	}
	return r.createResourceMappingGroupPostgres(ctx, params)
}

func (r *QueryRouter) createResourceMappingGroupPostgres(ctx context.Context, params UnifiedCreateResourceMappingGroupParams) (string, error) {
	pgParams := createResourceMappingGroupParams{
		NamespaceID: params.NamespaceID,
		Name:        params.Name,
		Metadata:    params.Metadata,
	}
	return r.postgres.createResourceMappingGroup(ctx, pgParams)
}

func (r *QueryRouter) createResourceMappingGroupSQLite(ctx context.Context, params UnifiedCreateResourceMappingGroupParams) (string, error) {
	id := uuid.NewString()
	sqliteParams := sqlite.CreateResourceMappingGroupParams{
		ID:          id,
		NamespaceID: params.NamespaceID,
		Name:        params.Name,
	}
	if params.Metadata != nil {
		sqliteParams.Metadata = sql.NullString{String: string(params.Metadata), Valid: true}
	}
	_, err := r.sqlite.CreateResourceMappingGroup(ctx, sqliteParams)
	if err != nil {
		return "", err
	}
	return id, nil
}

// UpdateResourceMappingGroup routes to the appropriate database backend.
func (r *QueryRouter) UpdateResourceMappingGroup(ctx context.Context, id string, namespaceID, name *string, metadata []byte) (int64, error) {
	if r.IsSQLite() {
		return r.updateResourceMappingGroupSQLite(ctx, id, namespaceID, name, metadata)
	}
	return r.updateResourceMappingGroupPostgres(ctx, id, namespaceID, name, metadata)
}

func (r *QueryRouter) updateResourceMappingGroupPostgres(ctx context.Context, id string, namespaceID, name *string, metadata []byte) (int64, error) {
	params := updateResourceMappingGroupParams{
		ID: id,
	}
	if namespaceID != nil {
		params.NamespaceID = pgtypeUUID(*namespaceID)
	}
	if name != nil {
		params.Name = pgtypeText(*name)
	}
	if metadata != nil {
		params.Metadata = metadata
	}
	return r.postgres.updateResourceMappingGroup(ctx, params)
}

func (r *QueryRouter) updateResourceMappingGroupSQLite(ctx context.Context, id string, namespaceID, name *string, metadata []byte) (int64, error) {
	params := sqlite.UpdateResourceMappingGroupParams{
		ID: id,
	}
	if namespaceID != nil {
		params.NamespaceID = sql.NullString{String: *namespaceID, Valid: true}
	}
	if name != nil {
		params.Name = sql.NullString{String: *name, Valid: true}
	}
	if metadata != nil {
		params.Metadata = sql.NullString{String: string(metadata), Valid: true}
	}
	return r.sqlite.UpdateResourceMappingGroup(ctx, params)
}

// DeleteResourceMappingGroup routes to the appropriate database backend.
func (r *QueryRouter) DeleteResourceMappingGroup(ctx context.Context, id string) (int64, error) {
	if r.IsSQLite() {
		return r.sqlite.DeleteResourceMappingGroup(ctx, id)
	}
	return r.postgres.deleteResourceMappingGroup(ctx, id)
}

// UnifiedGetResourceMappingRow is the unified result for getting a resource mapping.
type UnifiedGetResourceMappingRow struct {
	ID             string
	AttributeValue []byte
	Terms          []string
	Metadata       []byte
	GroupID        string
}

// GetResourceMapping routes to the appropriate database backend and normalizes the result.
func (r *QueryRouter) GetResourceMapping(ctx context.Context, id string) (UnifiedGetResourceMappingRow, error) {
	if r.IsSQLite() {
		return r.getResourceMappingSQLite(ctx, id)
	}
	return r.getResourceMappingPostgres(ctx, id)
}

func (r *QueryRouter) getResourceMappingPostgres(ctx context.Context, id string) (UnifiedGetResourceMappingRow, error) {
	row, err := r.postgres.getResourceMapping(ctx, id)
	if err != nil {
		return UnifiedGetResourceMappingRow{}, err
	}

	return UnifiedGetResourceMappingRow{
		ID:             row.ID,
		AttributeValue: row.AttributeValue,
		Terms:          row.Terms,
		Metadata:       row.Metadata,
		GroupID:        row.GroupID,
	}, nil
}

func (r *QueryRouter) getResourceMappingSQLite(ctx context.Context, id string) (UnifiedGetResourceMappingRow, error) {
	row, err := r.sqlite.GetResourceMapping(ctx, id)
	if err != nil {
		return UnifiedGetResourceMappingRow{}, err
	}

	// SQLite stores terms as a JSON string, need to parse
	var terms []string
	if row.Terms != "" {
		if err := json.Unmarshal([]byte(row.Terms), &terms); err != nil {
			// If not JSON, treat as a single term or comma-separated
			terms = strings.Split(row.Terms, ",")
		}
	}

	return UnifiedGetResourceMappingRow{
		ID:             row.ID,
		AttributeValue: sqliteMetadataToBytes(row.AttributeValue),
		Terms:          terms,
		Metadata:       sqliteMetadataToBytes(row.Metadata),
		GroupID:        row.GroupID,
	}, nil
}

// UnifiedListResourceMappingsParams is the unified parameters for listing resource mappings.
type UnifiedListResourceMappingsParams struct {
	GroupID string
	Limit   int32
	Offset  int32
}

// UnifiedListResourceMappingsRow is the unified result row for listing resource mappings.
type UnifiedListResourceMappingsRow struct {
	ID             string
	AttributeValue []byte
	Terms          []string
	Metadata       []byte
	Group          []byte
	Total          int64
}

// ListResourceMappings routes to the appropriate database backend and normalizes the result.
func (r *QueryRouter) ListResourceMappings(ctx context.Context, params UnifiedListResourceMappingsParams) ([]UnifiedListResourceMappingsRow, error) {
	if r.IsSQLite() {
		return r.listResourceMappingsSQLite(ctx, params)
	}
	return r.listResourceMappingsPostgres(ctx, params)
}

func (r *QueryRouter) listResourceMappingsPostgres(ctx context.Context, params UnifiedListResourceMappingsParams) ([]UnifiedListResourceMappingsRow, error) {
	pgParams := listResourceMappingsParams{
		GroupID: params.GroupID,
		Limit:   params.Limit,
		Offset:  params.Offset,
	}

	rows, err := r.postgres.listResourceMappings(ctx, pgParams)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListResourceMappingsRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListResourceMappingsRow{
			ID:             row.ID,
			AttributeValue: row.AttributeValue,
			Terms:          row.Terms,
			Metadata:       row.Metadata,
			Group:          row.Group,
			Total:          row.Total,
		}
	}

	return result, nil
}

func (r *QueryRouter) listResourceMappingsSQLite(ctx context.Context, params UnifiedListResourceMappingsParams) ([]UnifiedListResourceMappingsRow, error) {
	var groupID interface{}
	if params.GroupID != "" {
		groupID = params.GroupID
	}

	sqliteParams := sqlite.ListResourceMappingsParams{
		GroupID: groupID,
		Limit:   int64(params.Limit),
		Offset:  int64(params.Offset),
	}

	rows, err := r.sqlite.ListResourceMappings(ctx, sqliteParams)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListResourceMappingsRow, len(rows))
	for i, row := range rows {
		// SQLite stores terms as a JSON string, need to parse
		var terms []string
		if row.Terms != "" {
			if err := json.Unmarshal([]byte(row.Terms), &terms); err != nil {
				terms = strings.Split(row.Terms, ",")
			}
		}

		result[i] = UnifiedListResourceMappingsRow{
			ID:             row.ID,
			AttributeValue: sqliteMetadataToBytes(row.AttributeValue),
			Terms:          terms,
			Metadata:       sqliteMetadataToBytes(row.Metadata),
			Group:          sqliteMetadataToBytes(row.Group),
			Total:          row.Total,
		}
	}

	return result, nil
}

// UnifiedListResourceMappingsByFullyQualifiedGroupParams is the unified parameters.
type UnifiedListResourceMappingsByFullyQualifiedGroupParams struct {
	NamespaceName string
	GroupName     string
}

// UnifiedListResourceMappingsByFullyQualifiedGroupRow is the unified result row.
type UnifiedListResourceMappingsByFullyQualifiedGroupRow struct {
	ID             string
	AttributeValue []byte
	Terms          []string
	Metadata       []byte
	Group          []byte
}

// ListResourceMappingsByFullyQualifiedGroup routes to the appropriate database backend and normalizes the result.
func (r *QueryRouter) ListResourceMappingsByFullyQualifiedGroup(ctx context.Context, params UnifiedListResourceMappingsByFullyQualifiedGroupParams) ([]UnifiedListResourceMappingsByFullyQualifiedGroupRow, error) {
	if r.IsSQLite() {
		return r.listResourceMappingsByFullyQualifiedGroupSQLite(ctx, params)
	}
	return r.listResourceMappingsByFullyQualifiedGroupPostgres(ctx, params)
}

func (r *QueryRouter) listResourceMappingsByFullyQualifiedGroupPostgres(ctx context.Context, params UnifiedListResourceMappingsByFullyQualifiedGroupParams) ([]UnifiedListResourceMappingsByFullyQualifiedGroupRow, error) {
	pgParams := listResourceMappingsByFullyQualifiedGroupParams{
		NamespaceName: params.NamespaceName,
		GroupName:     params.GroupName,
	}

	rows, err := r.postgres.listResourceMappingsByFullyQualifiedGroup(ctx, pgParams)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListResourceMappingsByFullyQualifiedGroupRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListResourceMappingsByFullyQualifiedGroupRow{
			ID:             row.ID,
			AttributeValue: row.AttributeValue,
			Terms:          row.Terms,
			Metadata:       row.Metadata,
			Group:          row.Group,
		}
	}

	return result, nil
}

func (r *QueryRouter) listResourceMappingsByFullyQualifiedGroupSQLite(ctx context.Context, params UnifiedListResourceMappingsByFullyQualifiedGroupParams) ([]UnifiedListResourceMappingsByFullyQualifiedGroupRow, error) {
	sqliteParams := sqlite.ListResourceMappingsByFullyQualifiedGroupParams{
		NamespaceName: params.NamespaceName,
		GroupName:     params.GroupName,
	}

	rows, err := r.sqlite.ListResourceMappingsByFullyQualifiedGroup(ctx, sqliteParams)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListResourceMappingsByFullyQualifiedGroupRow, len(rows))
	for i, row := range rows {
		// SQLite stores terms as a JSON string, need to parse
		var terms []string
		if row.Terms != "" {
			if err := json.Unmarshal([]byte(row.Terms), &terms); err != nil {
				terms = strings.Split(row.Terms, ",")
			}
		}

		result[i] = UnifiedListResourceMappingsByFullyQualifiedGroupRow{
			ID:             row.ID,
			AttributeValue: sqliteMetadataToBytes(row.AttributeValue),
			Terms:          terms,
			Metadata:       sqliteMetadataToBytes(row.Metadata),
			Group:          sqliteMetadataToBytes(row.Group),
		}
	}

	return result, nil
}

// UnifiedCreateResourceMappingParams is the unified parameters for creating a resource mapping.
type UnifiedCreateResourceMappingParams struct {
	AttributeValueID string
	Terms            []string
	Metadata         []byte
	GroupID          string
}

// CreateResourceMapping routes to the appropriate database backend and returns the created ID.
func (r *QueryRouter) CreateResourceMapping(ctx context.Context, params UnifiedCreateResourceMappingParams) (string, error) {
	if r.IsSQLite() {
		return r.createResourceMappingSQLite(ctx, params)
	}
	return r.createResourceMappingPostgres(ctx, params)
}

func (r *QueryRouter) createResourceMappingPostgres(ctx context.Context, params UnifiedCreateResourceMappingParams) (string, error) {
	pgParams := createResourceMappingParams{
		AttributeValueID: params.AttributeValueID,
		Terms:            params.Terms,
		Metadata:         params.Metadata,
	}
	if params.GroupID != "" {
		pgParams.GroupID = pgtypeUUID(params.GroupID)
	}
	return r.postgres.createResourceMapping(ctx, pgParams)
}

func (r *QueryRouter) createResourceMappingSQLite(ctx context.Context, params UnifiedCreateResourceMappingParams) (string, error) {
	id := uuid.NewString()

	// Convert terms slice to JSON string for SQLite
	termsJSON, err := json.Marshal(params.Terms)
	if err != nil {
		return "", err
	}

	sqliteParams := sqlite.CreateResourceMappingParams{
		ID:               id,
		AttributeValueID: params.AttributeValueID,
		Terms:            string(termsJSON),
	}
	if params.Metadata != nil {
		sqliteParams.Metadata = sql.NullString{String: string(params.Metadata), Valid: true}
	}
	if params.GroupID != "" {
		sqliteParams.GroupID = sql.NullString{String: params.GroupID, Valid: true}
	}
	_, err = r.sqlite.CreateResourceMapping(ctx, sqliteParams)
	if err != nil {
		return "", err
	}
	return id, nil
}

// UpdateResourceMapping routes to the appropriate database backend.
func (r *QueryRouter) UpdateResourceMapping(ctx context.Context, id string, attributeValueID *string, terms []string, metadata []byte, groupID *string) (int64, error) {
	if r.IsSQLite() {
		return r.updateResourceMappingSQLite(ctx, id, attributeValueID, terms, metadata, groupID)
	}
	return r.updateResourceMappingPostgres(ctx, id, attributeValueID, terms, metadata, groupID)
}

func (r *QueryRouter) updateResourceMappingPostgres(ctx context.Context, id string, attributeValueID *string, terms []string, metadata []byte, groupID *string) (int64, error) {
	params := updateResourceMappingParams{
		ID:    id,
		Terms: terms,
	}
	if attributeValueID != nil {
		params.AttributeValueID = pgtypeUUID(*attributeValueID)
	}
	if metadata != nil {
		params.Metadata = metadata
	}
	if groupID != nil {
		params.GroupID = pgtypeUUID(*groupID)
	}
	return r.postgres.updateResourceMapping(ctx, params)
}

func (r *QueryRouter) updateResourceMappingSQLite(ctx context.Context, id string, attributeValueID *string, terms []string, metadata []byte, groupID *string) (int64, error) {
	params := sqlite.UpdateResourceMappingParams{
		ID: id,
	}
	if attributeValueID != nil {
		params.AttributeValueID = sql.NullString{String: *attributeValueID, Valid: true}
	}
	if terms != nil {
		termsJSON, err := json.Marshal(terms)
		if err != nil {
			return 0, err
		}
		params.Terms = sql.NullString{String: string(termsJSON), Valid: true}
	}
	if metadata != nil {
		params.Metadata = sql.NullString{String: string(metadata), Valid: true}
	}
	if groupID != nil {
		params.GroupID = sql.NullString{String: *groupID, Valid: true}
	}
	return r.sqlite.UpdateResourceMapping(ctx, params)
}

// DeleteResourceMapping routes to the appropriate database backend.
func (r *QueryRouter) DeleteResourceMapping(ctx context.Context, id string) (int64, error) {
	if r.IsSQLite() {
		return r.sqlite.DeleteResourceMapping(ctx, id)
	}
	return r.postgres.deleteResourceMapping(ctx, id)
}
