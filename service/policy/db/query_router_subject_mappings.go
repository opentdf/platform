package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"

	"github.com/google/uuid"
	"github.com/opentdf/platform/service/policy/db/sqlite"
)

// Subject Condition Set routing

// UnifiedGetSubjectConditionSetRow is the unified result for getting a subject condition set.
type UnifiedGetSubjectConditionSetRow struct {
	ID        string
	Condition []byte
	Metadata  []byte
}

// GetSubjectConditionSet routes to the appropriate database backend.
func (r *QueryRouter) GetSubjectConditionSet(ctx context.Context, id string) (UnifiedGetSubjectConditionSetRow, error) {
	if r.IsSQLite() {
		return r.getSubjectConditionSetSQLite(ctx, id)
	}
	return r.getSubjectConditionSetPostgres(ctx, id)
}

func (r *QueryRouter) getSubjectConditionSetPostgres(ctx context.Context, id string) (UnifiedGetSubjectConditionSetRow, error) {
	row, err := r.postgres.getSubjectConditionSet(ctx, id)
	if err != nil {
		return UnifiedGetSubjectConditionSetRow{}, err
	}
	return UnifiedGetSubjectConditionSetRow{
		ID:        row.ID,
		Condition: row.Condition,
		Metadata:  row.Metadata,
	}, nil
}

func (r *QueryRouter) getSubjectConditionSetSQLite(ctx context.Context, id string) (UnifiedGetSubjectConditionSetRow, error) {
	row, err := r.sqlite.GetSubjectConditionSet(ctx, id)
	if err != nil {
		return UnifiedGetSubjectConditionSetRow{}, err
	}
	return UnifiedGetSubjectConditionSetRow{
		ID:        row.ID,
		Condition: []byte(row.Condition),
		Metadata:  sqliteMetadataToBytes(row.Metadata),
	}, nil
}

// UnifiedListSubjectConditionSetsParams is the unified parameters for listing subject condition sets.
type UnifiedListSubjectConditionSetsParams struct {
	Limit  int32
	Offset int32
}

// UnifiedListSubjectConditionSetsRow is the unified result row for listing subject condition sets.
type UnifiedListSubjectConditionSetsRow struct {
	ID        string
	Condition []byte
	Metadata  []byte
	Total     int64
}

// ListSubjectConditionSets routes to the appropriate database backend.
func (r *QueryRouter) ListSubjectConditionSets(ctx context.Context, params UnifiedListSubjectConditionSetsParams) ([]UnifiedListSubjectConditionSetsRow, error) {
	if r.IsSQLite() {
		return r.listSubjectConditionSetsSQLite(ctx, params)
	}
	return r.listSubjectConditionSetsPostgres(ctx, params)
}

func (r *QueryRouter) listSubjectConditionSetsPostgres(ctx context.Context, params UnifiedListSubjectConditionSetsParams) ([]UnifiedListSubjectConditionSetsRow, error) {
	rows, err := r.postgres.listSubjectConditionSets(ctx, listSubjectConditionSetsParams{
		Limit:  params.Limit,
		Offset: params.Offset,
	})
	if err != nil {
		return nil, err
	}
	result := make([]UnifiedListSubjectConditionSetsRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListSubjectConditionSetsRow{
			ID:        row.ID,
			Condition: row.Condition,
			Metadata:  row.Metadata,
			Total:     row.Total,
		}
	}
	return result, nil
}

func (r *QueryRouter) listSubjectConditionSetsSQLite(ctx context.Context, params UnifiedListSubjectConditionSetsParams) ([]UnifiedListSubjectConditionSetsRow, error) {
	rows, err := r.sqlite.ListSubjectConditionSets(ctx, sqlite.ListSubjectConditionSetsParams{
		Limit:  int64(params.Limit),
		Offset: int64(params.Offset),
	})
	if err != nil {
		return nil, err
	}
	result := make([]UnifiedListSubjectConditionSetsRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListSubjectConditionSetsRow{
			ID:        row.ID,
			Condition: []byte(row.Condition),
			Metadata:  sqliteMetadataToBytes(row.Metadata),
			Total:     row.Total,
		}
	}
	return result, nil
}

// UnifiedCreateSubjectConditionSetParams is the unified parameters for creating a subject condition set.
type UnifiedCreateSubjectConditionSetParams struct {
	Condition []byte
	Metadata  []byte
}

// CreateSubjectConditionSet routes to the appropriate database backend and returns the created ID.
func (r *QueryRouter) CreateSubjectConditionSet(ctx context.Context, params UnifiedCreateSubjectConditionSetParams) (string, error) {
	if r.IsSQLite() {
		return r.createSubjectConditionSetSQLite(ctx, params)
	}
	return r.createSubjectConditionSetPostgres(ctx, params)
}

func (r *QueryRouter) createSubjectConditionSetPostgres(ctx context.Context, params UnifiedCreateSubjectConditionSetParams) (string, error) {
	return r.postgres.createSubjectConditionSet(ctx, createSubjectConditionSetParams{
		Condition: params.Condition,
		Metadata:  params.Metadata,
	})
}

func (r *QueryRouter) createSubjectConditionSetSQLite(ctx context.Context, params UnifiedCreateSubjectConditionSetParams) (string, error) {
	id := uuid.NewString()
	sqliteParams := sqlite.CreateSubjectConditionSetParams{
		ID:        id,
		Condition: string(params.Condition),
	}
	if params.Metadata != nil {
		sqliteParams.Metadata = sql.NullString{String: string(params.Metadata), Valid: true}
	}
	_, err := r.sqlite.CreateSubjectConditionSet(ctx, sqliteParams)
	if err != nil {
		return "", err
	}
	return id, nil
}

// UnifiedUpdateSubjectConditionSetParams is the unified parameters for updating a subject condition set.
type UnifiedUpdateSubjectConditionSetParams struct {
	ID        string
	Condition []byte // nil means don't update
	Metadata  []byte // nil means don't update
}

// UpdateSubjectConditionSet routes to the appropriate database backend.
func (r *QueryRouter) UpdateSubjectConditionSet(ctx context.Context, params UnifiedUpdateSubjectConditionSetParams) (int64, error) {
	if r.IsSQLite() {
		return r.updateSubjectConditionSetSQLite(ctx, params)
	}
	return r.updateSubjectConditionSetPostgres(ctx, params)
}

func (r *QueryRouter) updateSubjectConditionSetPostgres(ctx context.Context, params UnifiedUpdateSubjectConditionSetParams) (int64, error) {
	return r.postgres.updateSubjectConditionSet(ctx, updateSubjectConditionSetParams{
		ID:        params.ID,
		Condition: params.Condition,
		Metadata:  params.Metadata,
	})
}

func (r *QueryRouter) updateSubjectConditionSetSQLite(ctx context.Context, params UnifiedUpdateSubjectConditionSetParams) (int64, error) {
	sqliteParams := sqlite.UpdateSubjectConditionSetParams{
		ID: params.ID,
	}
	if params.Condition != nil {
		sqliteParams.Condition = sql.NullString{String: string(params.Condition), Valid: true}
	}
	if params.Metadata != nil {
		sqliteParams.Metadata = sql.NullString{String: string(params.Metadata), Valid: true}
	}
	return r.sqlite.UpdateSubjectConditionSet(ctx, sqliteParams)
}

// DeleteSubjectConditionSet routes to the appropriate database backend.
func (r *QueryRouter) DeleteSubjectConditionSet(ctx context.Context, id string) (int64, error) {
	if r.IsSQLite() {
		return r.sqlite.DeleteSubjectConditionSet(ctx, id)
	}
	return r.postgres.deleteSubjectConditionSet(ctx, id)
}

// DeleteAllUnmappedSubjectConditionSets routes to the appropriate database backend.
func (r *QueryRouter) DeleteAllUnmappedSubjectConditionSets(ctx context.Context) ([]string, error) {
	if r.IsSQLite() {
		return r.sqlite.DeleteAllUnmappedSubjectConditionSets(ctx)
	}
	return r.postgres.deleteAllUnmappedSubjectConditionSets(ctx)
}

// Subject Mapping routing

// UnifiedGetSubjectMappingRow is the unified result for getting a subject mapping.
type UnifiedGetSubjectMappingRow struct {
	ID                  string
	StandardActions     []byte
	CustomActions       []byte
	Metadata            []byte
	SubjectConditionSet []byte
	AttributeValue      []byte
}

// GetSubjectMapping routes to the appropriate database backend.
func (r *QueryRouter) GetSubjectMapping(ctx context.Context, id string) (UnifiedGetSubjectMappingRow, error) {
	if r.IsSQLite() {
		return r.getSubjectMappingSQLite(ctx, id)
	}
	return r.getSubjectMappingPostgres(ctx, id)
}

func (r *QueryRouter) getSubjectMappingPostgres(ctx context.Context, id string) (UnifiedGetSubjectMappingRow, error) {
	row, err := r.postgres.getSubjectMapping(ctx, id)
	if err != nil {
		return UnifiedGetSubjectMappingRow{}, err
	}
	return UnifiedGetSubjectMappingRow{
		ID:                  row.ID,
		StandardActions:     row.StandardActions,
		CustomActions:       row.CustomActions,
		Metadata:            row.Metadata,
		SubjectConditionSet: row.SubjectConditionSet,
		AttributeValue:      row.AttributeValue,
	}, nil
}

func (r *QueryRouter) getSubjectMappingSQLite(ctx context.Context, id string) (UnifiedGetSubjectMappingRow, error) {
	row, err := r.sqlite.GetSubjectMapping(ctx, id)
	if err != nil {
		return UnifiedGetSubjectMappingRow{}, err
	}
	return UnifiedGetSubjectMappingRow{
		ID:                  row.ID,
		StandardActions:     sqliteMetadataToBytes(row.StandardActions),
		CustomActions:       sqliteMetadataToBytes(row.CustomActions),
		Metadata:            sqliteMetadataToBytes(row.Metadata),
		SubjectConditionSet: sqliteMetadataToBytes(row.SubjectConditionSet),
		AttributeValue:      sqliteMetadataToBytes(row.AttributeValue),
	}, nil
}

// UnifiedListSubjectMappingsParams is the unified parameters for listing subject mappings.
type UnifiedListSubjectMappingsParams struct {
	Limit  int32
	Offset int32
}

// UnifiedListSubjectMappingsRow is the unified result row for listing subject mappings.
type UnifiedListSubjectMappingsRow struct {
	ID                  string
	StandardActions     []byte
	CustomActions       []byte
	Metadata            []byte
	SubjectConditionSet []byte
	AttributeValue      []byte
	Total               int64
}

// ListSubjectMappings routes to the appropriate database backend.
func (r *QueryRouter) ListSubjectMappings(ctx context.Context, params UnifiedListSubjectMappingsParams) ([]UnifiedListSubjectMappingsRow, error) {
	if r.IsSQLite() {
		return r.listSubjectMappingsSQLite(ctx, params)
	}
	return r.listSubjectMappingsPostgres(ctx, params)
}

func (r *QueryRouter) listSubjectMappingsPostgres(ctx context.Context, params UnifiedListSubjectMappingsParams) ([]UnifiedListSubjectMappingsRow, error) {
	rows, err := r.postgres.listSubjectMappings(ctx, listSubjectMappingsParams{
		Limit:  params.Limit,
		Offset: params.Offset,
	})
	if err != nil {
		return nil, err
	}
	result := make([]UnifiedListSubjectMappingsRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListSubjectMappingsRow{
			ID:                  row.ID,
			StandardActions:     interfaceToBytes(row.StandardActions),
			CustomActions:       interfaceToBytes(row.CustomActions),
			Metadata:            row.Metadata,
			SubjectConditionSet: row.SubjectConditionSet,
			AttributeValue:      row.AttributeValue,
			Total:               row.Total,
		}
	}
	return result, nil
}

func (r *QueryRouter) listSubjectMappingsSQLite(ctx context.Context, params UnifiedListSubjectMappingsParams) ([]UnifiedListSubjectMappingsRow, error) {
	rows, err := r.sqlite.ListSubjectMappings(ctx, sqlite.ListSubjectMappingsParams{
		Limit:  int64(params.Limit),
		Offset: int64(params.Offset),
	})
	if err != nil {
		return nil, err
	}
	result := make([]UnifiedListSubjectMappingsRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListSubjectMappingsRow{
			ID:                  row.ID,
			StandardActions:     sqliteMetadataToBytes(row.StandardActions),
			CustomActions:       sqliteMetadataToBytes(row.CustomActions),
			Metadata:            sqliteMetadataToBytes(row.Metadata),
			SubjectConditionSet: sqliteMetadataToBytes(row.SubjectConditionSet),
			AttributeValue:      sqliteMetadataToBytes(row.AttributeValue),
			Total:               row.Total,
		}
	}
	return result, nil
}

// UnifiedMatchSubjectMappingsRow is the unified result row for matching subject mappings.
type UnifiedMatchSubjectMappingsRow struct {
	ID                  string
	StandardActions     []byte
	CustomActions       []byte
	SubjectConditionSet []byte
	AttributeValue      []byte
}

// MatchSubjectMappings routes to the appropriate database backend.
func (r *QueryRouter) MatchSubjectMappings(ctx context.Context, selectors []string) ([]UnifiedMatchSubjectMappingsRow, error) {
	if r.IsSQLite() {
		return r.matchSubjectMappingsSQLite(ctx, selectors)
	}
	return r.matchSubjectMappingsPostgres(ctx, selectors)
}

func (r *QueryRouter) matchSubjectMappingsPostgres(ctx context.Context, selectors []string) ([]UnifiedMatchSubjectMappingsRow, error) {
	rows, err := r.postgres.matchSubjectMappings(ctx, selectors)
	if err != nil {
		return nil, err
	}
	result := make([]UnifiedMatchSubjectMappingsRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedMatchSubjectMappingsRow{
			ID:                  row.ID,
			StandardActions:     interfaceToBytes(row.StandardActions),
			CustomActions:       interfaceToBytes(row.CustomActions),
			SubjectConditionSet: row.SubjectConditionSet,
			AttributeValue:      row.AttributeValue,
		}
	}
	return result, nil
}

func (r *QueryRouter) matchSubjectMappingsSQLite(ctx context.Context, selectors []string) ([]UnifiedMatchSubjectMappingsRow, error) {
	// SQLite's matchSubjectMappings query uses json_each(@selectors) which requires the selectors
	// to be passed as a JSON array. Since the generated query doesn't accept a parameter,
	// we need to use raw SQL to pass the selectors.
	selectorsJSON, err := json.Marshal(selectors)
	if err != nil {
		return nil, err
	}

	query := `
SELECT
    sm.id,
    (
        SELECT json_group_array(json_object('id', a.id, 'name', a.name))
        FROM subject_mapping_actions sma
        JOIN actions a ON sma.action_id = a.id
        WHERE sma.subject_mapping_id = sm.id AND a.is_standard = 1
    ) AS standard_actions,
    (
        SELECT json_group_array(json_object('id', a.id, 'name', a.name))
        FROM subject_mapping_actions sma
        JOIN actions a ON sma.action_id = a.id
        WHERE sma.subject_mapping_id = sm.id AND a.is_standard = 0
    ) AS custom_actions,
    json_object(
        'id', scs.id,
        'subject_sets', json(scs.condition)
    ) AS subject_condition_set,
    json_object(
        'id', av.id,
        'value', av.value,
        'active', av.active,
        'fqn', fqns.fqn
    ) AS attribute_value
FROM subject_mappings sm
LEFT JOIN attribute_values av ON sm.attribute_value_id = av.id
LEFT JOIN attribute_definitions ad ON av.attribute_definition_id = ad.id
LEFT JOIN attribute_namespaces ns ON ad.namespace_id = ns.id
LEFT JOIN attribute_fqns fqns ON av.id = fqns.value_id
LEFT JOIN subject_condition_set scs ON scs.id = sm.subject_condition_set_id
WHERE
    ns.active = 1
    AND ad.active = 1
    AND av.active = 1
    AND EXISTS (
        SELECT 1
        FROM json_each(scs.selector_values) sv
        WHERE sv.value IN (SELECT value FROM json_each(?))
    )
GROUP BY sm.id, scs.id, scs.condition, av.id, av.value, av.active, fqns.fqn
`

	rows, err := r.SQLExecutor().QueryContext(ctx, query, string(selectorsJSON))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []UnifiedMatchSubjectMappingsRow
	for rows.Next() {
		var row UnifiedMatchSubjectMappingsRow
		var standardActions, customActions, subjectConditionSet, attributeValue interface{}
		if err := rows.Scan(
			&row.ID,
			&standardActions,
			&customActions,
			&subjectConditionSet,
			&attributeValue,
		); err != nil {
			return nil, err
		}
		row.StandardActions = sqliteMetadataToBytes(standardActions)
		row.CustomActions = sqliteMetadataToBytes(customActions)
		row.SubjectConditionSet = sqliteMetadataToBytes(subjectConditionSet)
		row.AttributeValue = sqliteMetadataToBytes(attributeValue)
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// UnifiedCreateSubjectMappingParams is the unified parameters for creating a subject mapping.
type UnifiedCreateSubjectMappingParams struct {
	AttributeValueID      string
	ActionIDs             []string
	Metadata              []byte
	SubjectConditionSetID string // UUID as string (empty if null)
}

// CreateSubjectMapping routes to the appropriate database backend and returns the created ID.
func (r *QueryRouter) CreateSubjectMapping(ctx context.Context, params UnifiedCreateSubjectMappingParams) (string, error) {
	if r.IsSQLite() {
		return r.createSubjectMappingSQLite(ctx, params)
	}
	return r.createSubjectMappingPostgres(ctx, params)
}

func (r *QueryRouter) createSubjectMappingPostgres(ctx context.Context, params UnifiedCreateSubjectMappingParams) (string, error) {
	pgParams := createSubjectMappingParams{
		AttributeValueID: params.AttributeValueID,
		ActionIds:        params.ActionIDs,
		Metadata:         params.Metadata,
	}
	if params.SubjectConditionSetID != "" {
		pgParams.SubjectConditionSetID = pgtypeUUID(params.SubjectConditionSetID)
	}
	return r.postgres.createSubjectMapping(ctx, pgParams)
}

func (r *QueryRouter) createSubjectMappingSQLite(ctx context.Context, params UnifiedCreateSubjectMappingParams) (string, error) {
	id := uuid.NewString()
	sqliteParams := sqlite.CreateSubjectMappingParams{
		ID:               id,
		AttributeValueID: params.AttributeValueID,
	}
	if params.Metadata != nil {
		sqliteParams.Metadata = sql.NullString{String: string(params.Metadata), Valid: true}
	}
	if params.SubjectConditionSetID != "" {
		sqliteParams.SubjectConditionSetID = sql.NullString{String: params.SubjectConditionSetID, Valid: true}
	}
	_, err := r.sqlite.CreateSubjectMapping(ctx, sqliteParams)
	if err != nil {
		return "", err
	}

	// For SQLite, actions must be added separately since there's no unnest
	for _, actionID := range params.ActionIDs {
		err := r.sqlite.AddActionToSubjectMapping(ctx, sqlite.AddActionToSubjectMappingParams{
			SubjectMappingID: id,
			ActionID:         actionID,
		})
		if err != nil {
			return "", err
		}
	}

	return id, nil
}

// UnifiedUpdateSubjectMappingParams is the unified parameters for updating a subject mapping.
type UnifiedUpdateSubjectMappingParams struct {
	ID                    string
	ActionIDs             []string // nil means don't update, empty slice means clear all
	Metadata              []byte   // nil means don't update
	SubjectConditionSetID string   // empty means don't update (use pgtype for actual null)
}

// UpdateSubjectMapping routes to the appropriate database backend.
func (r *QueryRouter) UpdateSubjectMapping(ctx context.Context, params UnifiedUpdateSubjectMappingParams) (int64, error) {
	if r.IsSQLite() {
		return r.updateSubjectMappingSQLite(ctx, params)
	}
	return r.updateSubjectMappingPostgres(ctx, params)
}

func (r *QueryRouter) updateSubjectMappingPostgres(ctx context.Context, params UnifiedUpdateSubjectMappingParams) (int64, error) {
	pgParams := updateSubjectMappingParams{
		ID:        params.ID,
		Metadata:  params.Metadata,
		ActionIds: params.ActionIDs,
	}
	if params.SubjectConditionSetID != "" {
		pgParams.SubjectConditionSetID = pgtypeUUID(params.SubjectConditionSetID)
	}
	return r.postgres.updateSubjectMapping(ctx, pgParams)
}

func (r *QueryRouter) updateSubjectMappingSQLite(ctx context.Context, params UnifiedUpdateSubjectMappingParams) (int64, error) {
	sqliteParams := sqlite.UpdateSubjectMappingParams{
		ID: params.ID,
	}
	if params.Metadata != nil {
		sqliteParams.Metadata = sql.NullString{String: string(params.Metadata), Valid: true}
	}
	if params.SubjectConditionSetID != "" {
		sqliteParams.SubjectConditionSetID = sql.NullString{String: params.SubjectConditionSetID, Valid: true}
	}
	count, err := r.sqlite.UpdateSubjectMapping(ctx, sqliteParams)
	if err != nil {
		return 0, err
	}

	// For SQLite, action updates must be handled separately
	if params.ActionIDs != nil {
		// Remove all existing actions
		_, err := r.sqlite.RemoveAllActionsFromSubjectMapping(ctx, params.ID)
		if err != nil {
			return 0, err
		}
		// Add new actions
		for _, actionID := range params.ActionIDs {
			err := r.sqlite.AddActionToSubjectMapping(ctx, sqlite.AddActionToSubjectMappingParams{
				SubjectMappingID: params.ID,
				ActionID:         actionID,
			})
			if err != nil {
				return 0, err
			}
		}
	}

	return count, nil
}

// DeleteSubjectMapping routes to the appropriate database backend.
func (r *QueryRouter) DeleteSubjectMapping(ctx context.Context, id string) (int64, error) {
	if r.IsSQLite() {
		return r.sqlite.DeleteSubjectMapping(ctx, id)
	}
	return r.postgres.deleteSubjectMapping(ctx, id)
}

// CreateOrListActionsByName result row
type UnifiedActionRow struct {
	ID          string
	Name        string
	IsStandard  bool
	PreExisting bool
}

// CreateOrListActionsByName routes to the appropriate database backend.
// For SQLite, this emulates PostgreSQL's behavior by looking up existing actions
// and creating new custom actions for names that don't exist.
func (r *QueryRouter) CreateOrListActionsByName(ctx context.Context, actionNames []string) ([]UnifiedActionRow, error) {
	if r.IsSQLite() {
		return r.createOrListActionsByNameSQLite(ctx, actionNames)
	}
	return r.createOrListActionsByNamePostgres(ctx, actionNames)
}

func (r *QueryRouter) createOrListActionsByNamePostgres(ctx context.Context, actionNames []string) ([]UnifiedActionRow, error) {
	rows, err := r.postgres.createOrListActionsByName(ctx, actionNames)
	if err != nil {
		return nil, err
	}
	result := make([]UnifiedActionRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedActionRow{
			ID:          row.ID,
			Name:        row.Name,
			IsStandard:  row.IsStandard,
			PreExisting: row.PreExisting,
		}
	}
	return result, nil
}

func (r *QueryRouter) createOrListActionsByNameSQLite(ctx context.Context, actionNames []string) ([]UnifiedActionRow, error) {
	// Create a map for quick lookup of input names (lowercase for case-insensitive matching)
	inputNames := make(map[string]bool)
	for _, name := range actionNames {
		inputNames[strings.ToLower(name)] = true
	}

	// First, get all existing actions that match the input names
	// We need to use raw SQL since the generated getActionsByNames doesn't accept parameters
	namesJSON, err := json.Marshal(actionNames)
	if err != nil {
		return nil, err
	}

	query := `
SELECT
    id,
    name,
    is_standard
FROM actions
WHERE LOWER(name) IN (SELECT LOWER(value) FROM json_each(?))
`
	rows, err := r.SQLExecutor().QueryContext(ctx, query, string(namesJSON))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := []UnifiedActionRow{}
	existingNames := make(map[string]bool)
	for rows.Next() {
		var id, name string
		var isStandard int64
		if err := rows.Scan(&id, &name, &isStandard); err != nil {
			return nil, err
		}
		existingNames[strings.ToLower(name)] = true
		result = append(result, UnifiedActionRow{
			ID:          id,
			Name:        name,
			IsStandard:  isStandard != 0,
			PreExisting: true,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Create new custom actions for names that don't exist
	for _, name := range actionNames {
		if !existingNames[strings.ToLower(name)] {
			id := uuid.NewString()
			_, err := r.sqlite.CreateCustomAction(ctx, sqlite.CreateCustomActionParams{
				ID:   id,
				Name: name,
			})
			if err != nil {
				return nil, err
			}
			result = append(result, UnifiedActionRow{
				ID:          id,
				Name:        name,
				IsStandard:  false,
				PreExisting: false,
			})
		}
	}

	return result, nil
}
