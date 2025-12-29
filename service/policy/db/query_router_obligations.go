package db

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/opentdf/platform/service/policy/db/sqlite"
)

// UnifiedGetObligationParams is the unified parameters for getting an obligation.
type UnifiedGetObligationParams struct {
	ID           string
	NamespaceFqn string
	Name         string
}

// UnifiedGetObligationRow is the unified result for getting an obligation.
type UnifiedGetObligationRow struct {
	ID        string
	Name      string
	Namespace []byte
	Metadata  []byte
	Values    []byte
}

// GetObligation routes to the appropriate database backend and normalizes the result.
func (r *QueryRouter) GetObligation(ctx context.Context, params UnifiedGetObligationParams) (UnifiedGetObligationRow, error) {
	if r.IsSQLite() {
		return r.getObligationSQLite(ctx, params)
	}
	return r.getObligationPostgres(ctx, params)
}

func (r *QueryRouter) getObligationPostgres(ctx context.Context, params UnifiedGetObligationParams) (UnifiedGetObligationRow, error) {
	pgParams := getObligationParams{
		ID:           params.ID,
		NamespaceFqn: params.NamespaceFqn,
		Name:         params.Name,
	}

	row, err := r.postgres.getObligation(ctx, pgParams)
	if err != nil {
		return UnifiedGetObligationRow{}, err
	}

	return UnifiedGetObligationRow{
		ID:        row.ID,
		Name:      row.Name,
		Namespace: row.Namespace,
		Metadata:  row.Metadata,
		Values:    row.Values,
	}, nil
}

func (r *QueryRouter) getObligationSQLite(ctx context.Context, params UnifiedGetObligationParams) (UnifiedGetObligationRow, error) {
	sqliteParams := sqlite.GetObligationParams{
		ID:           params.ID,
		NamespaceFqn: params.NamespaceFqn,
		Name:         params.Name,
	}

	row, err := r.sqlite.GetObligation(ctx, sqliteParams)
	if err != nil {
		return UnifiedGetObligationRow{}, err
	}

	return UnifiedGetObligationRow{
		ID:        row.ID,
		Name:      row.Name,
		Namespace: sqliteInterfaceToBytes(row.Namespace),
		Metadata:  sqliteInterfaceToBytes(row.Metadata),
		Values:    sqliteInterfaceToBytes(row.Values),
	}, nil
}

// UnifiedListObligationsParams is the unified parameters for listing obligations.
type UnifiedListObligationsParams struct {
	NamespaceID  string
	NamespaceFqn string
	Limit        int32
	Offset       int32
}

// UnifiedListObligationsRow is the unified result row for listing obligations.
type UnifiedListObligationsRow struct {
	ID        string
	Name      string
	Namespace []byte
	Metadata  []byte
	Values    []byte
	Total     int64
}

// ListObligations routes to the appropriate database backend and normalizes the result.
func (r *QueryRouter) ListObligations(ctx context.Context, params UnifiedListObligationsParams) ([]UnifiedListObligationsRow, error) {
	if r.IsSQLite() {
		return r.listObligationsSQLite(ctx, params)
	}
	return r.listObligationsPostgres(ctx, params)
}

func (r *QueryRouter) listObligationsPostgres(ctx context.Context, params UnifiedListObligationsParams) ([]UnifiedListObligationsRow, error) {
	pgParams := listObligationsParams{
		NamespaceID:  params.NamespaceID,
		NamespaceFqn: params.NamespaceFqn,
		Limit:        params.Limit,
		Offset:       params.Offset,
	}

	rows, err := r.postgres.listObligations(ctx, pgParams)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListObligationsRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListObligationsRow{
			ID:        row.ID,
			Name:      row.Name,
			Namespace: row.Namespace,
			Metadata:  row.Metadata,
			Values:    row.Values,
			Total:     row.Total,
		}
	}

	return result, nil
}

func (r *QueryRouter) listObligationsSQLite(ctx context.Context, params UnifiedListObligationsParams) ([]UnifiedListObligationsRow, error) {
	sqliteParams := sqlite.ListObligationsParams{
		NamespaceID:  params.NamespaceID,
		NamespaceFqn: params.NamespaceFqn,
		Limit:        int64(params.Limit),
		Offset:       int64(params.Offset),
	}

	rows, err := r.sqlite.ListObligations(ctx, sqliteParams)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListObligationsRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListObligationsRow{
			ID:        row.ID,
			Name:      row.Name,
			Namespace: sqliteInterfaceToBytes(row.Namespace),
			Metadata:  sqliteInterfaceToBytes(row.Metadata),
			Values:    sqliteInterfaceToBytes(row.Values),
			Total:     row.Total,
		}
	}

	return result, nil
}

// UnifiedCreateObligationParams is the unified parameters for creating an obligation.
type UnifiedCreateObligationParams struct {
	NamespaceID  string
	NamespaceFqn string
	Name         string
	Metadata     []byte
	Values       []string
}

// UnifiedCreateObligationRow is the unified result for creating an obligation.
type UnifiedCreateObligationRow struct {
	ID        string
	Name      string
	Namespace []byte
	Metadata  []byte
	Values    []byte
}

// CreateObligation routes to the appropriate database backend.
func (r *QueryRouter) CreateObligation(ctx context.Context, params UnifiedCreateObligationParams) (UnifiedCreateObligationRow, error) {
	if r.IsSQLite() {
		return r.createObligationSQLite(ctx, params)
	}
	return r.createObligationPostgres(ctx, params)
}

func (r *QueryRouter) createObligationPostgres(ctx context.Context, params UnifiedCreateObligationParams) (UnifiedCreateObligationRow, error) {
	pgParams := createObligationParams{
		NamespaceID:  params.NamespaceID,
		NamespaceFqn: params.NamespaceFqn,
		Name:         params.Name,
		Metadata:     params.Metadata,
		Values:       params.Values,
	}

	row, err := r.postgres.createObligation(ctx, pgParams)
	if err != nil {
		return UnifiedCreateObligationRow{}, err
	}

	return UnifiedCreateObligationRow{
		ID:        row.ID,
		Name:      row.Name,
		Namespace: row.Namespace,
		Metadata:  row.Metadata,
		Values:    row.Values,
	}, nil
}

func (r *QueryRouter) createObligationSQLite(ctx context.Context, params UnifiedCreateObligationParams) (UnifiedCreateObligationRow, error) {
	// Generate UUID for obligation
	oblID := uuid.NewString()

	// First, we need to look up the namespace ID if only FQN is provided
	namespaceID := params.NamespaceID
	if namespaceID == "" && params.NamespaceFqn != "" {
		nsRow, err := r.GetNamespace(ctx, UnifiedGetNamespaceParams{Name: params.NamespaceFqn})
		if err != nil {
			return UnifiedCreateObligationRow{}, err
		}
		namespaceID = nsRow.ID
	}

	sqliteParams := sqlite.CreateObligationParams{
		ID:          oblID,
		NamespaceID: namespaceID,
		Name:        params.Name,
	}
	if params.Metadata != nil {
		sqliteParams.Metadata = sql.NullString{String: string(params.Metadata), Valid: true}
	}

	_, err := r.sqlite.CreateObligation(ctx, sqliteParams)
	if err != nil {
		return UnifiedCreateObligationRow{}, err
	}

	// Create values if provided
	var createdValues []map[string]string
	for _, val := range params.Values {
		valID := uuid.NewString()
		valParams := sqlite.CreateObligationValueParams{
			ID:                     valID,
			ObligationDefinitionID: oblID,
			Value:                  val,
		}
		_, err := r.sqlite.CreateObligationValue(ctx, valParams)
		if err != nil {
			return UnifiedCreateObligationRow{}, err
		}
		createdValues = append(createdValues, map[string]string{"id": valID, "value": val})
	}

	// Now fetch the full obligation to return consistent data
	getRow, err := r.getObligationSQLite(ctx, UnifiedGetObligationParams{ID: oblID})
	if err != nil {
		return UnifiedCreateObligationRow{}, err
	}

	// Build values JSON if we have created values
	var valuesBytes []byte
	if len(createdValues) > 0 {
		valuesBytes, _ = json.Marshal(createdValues)
	} else {
		valuesBytes = []byte("[]")
	}

	return UnifiedCreateObligationRow{
		ID:        getRow.ID,
		Name:      getRow.Name,
		Namespace: getRow.Namespace,
		Metadata:  getRow.Metadata,
		Values:    valuesBytes,
	}, nil
}

// UpdateObligation routes to the appropriate database backend.
func (r *QueryRouter) UpdateObligation(ctx context.Context, id, name string, metadata []byte) (int64, error) {
	if r.IsSQLite() {
		return r.updateObligationSQLite(ctx, id, name, metadata)
	}
	return r.updateObligationPostgres(ctx, id, name, metadata)
}

func (r *QueryRouter) updateObligationPostgres(ctx context.Context, id, name string, metadata []byte) (int64, error) {
	params := updateObligationParams{
		ID:       id,
		Name:     name,
		Metadata: metadata,
	}
	return r.postgres.updateObligation(ctx, params)
}

func (r *QueryRouter) updateObligationSQLite(ctx context.Context, id, name string, metadata []byte) (int64, error) {
	params := sqlite.UpdateObligationParams{
		ID:   id,
		Name: name,
	}
	if metadata != nil {
		params.Metadata = sql.NullString{String: string(metadata), Valid: true}
	}
	return r.sqlite.UpdateObligation(ctx, params)
}

// DeleteObligation routes to the appropriate database backend.
func (r *QueryRouter) DeleteObligation(ctx context.Context, id, namespaceFqn, name string) (string, error) {
	if r.IsSQLite() {
		return r.deleteObligationSQLite(ctx, id)
	}
	return r.deleteObligationPostgres(ctx, id, namespaceFqn, name)
}

func (r *QueryRouter) deleteObligationPostgres(ctx context.Context, id, namespaceFqn, name string) (string, error) {
	params := deleteObligationParams{
		ID:           id,
		NamespaceFqn: namespaceFqn,
		Name:         name,
	}
	return r.postgres.deleteObligation(ctx, params)
}

func (r *QueryRouter) deleteObligationSQLite(ctx context.Context, id string) (string, error) {
	// For SQLite, we need to get the obligation first to return the ID on delete
	// Since SQLite deleteObligation returns rows affected, not ID
	count, err := r.sqlite.DeleteObligation(ctx, id)
	if err != nil {
		return "", err
	}
	if count == 0 {
		return "", nil
	}
	return id, nil
}

// UnifiedGetObligationsByFQNsRow is the unified result for getting obligations by FQNs.
type UnifiedGetObligationsByFQNsRow struct {
	ID        string
	Name      string
	Metadata  []byte
	Namespace []byte
	Values    []byte
}

// GetObligationsByFQNs routes to the appropriate database backend.
func (r *QueryRouter) GetObligationsByFQNs(ctx context.Context, namespaceFqns, names []string) ([]UnifiedGetObligationsByFQNsRow, error) {
	if r.IsSQLite() {
		return r.getObligationsByFQNsSQLite(ctx, namespaceFqns, names)
	}
	return r.getObligationsByFQNsPostgres(ctx, namespaceFqns, names)
}

func (r *QueryRouter) getObligationsByFQNsPostgres(ctx context.Context, namespaceFqns, names []string) ([]UnifiedGetObligationsByFQNsRow, error) {
	params := getObligationsByFQNsParams{
		NamespaceFqns: namespaceFqns,
		Names:         names,
	}

	rows, err := r.postgres.getObligationsByFQNs(ctx, params)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedGetObligationsByFQNsRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedGetObligationsByFQNsRow{
			ID:        row.ID,
			Name:      row.Name,
			Metadata:  row.Metadata,
			Namespace: row.Namespace,
			Values:    row.Values,
		}
	}

	return result, nil
}

func (r *QueryRouter) getObligationsByFQNsSQLite(ctx context.Context, namespaceFqns, names []string) ([]UnifiedGetObligationsByFQNsRow, error) {
	// SQLite version uses json_each, so we need to convert arrays to JSON
	nsFqnsJSON, _ := json.Marshal(namespaceFqns)
	namesJSON, _ := json.Marshal(names)

	rows, err := r.sqlite.GetObligationsByFQNs(ctx, string(nsFqnsJSON), string(namesJSON))
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedGetObligationsByFQNsRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedGetObligationsByFQNsRow{
			ID:        row.ID,
			Name:      row.Name,
			Metadata:  sqliteInterfaceToBytes(row.Metadata),
			Namespace: sqliteInterfaceToBytes(row.Namespace),
			Values:    sqliteInterfaceToBytes(row.Values),
		}
	}

	return result, nil
}

// UnifiedGetObligationValueParams is the unified parameters for getting an obligation value.
type UnifiedGetObligationValueParams struct {
	ID           string
	NamespaceFqn string
	Name         string
	Value        string
}

// UnifiedGetObligationValueRow is the unified result for getting an obligation value.
type UnifiedGetObligationValueRow struct {
	ID           string
	Value        string
	ObligationID string
	Name         string
	Namespace    []byte
	Metadata     []byte
	Triggers     []byte
}

// GetObligationValue routes to the appropriate database backend.
func (r *QueryRouter) GetObligationValue(ctx context.Context, params UnifiedGetObligationValueParams) (UnifiedGetObligationValueRow, error) {
	if r.IsSQLite() {
		return r.getObligationValueSQLite(ctx, params)
	}
	return r.getObligationValuePostgres(ctx, params)
}

func (r *QueryRouter) getObligationValuePostgres(ctx context.Context, params UnifiedGetObligationValueParams) (UnifiedGetObligationValueRow, error) {
	pgParams := getObligationValueParams{
		ID:           params.ID,
		NamespaceFqn: params.NamespaceFqn,
		Name:         params.Name,
		Value:        params.Value,
	}

	row, err := r.postgres.getObligationValue(ctx, pgParams)
	if err != nil {
		return UnifiedGetObligationValueRow{}, err
	}

	return UnifiedGetObligationValueRow{
		ID:           row.ID,
		Value:        row.Value,
		ObligationID: row.ObligationID,
		Name:         row.Name,
		Namespace:    row.Namespace,
		Metadata:     row.Metadata,
		Triggers:     row.Triggers,
	}, nil
}

func (r *QueryRouter) getObligationValueSQLite(ctx context.Context, params UnifiedGetObligationValueParams) (UnifiedGetObligationValueRow, error) {
	sqliteParams := sqlite.GetObligationValueParams{
		ID:           params.ID,
		NamespaceFqn: params.NamespaceFqn,
		Name:         params.Name,
		Value:        params.Value,
	}

	row, err := r.sqlite.GetObligationValue(ctx, sqliteParams)
	if err != nil {
		return UnifiedGetObligationValueRow{}, err
	}

	return UnifiedGetObligationValueRow{
		ID:           row.ID,
		Value:        row.Value,
		ObligationID: row.ObligationID,
		Name:         row.Name,
		Namespace:    sqliteInterfaceToBytes(row.Namespace),
		Metadata:     sqliteInterfaceToBytes(row.Metadata),
		Triggers:     sqliteInterfaceToBytes(row.Triggers),
	}, nil
}

// UnifiedCreateObligationValueParams is the unified parameters for creating an obligation value.
type UnifiedCreateObligationValueParams struct {
	ObligationID string
	NamespaceFqn string
	Name         string
	Value        string
	Metadata     []byte
}

// UnifiedCreateObligationValueRow is the unified result for creating an obligation value.
type UnifiedCreateObligationValueRow struct {
	ID           string
	Name         string
	ObligationID string
	Namespace    []byte
	Metadata     []byte
}

// CreateObligationValue routes to the appropriate database backend.
func (r *QueryRouter) CreateObligationValue(ctx context.Context, params UnifiedCreateObligationValueParams) (UnifiedCreateObligationValueRow, error) {
	if r.IsSQLite() {
		return r.createObligationValueSQLite(ctx, params)
	}
	return r.createObligationValuePostgres(ctx, params)
}

func (r *QueryRouter) createObligationValuePostgres(ctx context.Context, params UnifiedCreateObligationValueParams) (UnifiedCreateObligationValueRow, error) {
	pgParams := createObligationValueParams{
		ID:           params.ObligationID,
		NamespaceFqn: params.NamespaceFqn,
		Name:         params.Name,
		Value:        params.Value,
		Metadata:     params.Metadata,
	}

	row, err := r.postgres.createObligationValue(ctx, pgParams)
	if err != nil {
		return UnifiedCreateObligationValueRow{}, err
	}

	return UnifiedCreateObligationValueRow{
		ID:           row.ID,
		Name:         row.Name,
		ObligationID: row.ObligationID,
		Namespace:    row.Namespace,
		Metadata:     row.Metadata,
	}, nil
}

func (r *QueryRouter) createObligationValueSQLite(ctx context.Context, params UnifiedCreateObligationValueParams) (UnifiedCreateObligationValueRow, error) {
	valID := uuid.NewString()

	// Get obligation ID if only FQN provided
	oblID := params.ObligationID
	if oblID == "" && params.NamespaceFqn != "" && params.Name != "" {
		oblRow, err := r.getObligationSQLite(ctx, UnifiedGetObligationParams{
			NamespaceFqn: params.NamespaceFqn,
			Name:         params.Name,
		})
		if err != nil {
			return UnifiedCreateObligationValueRow{}, err
		}
		oblID = oblRow.ID
	}

	sqliteParams := sqlite.CreateObligationValueParams{
		ID:                     valID,
		ObligationDefinitionID: oblID,
		Value:                  params.Value,
	}
	if params.Metadata != nil {
		sqliteParams.Metadata = sql.NullString{String: string(params.Metadata), Valid: true}
	}

	_, err := r.sqlite.CreateObligationValue(ctx, sqliteParams)
	if err != nil {
		return UnifiedCreateObligationValueRow{}, err
	}

	// Fetch the value to get full data
	valRow, err := r.getObligationValueSQLite(ctx, UnifiedGetObligationValueParams{ID: valID})
	if err != nil {
		return UnifiedCreateObligationValueRow{}, err
	}

	return UnifiedCreateObligationValueRow{
		ID:           valRow.ID,
		Name:         valRow.Name,
		ObligationID: valRow.ObligationID,
		Namespace:    valRow.Namespace,
		Metadata:     valRow.Metadata,
	}, nil
}

// UpdateObligationValue routes to the appropriate database backend.
func (r *QueryRouter) UpdateObligationValue(ctx context.Context, id, value string, metadata []byte) (int64, error) {
	if r.IsSQLite() {
		return r.updateObligationValueSQLite(ctx, id, value, metadata)
	}
	return r.updateObligationValuePostgres(ctx, id, value, metadata)
}

func (r *QueryRouter) updateObligationValuePostgres(ctx context.Context, id, value string, metadata []byte) (int64, error) {
	params := updateObligationValueParams{
		ID:       id,
		Value:    value,
		Metadata: metadata,
	}
	return r.postgres.updateObligationValue(ctx, params)
}

func (r *QueryRouter) updateObligationValueSQLite(ctx context.Context, id, value string, metadata []byte) (int64, error) {
	params := sqlite.UpdateObligationValueParams{
		ID:    id,
		Value: value,
	}
	if metadata != nil {
		params.Metadata = sql.NullString{String: string(metadata), Valid: true}
	}
	return r.sqlite.UpdateObligationValue(ctx, params)
}

// DeleteObligationValue routes to the appropriate database backend.
func (r *QueryRouter) DeleteObligationValue(ctx context.Context, id, namespaceFqn, name, value string) (string, error) {
	if r.IsSQLite() {
		return r.deleteObligationValueSQLite(ctx, id)
	}
	return r.deleteObligationValuePostgres(ctx, id, namespaceFqn, name, value)
}

func (r *QueryRouter) deleteObligationValuePostgres(ctx context.Context, id, namespaceFqn, name, value string) (string, error) {
	params := deleteObligationValueParams{
		ID:           id,
		NamespaceFqn: namespaceFqn,
		Name:         name,
		Value:        value,
	}
	return r.postgres.deleteObligationValue(ctx, params)
}

func (r *QueryRouter) deleteObligationValueSQLite(ctx context.Context, id string) (string, error) {
	count, err := r.sqlite.DeleteObligationValue(ctx, id)
	if err != nil {
		return "", err
	}
	if count == 0 {
		return "", nil
	}
	return id, nil
}

// UnifiedGetObligationValuesByFQNsRow is the unified result for getting obligation values by FQNs.
type UnifiedGetObligationValuesByFQNsRow struct {
	ID           string
	Value        string
	Metadata     []byte
	ObligationID string
	Name         string
	Namespace    []byte
	Triggers     []byte
}

// GetObligationValuesByFQNs routes to the appropriate database backend.
func (r *QueryRouter) GetObligationValuesByFQNs(ctx context.Context, namespaceFqns, names, values []string) ([]UnifiedGetObligationValuesByFQNsRow, error) {
	if r.IsSQLite() {
		return r.getObligationValuesByFQNsSQLite(ctx, namespaceFqns, names, values)
	}
	return r.getObligationValuesByFQNsPostgres(ctx, namespaceFqns, names, values)
}

func (r *QueryRouter) getObligationValuesByFQNsPostgres(ctx context.Context, namespaceFqns, names, values []string) ([]UnifiedGetObligationValuesByFQNsRow, error) {
	params := getObligationValuesByFQNsParams{
		NamespaceFqns: namespaceFqns,
		Names:         names,
		Values:        values,
	}

	rows, err := r.postgres.getObligationValuesByFQNs(ctx, params)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedGetObligationValuesByFQNsRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedGetObligationValuesByFQNsRow{
			ID:           row.ID,
			Value:        row.Value,
			Metadata:     row.Metadata,
			ObligationID: row.ObligationID,
			Name:         row.Name,
			Namespace:    row.Namespace,
			Triggers:     row.Triggers,
		}
	}

	return result, nil
}

func (r *QueryRouter) getObligationValuesByFQNsSQLite(ctx context.Context, namespaceFqns, names, values []string) ([]UnifiedGetObligationValuesByFQNsRow, error) {
	nsFqnsJSON, _ := json.Marshal(namespaceFqns)
	namesJSON, _ := json.Marshal(names)
	valuesJSON, _ := json.Marshal(values)

	rows, err := r.sqlite.GetObligationValuesByFQNs(ctx, string(nsFqnsJSON), string(namesJSON), string(valuesJSON))
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedGetObligationValuesByFQNsRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedGetObligationValuesByFQNsRow{
			ID:           row.ID,
			Value:        row.Value,
			Metadata:     sqliteInterfaceToBytes(row.Metadata),
			ObligationID: row.ObligationID,
			Name:         row.Name,
			Namespace:    sqliteInterfaceToBytes(row.Namespace),
		}
	}

	return result, nil
}

// UnifiedListObligationTriggersParams is the unified parameters for listing obligation triggers.
type UnifiedListObligationTriggersParams struct {
	NamespaceID  string
	NamespaceFqn string
	Limit        int32
	Offset       int32
}

// UnifiedListObligationTriggersRow is the unified result for listing obligation triggers.
type UnifiedListObligationTriggersRow struct {
	Trigger  []byte
	Metadata []byte
	Total    int64
}

// ListObligationTriggers routes to the appropriate database backend.
func (r *QueryRouter) ListObligationTriggers(ctx context.Context, params UnifiedListObligationTriggersParams) ([]UnifiedListObligationTriggersRow, error) {
	if r.IsSQLite() {
		return r.listObligationTriggersSQLite(ctx, params)
	}
	return r.listObligationTriggersPostgres(ctx, params)
}

func (r *QueryRouter) listObligationTriggersPostgres(ctx context.Context, params UnifiedListObligationTriggersParams) ([]UnifiedListObligationTriggersRow, error) {
	pgParams := listObligationTriggersParams{
		NamespaceID:  params.NamespaceID,
		NamespaceFqn: params.NamespaceFqn,
		Limit:        params.Limit,
		Offset:       params.Offset,
	}

	rows, err := r.postgres.listObligationTriggers(ctx, pgParams)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListObligationTriggersRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListObligationTriggersRow{
			Trigger:  row.Trigger,
			Metadata: row.Metadata,
			Total:    row.Total,
		}
	}

	return result, nil
}

func (r *QueryRouter) listObligationTriggersSQLite(ctx context.Context, params UnifiedListObligationTriggersParams) ([]UnifiedListObligationTriggersRow, error) {
	sqliteParams := sqlite.ListObligationTriggersParams{
		NamespaceID:  params.NamespaceID,
		NamespaceFqn: params.NamespaceFqn,
		Limit:        int64(params.Limit),
		Offset:       int64(params.Offset),
	}

	rows, err := r.sqlite.ListObligationTriggers(ctx, sqliteParams)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListObligationTriggersRow, len(rows))
	for i, row := range rows {
		// Build trigger JSON from SQLite flattened structure
		trigger := map[string]interface{}{
			"id": row.ID,
			"obligation_value": map[string]interface{}{
				"id":    row.ObligationValueID,
				"value": row.ObligationValueValue,
				"obligation": map[string]interface{}{
					"id":   row.ObligationID,
					"name": row.ObligationName,
					"namespace": map[string]interface{}{
						"id":   row.NamespaceID,
						"name": row.NamespaceName,
						"fqn":  row.NamespaceFqn,
					},
				},
			},
			"action": map[string]interface{}{
				"id":   row.ActionID,
				"name": row.ActionName,
			},
			"attribute_value": map[string]interface{}{
				"id":    row.AttributeValueID,
				"value": row.AttributeValueValue,
				"fqn":   row.AttributeValueFqn,
			},
		}
		if row.ClientID.Valid {
			trigger["context"] = []map[string]interface{}{
				{"pep": map[string]interface{}{"client_id": row.ClientID.String}},
			}
		} else {
			trigger["context"] = []interface{}{}
		}

		triggerJSON, _ := json.Marshal(trigger)

		// Build metadata from row fields
		metadata := map[string]interface{}{}
		if row.Metadata.Valid {
			json.Unmarshal([]byte(row.Metadata.String), &metadata)
		}
		metadata["created_at"] = row.CreatedAt
		metadata["updated_at"] = row.UpdatedAt
		metadataJSON, _ := json.Marshal(metadata)

		result[i] = UnifiedListObligationTriggersRow{
			Trigger:  triggerJSON,
			Metadata: metadataJSON,
			Total:    row.Total,
		}
	}

	return result, nil
}

// UnifiedCreateObligationTriggerParams is the unified parameters for creating an obligation trigger.
type UnifiedCreateObligationTriggerParams struct {
	ObligationValueID string
	ActionID          string
	ActionName        string
	AttributeValueID  string
	AttributeValueFqn string
	Metadata          []byte
	ClientID          string
}

// UnifiedCreateObligationTriggerRow is the unified result for creating an obligation trigger.
type UnifiedCreateObligationTriggerRow struct {
	Metadata []byte
	Trigger  []byte
}

// CreateObligationTrigger routes to the appropriate database backend.
func (r *QueryRouter) CreateObligationTrigger(ctx context.Context, params UnifiedCreateObligationTriggerParams) (UnifiedCreateObligationTriggerRow, error) {
	if r.IsSQLite() {
		return r.createObligationTriggerSQLite(ctx, params)
	}
	return r.createObligationTriggerPostgres(ctx, params)
}

func (r *QueryRouter) createObligationTriggerPostgres(ctx context.Context, params UnifiedCreateObligationTriggerParams) (UnifiedCreateObligationTriggerRow, error) {
	pgParams := createObligationTriggerParams{
		ObligationValueID: params.ObligationValueID,
		ActionID:          params.ActionID,
		ActionName:        params.ActionName,
		AttributeValueID:  params.AttributeValueID,
		AttributeValueFqn: params.AttributeValueFqn,
		Metadata:          params.Metadata,
		ClientID:          params.ClientID,
	}

	row, err := r.postgres.createObligationTrigger(ctx, pgParams)
	if err != nil {
		return UnifiedCreateObligationTriggerRow{}, err
	}

	return UnifiedCreateObligationTriggerRow{
		Metadata: row.Metadata,
		Trigger:  row.Trigger,
	}, nil
}

func (r *QueryRouter) createObligationTriggerSQLite(ctx context.Context, params UnifiedCreateObligationTriggerParams) (UnifiedCreateObligationTriggerRow, error) {
	triggerID := uuid.NewString()

	// Get action ID if only name provided
	actionID := params.ActionID
	if actionID == "" && params.ActionName != "" {
		// Query for action by name
		actionRow, err := r.sqlite.GetAction(ctx, sqlite.GetActionParams{
			Name: params.ActionName,
		})
		if err != nil {
			return UnifiedCreateObligationTriggerRow{}, err
		}
		actionID = actionRow.ID
	}

	// Get attribute value ID if only FQN provided
	attrValueID := params.AttributeValueID
	if attrValueID == "" && params.AttributeValueFqn != "" {
		// Query for attribute value by FQN using raw SQL since there's no direct method
		var valueID string
		err := r.SQLExecutor().QueryRowContext(ctx,
			`SELECT av.id FROM attribute_values av
			 JOIN attribute_fqns fqns ON fqns.value_id = av.id
			 WHERE fqns.fqn = ?`,
			params.AttributeValueFqn,
		).Scan(&valueID)
		if err != nil {
			return UnifiedCreateObligationTriggerRow{}, err
		}
		attrValueID = valueID
	}

	sqliteParams := sqlite.CreateObligationTriggerParams{
		ID:                triggerID,
		ObligationValueID: params.ObligationValueID,
		ActionID:          actionID,
		AttributeValueID:  attrValueID,
		ClientID:          params.ClientID,
	}
	if params.Metadata != nil {
		sqliteParams.Metadata = sql.NullString{String: string(params.Metadata), Valid: true}
	}

	_, err := r.sqlite.CreateObligationTrigger(ctx, sqliteParams)
	if err != nil {
		return UnifiedCreateObligationTriggerRow{}, err
	}

	// Build full trigger response by fetching related data
	// Get action info
	actionRow, _ := r.sqlite.GetAction(ctx, sqlite.GetActionParams{ID: actionID})

	// Get attribute value info with FQN
	var avID, avValue, avFqn string
	r.SQLExecutor().QueryRowContext(ctx,
		`SELECT av.id, av.value, COALESCE(fqns.fqn, '') as fqn
		 FROM attribute_values av
		 LEFT JOIN attribute_fqns fqns ON fqns.value_id = av.id
		 WHERE av.id = ?`,
		attrValueID,
	).Scan(&avID, &avValue, &avFqn)

	// Get obligation value info
	oblValRow, _ := r.getObligationValueSQLite(ctx, UnifiedGetObligationValueParams{ID: params.ObligationValueID})

	// Build trigger JSON matching postgres format
	trigger := map[string]interface{}{
		"id": triggerID,
		"obligation_value": map[string]interface{}{
			"id":    params.ObligationValueID,
			"value": oblValRow.Value,
			"obligation": map[string]interface{}{
				"id":   oblValRow.ObligationID,
				"name": oblValRow.Name,
				"namespace": func() interface{} {
					var ns map[string]interface{}
					json.Unmarshal(oblValRow.Namespace, &ns)
					return ns
				}(),
			},
		},
		"action": map[string]interface{}{
			"id":   actionRow.ID,
			"name": actionRow.Name,
		},
		"attribute_value": map[string]interface{}{
			"id":    avID,
			"value": avValue,
			"fqn":   avFqn,
		},
	}
	if params.ClientID != "" {
		trigger["context"] = []map[string]interface{}{
			{"pep": map[string]interface{}{"client_id": params.ClientID}},
		}
	} else {
		trigger["context"] = []interface{}{}
	}

	triggerJSON, _ := json.Marshal(trigger)

	metadata := map[string]interface{}{}
	if params.Metadata != nil {
		json.Unmarshal(params.Metadata, &metadata)
	}
	metadataJSON, _ := json.Marshal(metadata)

	return UnifiedCreateObligationTriggerRow{
		Metadata: metadataJSON,
		Trigger:  triggerJSON,
	}, nil
}

// DeleteObligationTrigger routes to the appropriate database backend.
func (r *QueryRouter) DeleteObligationTrigger(ctx context.Context, id string) (string, error) {
	if r.IsSQLite() {
		return r.deleteObligationTriggerSQLite(ctx, id)
	}
	return r.deleteObligationTriggerPostgres(ctx, id)
}

func (r *QueryRouter) deleteObligationTriggerPostgres(ctx context.Context, id string) (string, error) {
	return r.postgres.deleteObligationTrigger(ctx, id)
}

func (r *QueryRouter) deleteObligationTriggerSQLite(ctx context.Context, id string) (string, error) {
	count, err := r.sqlite.DeleteObligationTrigger(ctx, id)
	if err != nil {
		return "", err
	}
	if count == 0 {
		return "", nil
	}
	return id, nil
}

// DeleteAllObligationTriggersForValue routes to the appropriate database backend.
func (r *QueryRouter) DeleteAllObligationTriggersForValue(ctx context.Context, obligationValueID string) (int64, error) {
	if r.IsSQLite() {
		return r.sqlite.DeleteAllObligationTriggersForValue(ctx, obligationValueID)
	}
	return r.postgres.deleteAllObligationTriggersForValue(ctx, obligationValueID)
}

// sqliteInterfaceToBytes converts SQLite's interface{} to []byte
func sqliteInterfaceToBytes(v interface{}) []byte {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case []byte:
		return val
	case string:
		return []byte(val)
	default:
		// Try to marshal as JSON
		b, _ := json.Marshal(v)
		return b
	}
}
