package db

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/opentdf/platform/service/policy/db/sqlite"
)

// UnifiedListNamespacesParams is the unified parameters for listing namespaces.
type UnifiedListNamespacesParams struct {
	Active *bool // nil = any, true/false = filter by active state
	Limit  int32
	Offset int32
}

// UnifiedListNamespacesRow is the unified result row for listing namespaces.
type UnifiedListNamespacesRow struct {
	Total    int64
	ID       string
	Name     string
	Active   bool
	Fqn      pgtype.Text
	Metadata []byte
}

// ListNamespaces routes to the appropriate database backend and normalizes the result.
func (r *QueryRouter) ListNamespaces(ctx context.Context, params UnifiedListNamespacesParams) ([]UnifiedListNamespacesRow, error) {
	if r.IsSQLite() {
		return r.listNamespacesSQLite(ctx, params)
	}
	return r.listNamespacesPostgres(ctx, params)
}

func (r *QueryRouter) listNamespacesPostgres(ctx context.Context, params UnifiedListNamespacesParams) ([]UnifiedListNamespacesRow, error) {
	pgParams := listNamespacesParams{
		Active: pgtype.Bool{Valid: false},
		Limit:  params.Limit,
		Offset: params.Offset,
	}

	if params.Active != nil {
		pgParams.Active = pgtype.Bool{Bool: *params.Active, Valid: true}
	}

	rows, err := r.postgres.listNamespaces(ctx, pgParams)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListNamespacesRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListNamespacesRow{
			Total:    row.Total,
			ID:       row.ID,
			Name:     row.Name,
			Active:   row.Active,
			Fqn:      row.Fqn,
			Metadata: row.Metadata,
		}
	}

	return result, nil
}

func (r *QueryRouter) listNamespacesSQLite(ctx context.Context, params UnifiedListNamespacesParams) ([]UnifiedListNamespacesRow, error) {
	var activeFilter interface{}
	if params.Active != nil {
		// SQLite uses 0/1 for booleans
		if *params.Active {
			activeFilter = int64(1)
		} else {
			activeFilter = int64(0)
		}
	}

	sqliteParams := sqlite.ListNamespacesParams{
		Active: activeFilter,
		Limit:  int64(params.Limit),
		Offset: int64(params.Offset),
	}

	rows, err := r.sqlite.ListNamespaces(ctx, sqliteParams)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListNamespacesRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListNamespacesRow{
			Total:  row.Total,
			ID:     row.ID,
			Name:   row.Name,
			Active: row.Active != 0,
			Fqn: pgtype.Text{
				String: row.Fqn.String,
				Valid:  row.Fqn.Valid,
			},
			Metadata: sqliteMetadataToBytes(row.Metadata),
		}
	}

	return result, nil
}

// sqliteMetadataToBytes converts SQLite's interface{} metadata to []byte
func sqliteMetadataToBytes(metadata interface{}) []byte {
	if metadata == nil {
		return nil
	}
	switch v := metadata.(type) {
	case []byte:
		return v
	case string:
		return []byte(v)
	default:
		return nil
	}
}

// interfaceToBytes converts interface{} values (from pgx JSON scanning) to []byte
// For PostgreSQL, JSONB is scanned into interface{} as Go types (maps/slices),
// so we need to re-marshal them to JSON bytes.
func interfaceToBytes(v interface{}) []byte {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case []byte:
		return val
	case string:
		return []byte(val)
	default:
		// For Postgres JSONB, the value is parsed into Go types, re-marshal to JSON
		b, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		return b
	}
}

// UnifiedGetNamespaceParams is the unified parameters for getting a namespace.
type UnifiedGetNamespaceParams struct {
	ID   string // UUID as string (empty if not used)
	Name string // FQN (empty if not used)
}

// UnifiedGetNamespaceRow is the unified result for getting a namespace.
type UnifiedGetNamespaceRow struct {
	ID       string
	Name     string
	Active   bool
	Fqn      pgtype.Text
	Metadata []byte
	Grants   []byte
	Keys     []byte
	Certs    []byte
}

// GetNamespace routes to the appropriate database backend and normalizes the result.
func (r *QueryRouter) GetNamespace(ctx context.Context, params UnifiedGetNamespaceParams) (UnifiedGetNamespaceRow, error) {
	if r.IsSQLite() {
		return r.getNamespaceSQLite(ctx, params)
	}
	return r.getNamespacePostgres(ctx, params)
}

func (r *QueryRouter) getNamespacePostgres(ctx context.Context, params UnifiedGetNamespaceParams) (UnifiedGetNamespaceRow, error) {
	pgParams := getNamespaceParams{}
	if params.ID != "" {
		pgParams.ID = pgtypeUUID(params.ID)
	}
	if params.Name != "" {
		pgParams.Name = pgtypeText(params.Name)
	}

	row, err := r.postgres.getNamespace(ctx, pgParams)
	if err != nil {
		return UnifiedGetNamespaceRow{}, err
	}

	return UnifiedGetNamespaceRow{
		ID:       row.ID,
		Name:     row.Name,
		Active:   row.Active,
		Fqn:      row.Fqn,
		Metadata: row.Metadata,
		Grants:   row.Grants,
		Keys:     row.Keys,
		Certs:    row.Certs,
	}, nil
}

func (r *QueryRouter) getNamespaceSQLite(ctx context.Context, params UnifiedGetNamespaceParams) (UnifiedGetNamespaceRow, error) {
	var idParam, nameParam interface{}
	if params.ID != "" {
		idParam = params.ID
	}
	if params.Name != "" {
		nameParam = params.Name
	}

	sqliteParams := sqlite.GetNamespaceParams{
		ID:   idParam,
		Name: nameParam,
	}

	row, err := r.sqlite.GetNamespace(ctx, sqliteParams)
	if err != nil {
		return UnifiedGetNamespaceRow{}, err
	}

	return UnifiedGetNamespaceRow{
		ID:     row.ID,
		Name:   row.Name,
		Active: row.Active != 0,
		Fqn: pgtype.Text{
			String: row.Fqn.String,
			Valid:  row.Fqn.Valid,
		},
		Metadata: sqliteMetadataToBytes(row.Metadata),
		Grants:   sqliteMetadataToBytes(row.Grants),
		Keys:     sqliteMetadataToBytes(row.Keys),
		Certs:    sqliteMetadataToBytes(row.Certs),
	}, nil
}

// UpdateNamespace routes to the appropriate database backend.
func (r *QueryRouter) UpdateNamespace(ctx context.Context, id string, name *string, active *bool, metadata []byte) (int64, error) {
	if r.IsSQLite() {
		return r.updateNamespaceSQLite(ctx, id, name, active, metadata)
	}
	return r.updateNamespacePostgres(ctx, id, name, active, metadata)
}

func (r *QueryRouter) updateNamespacePostgres(ctx context.Context, id string, name *string, active *bool, metadata []byte) (int64, error) {
	params := updateNamespaceParams{
		ID: id,
	}
	if name != nil {
		params.Name = pgtypeText(*name)
	}
	if active != nil {
		params.Active = pgtypeBool(*active)
	}
	if metadata != nil {
		params.Metadata = metadata
	}
	return r.postgres.updateNamespace(ctx, params)
}

func (r *QueryRouter) updateNamespaceSQLite(ctx context.Context, id string, name *string, active *bool, metadata []byte) (int64, error) {
	params := sqlite.UpdateNamespaceParams{
		ID: id,
	}
	if name != nil {
		params.Name = sql.NullString{String: *name, Valid: true}
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
	return r.sqlite.UpdateNamespace(ctx, params)
}

// UnifiedCreateNamespaceParams is the unified parameters for creating a namespace.
type UnifiedCreateNamespaceParams struct {
	Name     string
	Metadata []byte
}

// CreateNamespace routes to the appropriate database backend and returns the created ID.
func (r *QueryRouter) CreateNamespace(ctx context.Context, params UnifiedCreateNamespaceParams) (string, error) {
	if r.IsSQLite() {
		return r.createNamespaceSQLite(ctx, params)
	}
	return r.createNamespacePostgres(ctx, params)
}

func (r *QueryRouter) createNamespacePostgres(ctx context.Context, params UnifiedCreateNamespaceParams) (string, error) {
	pgParams := createNamespaceParams{
		Name:     params.Name,
		Metadata: params.Metadata,
	}
	return r.postgres.createNamespace(ctx, pgParams)
}

func (r *QueryRouter) createNamespaceSQLite(ctx context.Context, params UnifiedCreateNamespaceParams) (string, error) {
	id := uuid.NewString()
	sqliteParams := sqlite.CreateNamespaceParams{
		ID:   id,
		Name: params.Name,
	}
	if params.Metadata != nil {
		sqliteParams.Metadata = sql.NullString{String: string(params.Metadata), Valid: true}
	}
	_, err := r.sqlite.CreateNamespace(ctx, sqliteParams)
	if err != nil {
		return "", err
	}
	return id, nil
}

// DeleteNamespace routes to the appropriate database backend.
func (r *QueryRouter) DeleteNamespace(ctx context.Context, id string) (int64, error) {
	if r.IsSQLite() {
		return r.sqlite.DeleteNamespace(ctx, id)
	}
	return r.postgres.deleteNamespace(ctx, id)
}

// RemoveKeyAccessServerFromNamespace routes to the appropriate database backend.
func (r *QueryRouter) RemoveKeyAccessServerFromNamespace(ctx context.Context, namespaceID, keyAccessServerID string) (int64, error) {
	if r.IsSQLite() {
		return r.sqlite.RemoveKeyAccessServerFromNamespace(ctx, sqlite.RemoveKeyAccessServerFromNamespaceParams{
			NamespaceID:       namespaceID,
			KeyAccessServerID: keyAccessServerID,
		})
	}
	return r.postgres.removeKeyAccessServerFromNamespace(ctx, removeKeyAccessServerFromNamespaceParams{
		NamespaceID:       namespaceID,
		KeyAccessServerID: keyAccessServerID,
	})
}

// UnifiedNamespaceKeyRow is the unified result for namespace public key operations.
type UnifiedNamespaceKeyRow struct {
	NamespaceID          string
	KeyAccessServerKeyID string
}

// AssignPublicKeyToNamespace routes to the appropriate database backend.
func (r *QueryRouter) AssignPublicKeyToNamespace(ctx context.Context, namespaceID, keyAccessServerKeyID string) (UnifiedNamespaceKeyRow, error) {
	if r.IsSQLite() {
		row, err := r.sqlite.AssignPublicKeyToNamespace(ctx, sqlite.AssignPublicKeyToNamespaceParams{
			NamespaceID:          namespaceID,
			KeyAccessServerKeyID: keyAccessServerKeyID,
		})
		if err != nil {
			return UnifiedNamespaceKeyRow{}, err
		}
		return UnifiedNamespaceKeyRow{
			NamespaceID:          row.NamespaceID,
			KeyAccessServerKeyID: row.KeyAccessServerKeyID,
		}, nil
	}
	row, err := r.postgres.assignPublicKeyToNamespace(ctx, assignPublicKeyToNamespaceParams{
		NamespaceID:          namespaceID,
		KeyAccessServerKeyID: keyAccessServerKeyID,
	})
	if err != nil {
		return UnifiedNamespaceKeyRow{}, err
	}
	return UnifiedNamespaceKeyRow{
		NamespaceID:          row.NamespaceID,
		KeyAccessServerKeyID: row.KeyAccessServerKeyID,
	}, nil
}

// RemovePublicKeyFromNamespace routes to the appropriate database backend.
func (r *QueryRouter) RemovePublicKeyFromNamespace(ctx context.Context, namespaceID, keyAccessServerKeyID string) (int64, error) {
	if r.IsSQLite() {
		return r.sqlite.RemovePublicKeyFromNamespace(ctx, sqlite.RemovePublicKeyFromNamespaceParams{
			NamespaceID:          namespaceID,
			KeyAccessServerKeyID: keyAccessServerKeyID,
		})
	}
	return r.postgres.removePublicKeyFromNamespace(ctx, removePublicKeyFromNamespaceParams{
		NamespaceID:          namespaceID,
		KeyAccessServerKeyID: keyAccessServerKeyID,
	})
}

// CreateCertificate routes to the appropriate database backend.
func (r *QueryRouter) CreateCertificate(ctx context.Context, pem string, metadata []byte) (string, error) {
	if r.IsSQLite() {
		id := uuid.NewString()
		var metadataParam sql.NullString
		if metadata != nil {
			metadataParam = sql.NullString{String: string(metadata), Valid: true}
		}
		_, err := r.sqlite.CreateCertificate(ctx, sqlite.CreateCertificateParams{
			ID:       id,
			Pem:      pem,
			Metadata: metadataParam,
		})
		if err != nil {
			return "", err
		}
		return id, nil
	}
	return r.postgres.createCertificate(ctx, createCertificateParams{
		Pem:      pem,
		Metadata: metadata,
	})
}

// UnifiedCertificateRow is the unified result for certificate operations.
type UnifiedCertificateRow struct {
	ID       string
	Pem      string
	Metadata []byte
}

// GetCertificate routes to the appropriate database backend.
func (r *QueryRouter) GetCertificate(ctx context.Context, id string) (UnifiedCertificateRow, error) {
	if r.IsSQLite() {
		row, err := r.sqlite.GetCertificate(ctx, id)
		if err != nil {
			return UnifiedCertificateRow{}, err
		}
		return UnifiedCertificateRow{
			ID:       row.ID,
			Pem:      row.Pem,
			Metadata: sqliteMetadataToBytes(row.Metadata),
		}, nil
	}
	row, err := r.postgres.getCertificate(ctx, id)
	if err != nil {
		return UnifiedCertificateRow{}, err
	}
	return UnifiedCertificateRow{
		ID:       row.ID,
		Pem:      row.Pem,
		Metadata: row.Metadata,
	}, nil
}

// GetCertificateByPEM routes to the appropriate database backend.
func (r *QueryRouter) GetCertificateByPEM(ctx context.Context, pem string) (UnifiedCertificateRow, error) {
	if r.IsSQLite() {
		row, err := r.sqlite.GetCertificateByPEM(ctx, pem)
		if err != nil {
			return UnifiedCertificateRow{}, err
		}
		return UnifiedCertificateRow{
			ID:       row.ID,
			Pem:      row.Pem,
			Metadata: sqliteMetadataToBytes(row.Metadata),
		}, nil
	}
	row, err := r.postgres.getCertificateByPEM(ctx, pem)
	if err != nil {
		return UnifiedCertificateRow{}, err
	}
	return UnifiedCertificateRow{
		ID:       row.ID,
		Pem:      row.Pem,
		Metadata: row.Metadata,
	}, nil
}

// DeleteCertificate routes to the appropriate database backend.
func (r *QueryRouter) DeleteCertificate(ctx context.Context, id string) (int64, error) {
	if r.IsSQLite() {
		return r.sqlite.DeleteCertificate(ctx, id)
	}
	return r.postgres.deleteCertificate(ctx, id)
}

// UnifiedNamespaceCertificateRow is the unified result for namespace certificate operations.
type UnifiedNamespaceCertificateRow struct {
	NamespaceID   string
	CertificateID string
}

// AssignCertificateToNamespace routes to the appropriate database backend.
func (r *QueryRouter) AssignCertificateToNamespace(ctx context.Context, namespaceID, certificateID string) (UnifiedNamespaceCertificateRow, error) {
	if r.IsSQLite() {
		row, err := r.sqlite.AssignCertificateToNamespace(ctx, sqlite.AssignCertificateToNamespaceParams{
			NamespaceID:   namespaceID,
			CertificateID: certificateID,
		})
		if err != nil {
			return UnifiedNamespaceCertificateRow{}, err
		}
		return UnifiedNamespaceCertificateRow{
			NamespaceID:   row.NamespaceID,
			CertificateID: row.CertificateID,
		}, nil
	}
	row, err := r.postgres.assignCertificateToNamespace(ctx, assignCertificateToNamespaceParams{
		NamespaceID:   namespaceID,
		CertificateID: certificateID,
	})
	if err != nil {
		return UnifiedNamespaceCertificateRow{}, err
	}
	return UnifiedNamespaceCertificateRow{
		NamespaceID:   row.NamespaceID,
		CertificateID: row.CertificateID,
	}, nil
}

// RemoveCertificateFromNamespace routes to the appropriate database backend.
func (r *QueryRouter) RemoveCertificateFromNamespace(ctx context.Context, namespaceID, certificateID string) (int64, error) {
	if r.IsSQLite() {
		return r.sqlite.RemoveCertificateFromNamespace(ctx, sqlite.RemoveCertificateFromNamespaceParams{
			NamespaceID:   namespaceID,
			CertificateID: certificateID,
		})
	}
	return r.postgres.removeCertificateFromNamespace(ctx, removeCertificateFromNamespaceParams{
		NamespaceID:   namespaceID,
		CertificateID: certificateID,
	})
}

// CountCertificateNamespaceAssignments routes to the appropriate database backend.
func (r *QueryRouter) CountCertificateNamespaceAssignments(ctx context.Context, certificateID string) (int64, error) {
	if r.IsSQLite() {
		return r.sqlite.CountCertificateNamespaceAssignments(ctx, certificateID)
	}
	return r.postgres.countCertificateNamespaceAssignments(ctx, certificateID)
}
