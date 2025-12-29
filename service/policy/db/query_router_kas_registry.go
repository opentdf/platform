package db

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/opentdf/platform/service/policy/db/sqlite"
)

// ----------------------------------------------------------------
// Key Access Server Registry Routing
// ----------------------------------------------------------------

// UnifiedListKeyAccessServersParams is the unified parameters for listing KAS.
type UnifiedListKeyAccessServersParams struct {
	Limit  int32
	Offset int32
}

// UnifiedListKeyAccessServersRow is the unified result row for listing KAS.
type UnifiedListKeyAccessServersRow struct {
	ID         string
	Uri        string
	PublicKey  []byte
	KasName    pgtype.Text
	SourceType pgtype.Text
	Metadata   []byte
	Keys       []byte
	Total      int64
}

// ListKeyAccessServers routes to the appropriate database backend.
func (r *QueryRouter) ListKeyAccessServers(ctx context.Context, params UnifiedListKeyAccessServersParams) ([]UnifiedListKeyAccessServersRow, error) {
	if r.IsSQLite() {
		return r.listKeyAccessServersSQLite(ctx, params)
	}
	return r.listKeyAccessServersPostgres(ctx, params)
}

func (r *QueryRouter) listKeyAccessServersPostgres(ctx context.Context, params UnifiedListKeyAccessServersParams) ([]UnifiedListKeyAccessServersRow, error) {
	rows, err := r.postgres.listKeyAccessServers(ctx, listKeyAccessServersParams{
		Offset: params.Offset,
		Limit:  params.Limit,
	})
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListKeyAccessServersRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListKeyAccessServersRow{
			ID:         row.ID,
			Uri:        row.Uri,
			PublicKey:  row.PublicKey,
			KasName:    row.KasName,
			SourceType: row.SourceType,
			Metadata:   row.Metadata,
			Keys:       row.Keys,
			Total:      row.Total,
		}
	}
	return result, nil
}

func (r *QueryRouter) listKeyAccessServersSQLite(ctx context.Context, params UnifiedListKeyAccessServersParams) ([]UnifiedListKeyAccessServersRow, error) {
	rows, err := r.sqlite.ListKeyAccessServers(ctx, sqlite.ListKeyAccessServersParams{
		Offset: int64(params.Offset),
		Limit:  int64(params.Limit),
	})
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListKeyAccessServersRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListKeyAccessServersRow{
			ID:         row.ID,
			Uri:        row.Uri,
			PublicKey:  []byte(row.PublicKey),
			KasName:    pgtype.Text{String: row.KasName.String, Valid: row.KasName.Valid},
			SourceType: pgtype.Text{String: row.SourceType.String, Valid: row.SourceType.Valid},
			Metadata:   sqliteMetadataToBytes(row.Metadata),
			Keys:       sqliteMetadataToBytes(row.Keys),
			Total:      row.Total,
		}
	}
	return result, nil
}

// UnifiedGetKeyAccessServerParams is the unified parameters for getting a KAS.
type UnifiedGetKeyAccessServerParams struct {
	ID   string
	Name string
	Uri  string
}

// UnifiedGetKeyAccessServerRow is the unified result for getting a KAS.
type UnifiedGetKeyAccessServerRow struct {
	ID         string
	Uri        string
	PublicKey  []byte
	Name       pgtype.Text
	SourceType pgtype.Text
	Metadata   []byte
	Keys       []byte
}

// GetKeyAccessServer routes to the appropriate database backend.
func (r *QueryRouter) GetKeyAccessServer(ctx context.Context, params UnifiedGetKeyAccessServerParams) (UnifiedGetKeyAccessServerRow, error) {
	if r.IsSQLite() {
		return r.getKeyAccessServerSQLite(ctx, params)
	}
	return r.getKeyAccessServerPostgres(ctx, params)
}

func (r *QueryRouter) getKeyAccessServerPostgres(ctx context.Context, params UnifiedGetKeyAccessServerParams) (UnifiedGetKeyAccessServerRow, error) {
	pgParams := getKeyAccessServerParams{}
	if params.ID != "" {
		pgParams.ID = pgtypeUUID(params.ID)
	}
	if params.Name != "" {
		pgParams.Name = pgtypeText(params.Name)
	}
	if params.Uri != "" {
		pgParams.Uri = pgtypeText(params.Uri)
	}

	row, err := r.postgres.getKeyAccessServer(ctx, pgParams)
	if err != nil {
		return UnifiedGetKeyAccessServerRow{}, err
	}

	return UnifiedGetKeyAccessServerRow{
		ID:         row.ID,
		Uri:        row.Uri,
		PublicKey:  row.PublicKey,
		Name:       row.Name,
		SourceType: row.SourceType,
		Metadata:   row.Metadata,
		Keys:       row.Keys,
	}, nil
}

func (r *QueryRouter) getKeyAccessServerSQLite(ctx context.Context, params UnifiedGetKeyAccessServerParams) (UnifiedGetKeyAccessServerRow, error) {
	var idParam, nameParam, uriParam interface{}
	if params.ID != "" {
		idParam = params.ID
	}
	if params.Name != "" {
		nameParam = params.Name
	}
	if params.Uri != "" {
		uriParam = params.Uri
	}

	row, err := r.sqlite.GetKeyAccessServer(ctx, sqlite.GetKeyAccessServerParams{
		ID:   idParam,
		Name: nameParam,
		Uri:  uriParam,
	})
	if err != nil {
		return UnifiedGetKeyAccessServerRow{}, err
	}

	return UnifiedGetKeyAccessServerRow{
		ID:         row.ID,
		Uri:        row.Uri,
		PublicKey:  []byte(row.PublicKey),
		Name:       pgtype.Text{String: row.Name.String, Valid: row.Name.Valid},
		SourceType: pgtype.Text{String: row.SourceType.String, Valid: row.SourceType.Valid},
		Metadata:   sqliteMetadataToBytes(row.Metadata),
		Keys:       sqliteMetadataToBytes(row.Keys),
	}, nil
}

// UnifiedCreateKeyAccessServerParams is the unified parameters for creating a KAS.
type UnifiedCreateKeyAccessServerParams struct {
	Uri        string
	PublicKey  []byte
	Name       string
	Metadata   []byte
	SourceType string
}

// CreateKeyAccessServer routes to the appropriate database backend.
func (r *QueryRouter) CreateKeyAccessServer(ctx context.Context, params UnifiedCreateKeyAccessServerParams) (string, error) {
	if r.IsSQLite() {
		return r.createKeyAccessServerSQLite(ctx, params)
	}
	return r.createKeyAccessServerPostgres(ctx, params)
}

func (r *QueryRouter) createKeyAccessServerPostgres(ctx context.Context, params UnifiedCreateKeyAccessServerParams) (string, error) {
	return r.postgres.createKeyAccessServer(ctx, createKeyAccessServerParams{
		Uri:        params.Uri,
		PublicKey:  params.PublicKey,
		Name:       pgtypeText(params.Name),
		Metadata:   params.Metadata,
		SourceType: pgtypeText(params.SourceType),
	})
}

func (r *QueryRouter) createKeyAccessServerSQLite(ctx context.Context, params UnifiedCreateKeyAccessServerParams) (string, error) {
	id := uuid.NewString()
	sqliteParams := sqlite.CreateKeyAccessServerParams{
		ID:        id,
		Uri:       params.Uri,
		PublicKey: string(params.PublicKey),
	}
	if params.Name != "" {
		sqliteParams.Name = sql.NullString{String: params.Name, Valid: true}
	}
	if params.Metadata != nil {
		sqliteParams.Metadata = sql.NullString{String: string(params.Metadata), Valid: true}
	}
	if params.SourceType != "" {
		sqliteParams.SourceType = sql.NullString{String: params.SourceType, Valid: true}
	}
	_, err := r.sqlite.CreateKeyAccessServer(ctx, sqliteParams)
	if err != nil {
		return "", err
	}
	return id, nil
}

// UnifiedUpdateKeyAccessServerParams is the unified parameters for updating a KAS.
type UnifiedUpdateKeyAccessServerParams struct {
	ID         string
	Uri        string
	Name       string
	PublicKey  []byte
	Metadata   []byte
	SourceType string
}

// UpdateKeyAccessServer routes to the appropriate database backend.
func (r *QueryRouter) UpdateKeyAccessServer(ctx context.Context, params UnifiedUpdateKeyAccessServerParams) (int64, error) {
	if r.IsSQLite() {
		return r.updateKeyAccessServerSQLite(ctx, params)
	}
	return r.updateKeyAccessServerPostgres(ctx, params)
}

func (r *QueryRouter) updateKeyAccessServerPostgres(ctx context.Context, params UnifiedUpdateKeyAccessServerParams) (int64, error) {
	return r.postgres.updateKeyAccessServer(ctx, updateKeyAccessServerParams{
		ID:         params.ID,
		Uri:        pgtypeText(params.Uri),
		Name:       pgtypeText(params.Name),
		PublicKey:  params.PublicKey,
		Metadata:   params.Metadata,
		SourceType: pgtypeText(params.SourceType),
	})
}

func (r *QueryRouter) updateKeyAccessServerSQLite(ctx context.Context, params UnifiedUpdateKeyAccessServerParams) (int64, error) {
	sqliteParams := sqlite.UpdateKeyAccessServerParams{
		ID: params.ID,
	}
	if params.Uri != "" {
		sqliteParams.Uri = sql.NullString{String: params.Uri, Valid: true}
	}
	if params.Name != "" {
		sqliteParams.Name = sql.NullString{String: params.Name, Valid: true}
	}
	if params.PublicKey != nil {
		sqliteParams.PublicKey = sql.NullString{String: string(params.PublicKey), Valid: true}
	}
	if params.Metadata != nil {
		sqliteParams.Metadata = sql.NullString{String: string(params.Metadata), Valid: true}
	}
	if params.SourceType != "" {
		sqliteParams.SourceType = sql.NullString{String: params.SourceType, Valid: true}
	}
	return r.sqlite.UpdateKeyAccessServer(ctx, sqliteParams)
}

// DeleteKeyAccessServer routes to the appropriate database backend.
func (r *QueryRouter) DeleteKeyAccessServer(ctx context.Context, id string) (int64, error) {
	if r.IsSQLite() {
		return r.sqlite.DeleteKeyAccessServer(ctx, id)
	}
	return r.postgres.deleteKeyAccessServer(ctx, id)
}

// ----------------------------------------------------------------
// Key Access Server Grants Routing
// ----------------------------------------------------------------

// UnifiedListKeyAccessServerGrantsParams is the unified parameters for listing KAS grants.
type UnifiedListKeyAccessServerGrantsParams struct {
	KasID   string
	KasUri  string
	KasName string
	Offset  int32
	Limit   int32
}

// UnifiedListKeyAccessServerGrantsRow is the unified result row for listing KAS grants.
type UnifiedListKeyAccessServerGrantsRow struct {
	KasID            string
	KasUri           string
	KasName          pgtype.Text
	KasPublicKey     []byte
	KasMetadata      []byte
	AttributesGrants []byte
	ValuesGrants     []byte
	NamespaceGrants  []byte
	Total            int64
}

// ListKeyAccessServerGrants routes to the appropriate database backend.
func (r *QueryRouter) ListKeyAccessServerGrants(ctx context.Context, params UnifiedListKeyAccessServerGrantsParams) ([]UnifiedListKeyAccessServerGrantsRow, error) {
	if r.IsSQLite() {
		return r.listKeyAccessServerGrantsSQLite(ctx, params)
	}
	return r.listKeyAccessServerGrantsPostgres(ctx, params)
}

func (r *QueryRouter) listKeyAccessServerGrantsPostgres(ctx context.Context, params UnifiedListKeyAccessServerGrantsParams) ([]UnifiedListKeyAccessServerGrantsRow, error) {
	rows, err := r.postgres.listKeyAccessServerGrants(ctx, listKeyAccessServerGrantsParams{
		KasID:   params.KasID,
		KasUri:  params.KasUri,
		KasName: params.KasName,
		Offset:  params.Offset,
		Limit:   params.Limit,
	})
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListKeyAccessServerGrantsRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListKeyAccessServerGrantsRow{
			KasID:            row.KasID,
			KasUri:           row.KasUri,
			KasName:          row.KasName,
			KasPublicKey:     row.KasPublicKey,
			KasMetadata:      row.KasMetadata,
			AttributesGrants: row.AttributesGrants,
			ValuesGrants:     row.ValuesGrants,
			NamespaceGrants:  row.NamespaceGrants,
			Total:            row.Total,
		}
	}
	return result, nil
}

func (r *QueryRouter) listKeyAccessServerGrantsSQLite(ctx context.Context, params UnifiedListKeyAccessServerGrantsParams) ([]UnifiedListKeyAccessServerGrantsRow, error) {
	var kasID, kasUri, kasName interface{}
	if params.KasID != "" {
		kasID = params.KasID
	}
	if params.KasUri != "" {
		kasUri = params.KasUri
	}
	if params.KasName != "" {
		kasName = params.KasName
	}

	rows, err := r.sqlite.ListKeyAccessServerGrants(ctx, sqlite.ListKeyAccessServerGrantsParams{
		Offset:  int64(params.Offset),
		Limit:   int64(params.Limit),
		KasID:   kasID,
		KasUri:  kasUri,
		KasName: kasName,
	})
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListKeyAccessServerGrantsRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListKeyAccessServerGrantsRow{
			KasID:            row.KasID,
			KasUri:           row.KasUri,
			KasName:          pgtype.Text{String: row.KasName.String, Valid: row.KasName.Valid},
			KasPublicKey:     []byte(row.KasPublicKey),
			KasMetadata:      sqliteMetadataToBytes(row.KasMetadata),
			AttributesGrants: sqliteMetadataToBytes(row.AttributesGrants),
			ValuesGrants:     sqliteMetadataToBytes(row.ValuesGrants),
			NamespaceGrants:  sqliteMetadataToBytes(row.NamespaceGrants),
			Total:            row.Total,
		}
	}
	return result, nil
}

// ----------------------------------------------------------------
// Key Routing
// ----------------------------------------------------------------

// UnifiedGetKeyParams is the unified parameters for getting a key.
type UnifiedGetKeyParams struct {
	ID      string
	KeyID   string
	KasID   string
	KasUri  string
	KasName string
}

// UnifiedGetKeyRow is the unified result for getting a key.
type UnifiedGetKeyRow struct {
	ID                string
	KeyID             string
	KeyStatus         int32
	KeyMode           int32
	KeyAlgorithm      int32
	PrivateKeyCtx     []byte
	PublicKeyCtx      []byte
	ProviderConfigID  pgtype.UUID
	KeyAccessServerID string
	KasUri            string
	Metadata          []byte
	PcManager         pgtype.Text
	ProviderName      pgtype.Text
	PcConfig          []byte
	PcMetadata        []byte
	Legacy            bool
}

// GetKey routes to the appropriate database backend.
func (r *QueryRouter) GetKey(ctx context.Context, params UnifiedGetKeyParams) (UnifiedGetKeyRow, error) {
	if r.IsSQLite() {
		return r.getKeySQLite(ctx, params)
	}
	return r.getKeyPostgres(ctx, params)
}

func (r *QueryRouter) getKeyPostgres(ctx context.Context, params UnifiedGetKeyParams) (UnifiedGetKeyRow, error) {
	pgParams := getKeyParams{}
	if params.ID != "" {
		pgParams.ID = pgtypeUUID(params.ID)
	}
	if params.KeyID != "" {
		pgParams.KeyID = pgtypeText(params.KeyID)
	}
	if params.KasID != "" {
		pgParams.KasID = pgtypeUUID(params.KasID)
	}
	if params.KasUri != "" {
		pgParams.KasUri = pgtypeText(params.KasUri)
	}
	if params.KasName != "" {
		pgParams.KasName = pgtypeText(params.KasName)
	}

	row, err := r.postgres.getKey(ctx, pgParams)
	if err != nil {
		return UnifiedGetKeyRow{}, err
	}

	return UnifiedGetKeyRow{
		ID:                row.ID,
		KeyID:             row.KeyID,
		KeyStatus:         row.KeyStatus,
		KeyMode:           row.KeyMode,
		KeyAlgorithm:      row.KeyAlgorithm,
		PrivateKeyCtx:     row.PrivateKeyCtx,
		PublicKeyCtx:      row.PublicKeyCtx,
		ProviderConfigID:  row.ProviderConfigID,
		KeyAccessServerID: row.KeyAccessServerID,
		KasUri:            row.KasUri,
		Metadata:          row.Metadata,
		PcManager:         row.PcManager,
		ProviderName:      row.ProviderName,
		PcConfig:          row.PcConfig,
		PcMetadata:        row.PcMetadata,
		Legacy:            row.Legacy,
	}, nil
}

func (r *QueryRouter) getKeySQLite(ctx context.Context, params UnifiedGetKeyParams) (UnifiedGetKeyRow, error) {
	var idParam, keyIDParam, kasIDParam, kasUriParam, kasNameParam interface{}
	if params.ID != "" {
		idParam = params.ID
	}
	if params.KeyID != "" {
		keyIDParam = params.KeyID
	}
	if params.KasID != "" {
		kasIDParam = params.KasID
	}
	if params.KasUri != "" {
		kasUriParam = params.KasUri
	}
	if params.KasName != "" {
		kasNameParam = params.KasName
	}

	row, err := r.sqlite.GetKey(ctx, sqlite.GetKeyParams{
		ID:      idParam,
		KeyID:   keyIDParam,
		KasID:   kasIDParam,
		KasUri:  kasUriParam,
		KasName: kasNameParam,
	})
	if err != nil {
		return UnifiedGetKeyRow{}, err
	}

	return UnifiedGetKeyRow{
		ID:                row.ID,
		KeyID:             row.KeyID,
		KeyStatus:         int32(row.KeyStatus),
		KeyMode:           int32(row.KeyMode),
		KeyAlgorithm:      int32(row.KeyAlgorithm),
		PrivateKeyCtx:     sqliteNullStringToBytes(row.PrivateKeyCtx),
		PublicKeyCtx:      sqliteNullStringToBytes(row.PublicKeyCtx),
		ProviderConfigID:  sqliteNullStringToUUID(row.ProviderConfigID),
		KeyAccessServerID: row.KeyAccessServerID,
		KasUri:            row.KasUri,
		Metadata:          sqliteMetadataToBytes(row.Metadata),
		PcManager:         pgtype.Text{String: row.PcManager.String, Valid: row.PcManager.Valid},
		ProviderName:      pgtype.Text{String: row.ProviderName.String, Valid: row.ProviderName.Valid},
		PcConfig:          sqliteNullStringToBytes(row.PcConfig),
		PcMetadata:        sqliteMetadataToBytes(row.PcMetadata),
		Legacy:            row.Legacy != 0,
	}, nil
}

// sqliteNullStringToBytes converts sql.NullString to []byte
func sqliteNullStringToBytes(ns sql.NullString) []byte {
	if !ns.Valid {
		return nil
	}
	return []byte(ns.String)
}

// sqliteNullStringToUUID converts sql.NullString to pgtype.UUID
func sqliteNullStringToUUID(ns sql.NullString) pgtype.UUID {
	if !ns.Valid || ns.String == "" {
		return pgtype.UUID{Valid: false}
	}
	return pgtypeUUID(ns.String)
}

// UnifiedListKeysParams is the unified parameters for listing keys.
type UnifiedListKeysParams struct {
	KeyAlgorithm *int32
	Legacy       *bool
	KasID        string
	KasUri       string
	KasName      string
	Offset       int32
	Limit        int32
}

// UnifiedListKeysRow is the unified result row for listing keys.
type UnifiedListKeysRow struct {
	Total             int64
	ID                string
	KeyID             string
	KeyStatus         int32
	KeyMode           int32
	KeyAlgorithm      int32
	PrivateKeyCtx     []byte
	PublicKeyCtx      []byte
	ProviderConfigID  pgtype.UUID
	KeyAccessServerID string
	KasUri            string
	Metadata          []byte
	ProviderName      pgtype.Text
	ProviderConfig    []byte
	PcMetadata        []byte
	Legacy            bool
}

// ListKeys routes to the appropriate database backend.
func (r *QueryRouter) ListKeys(ctx context.Context, params UnifiedListKeysParams) ([]UnifiedListKeysRow, error) {
	if r.IsSQLite() {
		return r.listKeysSQLite(ctx, params)
	}
	return r.listKeysPostgres(ctx, params)
}

func (r *QueryRouter) listKeysPostgres(ctx context.Context, params UnifiedListKeysParams) ([]UnifiedListKeysRow, error) {
	pgParams := listKeysParams{
		Offset: params.Offset,
		Limit:  params.Limit,
	}
	if params.KeyAlgorithm != nil {
		pgParams.KeyAlgorithm = pgtype.Int4{Int32: *params.KeyAlgorithm, Valid: true}
	}
	if params.Legacy != nil {
		pgParams.Legacy = pgtype.Bool{Bool: *params.Legacy, Valid: true}
	}
	if params.KasID != "" {
		pgParams.KasID = pgtypeUUID(params.KasID)
	}
	if params.KasUri != "" {
		pgParams.KasUri = pgtypeText(params.KasUri)
	}
	if params.KasName != "" {
		pgParams.KasName = pgtypeText(params.KasName)
	}

	rows, err := r.postgres.listKeys(ctx, pgParams)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListKeysRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListKeysRow{
			Total:             row.Total,
			ID:                row.ID,
			KeyID:             row.KeyID,
			KeyStatus:         row.KeyStatus,
			KeyMode:           row.KeyMode,
			KeyAlgorithm:      row.KeyAlgorithm,
			PrivateKeyCtx:     row.PrivateKeyCtx,
			PublicKeyCtx:      row.PublicKeyCtx,
			ProviderConfigID:  row.ProviderConfigID,
			KeyAccessServerID: row.KeyAccessServerID,
			KasUri:            row.KasUri,
			Metadata:          row.Metadata,
			ProviderName:      row.ProviderName,
			ProviderConfig:    row.ProviderConfig,
			PcMetadata:        row.PcMetadata,
			Legacy:            row.Legacy,
		}
	}
	return result, nil
}

func (r *QueryRouter) listKeysSQLite(ctx context.Context, params UnifiedListKeysParams) ([]UnifiedListKeysRow, error) {
	sqliteParams := sqlite.ListKeysParams{
		Offset: int64(params.Offset),
		Limit:  int64(params.Limit),
	}
	if params.KeyAlgorithm != nil {
		sqliteParams.KeyAlgorithm = int64(*params.KeyAlgorithm)
	}
	if params.Legacy != nil {
		if *params.Legacy {
			sqliteParams.Legacy = int64(1)
		} else {
			sqliteParams.Legacy = int64(0)
		}
	}
	if params.KasID != "" {
		sqliteParams.KasID = params.KasID
	}
	if params.KasUri != "" {
		sqliteParams.KasUri = params.KasUri
	}
	if params.KasName != "" {
		sqliteParams.KasName = params.KasName
	}

	rows, err := r.sqlite.ListKeys(ctx, sqliteParams)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListKeysRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListKeysRow{
			Total:             row.Total,
			ID:                row.ID,
			KeyID:             row.KeyID,
			KeyStatus:         int32(row.KeyStatus),
			KeyMode:           int32(row.KeyMode),
			KeyAlgorithm:      int32(row.KeyAlgorithm),
			PrivateKeyCtx:     sqliteNullStringToBytes(row.PrivateKeyCtx),
			PublicKeyCtx:      sqliteNullStringToBytes(row.PublicKeyCtx),
			ProviderConfigID:  sqliteNullStringToUUID(row.ProviderConfigID),
			KeyAccessServerID: row.KeyAccessServerID,
			KasUri:            row.KasUri,
			Metadata:          sqliteMetadataToBytes(row.Metadata),
			ProviderName:      pgtype.Text{String: row.ProviderName.String, Valid: row.ProviderName.Valid},
			ProviderConfig:    sqliteNullStringToBytes(row.ProviderConfig),
			PcMetadata:        sqliteMetadataToBytes(row.PcMetadata),
			Legacy:            row.Legacy != 0,
		}
	}
	return result, nil
}

// UnifiedCreateKeyParams is the unified parameters for creating a key.
type UnifiedCreateKeyParams struct {
	KeyAccessServerID string
	KeyAlgorithm      int32
	KeyID             string
	KeyMode           int32
	KeyStatus         int32
	Metadata          []byte
	PrivateKeyCtx     []byte
	PublicKeyCtx      []byte
	ProviderConfigID  string
	Legacy            bool
}

// CreateKey routes to the appropriate database backend.
func (r *QueryRouter) CreateKey(ctx context.Context, params UnifiedCreateKeyParams) (string, error) {
	if r.IsSQLite() {
		return r.createKeySQLite(ctx, params)
	}
	return r.createKeyPostgres(ctx, params)
}

func (r *QueryRouter) createKeyPostgres(ctx context.Context, params UnifiedCreateKeyParams) (string, error) {
	return r.postgres.createKey(ctx, createKeyParams{
		KeyAccessServerID: params.KeyAccessServerID,
		KeyAlgorithm:      params.KeyAlgorithm,
		KeyID:             params.KeyID,
		KeyMode:           params.KeyMode,
		KeyStatus:         params.KeyStatus,
		Metadata:          params.Metadata,
		PrivateKeyCtx:     params.PrivateKeyCtx,
		PublicKeyCtx:      params.PublicKeyCtx,
		ProviderConfigID:  pgtypeUUID(params.ProviderConfigID),
		Legacy:            params.Legacy,
	})
}

func (r *QueryRouter) createKeySQLite(ctx context.Context, params UnifiedCreateKeyParams) (string, error) {
	id := uuid.NewString()
	var legacyInt int64
	if params.Legacy {
		legacyInt = 1
	}

	sqliteParams := sqlite.CreateKeyParams{
		ID:                id,
		KeyAccessServerID: params.KeyAccessServerID,
		KeyAlgorithm:      int64(params.KeyAlgorithm),
		KeyID:             params.KeyID,
		KeyMode:           int64(params.KeyMode),
		KeyStatus:         int64(params.KeyStatus),
		Legacy:            legacyInt,
	}
	if params.Metadata != nil {
		sqliteParams.Metadata = sql.NullString{String: string(params.Metadata), Valid: true}
	}
	if params.PrivateKeyCtx != nil {
		sqliteParams.PrivateKeyCtx = sql.NullString{String: string(params.PrivateKeyCtx), Valid: true}
	}
	if params.PublicKeyCtx != nil {
		sqliteParams.PublicKeyCtx = sql.NullString{String: string(params.PublicKeyCtx), Valid: true}
	}
	if params.ProviderConfigID != "" {
		sqliteParams.ProviderConfigID = sql.NullString{String: params.ProviderConfigID, Valid: true}
	}

	_, err := r.sqlite.CreateKey(ctx, sqliteParams)
	if err != nil {
		return "", err
	}
	return id, nil
}

// UnifiedUpdateKeyParams is the unified parameters for updating a key.
type UnifiedUpdateKeyParams struct {
	ID        string
	KeyStatus *int32
	Metadata  []byte
}

// UpdateKey routes to the appropriate database backend.
func (r *QueryRouter) UpdateKey(ctx context.Context, params UnifiedUpdateKeyParams) (int64, error) {
	if r.IsSQLite() {
		return r.updateKeySQLite(ctx, params)
	}
	return r.updateKeyPostgres(ctx, params)
}

func (r *QueryRouter) updateKeyPostgres(ctx context.Context, params UnifiedUpdateKeyParams) (int64, error) {
	pgParams := updateKeyParams{
		ID: params.ID,
	}
	if params.KeyStatus != nil {
		pgParams.KeyStatus = pgtype.Int4{Int32: *params.KeyStatus, Valid: true}
	}
	if params.Metadata != nil {
		pgParams.Metadata = params.Metadata
	}
	return r.postgres.updateKey(ctx, pgParams)
}

func (r *QueryRouter) updateKeySQLite(ctx context.Context, params UnifiedUpdateKeyParams) (int64, error) {
	sqliteParams := sqlite.UpdateKeyParams{
		ID: params.ID,
	}
	if params.KeyStatus != nil {
		sqliteParams.KeyStatus = sql.NullInt64{Int64: int64(*params.KeyStatus), Valid: true}
	}
	if params.Metadata != nil {
		sqliteParams.Metadata = sql.NullString{String: string(params.Metadata), Valid: true}
	}
	return r.sqlite.UpdateKey(ctx, sqliteParams)
}

// DeleteKey routes to the appropriate database backend.
func (r *QueryRouter) DeleteKey(ctx context.Context, id string) (int64, error) {
	if r.IsSQLite() {
		return r.sqlite.DeleteKey(ctx, id)
	}
	return r.postgres.deleteKey(ctx, id)
}

// ----------------------------------------------------------------
// Base Key Routing
// ----------------------------------------------------------------

// GetBaseKey routes to the appropriate database backend.
func (r *QueryRouter) GetBaseKey(ctx context.Context) ([]byte, error) {
	if r.IsSQLite() {
		result, err := r.sqlite.GetBaseKey(ctx)
		if err != nil {
			return nil, err
		}
		return sqliteMetadataToBytes(result), nil
	}
	return r.postgres.getBaseKey(ctx)
}

// SetBaseKey routes to the appropriate database backend.
func (r *QueryRouter) SetBaseKey(ctx context.Context, keyAccessServerKeyID string) (int64, error) {
	if r.IsSQLite() {
		return r.sqlite.SetBaseKey(ctx, keyAccessServerKeyID)
	}
	return r.postgres.setBaseKey(ctx, pgtypeUUID(keyAccessServerKeyID))
}

// ----------------------------------------------------------------
// Key Mappings Routing
// ----------------------------------------------------------------

// UnifiedListKeyMappingsParams is the unified parameters for listing key mappings.
type UnifiedListKeyMappingsParams struct {
	ID      string
	Kid     string
	KasID   string
	KasName string
	KasUri  string
	Offset  int32
	Limit   int32
}

// UnifiedListKeyMappingsRow is the unified result row for listing key mappings.
type UnifiedListKeyMappingsRow struct {
	Kid               string
	KasUri            string
	NamespaceMappings []byte
	AttributeMappings []byte
	ValueMappings     []byte
	Total             int64
}

// ListKeyMappings routes to the appropriate database backend.
func (r *QueryRouter) ListKeyMappings(ctx context.Context, params UnifiedListKeyMappingsParams) ([]UnifiedListKeyMappingsRow, error) {
	if r.IsSQLite() {
		return r.listKeyMappingsSQLite(ctx, params)
	}
	return r.listKeyMappingsPostgres(ctx, params)
}

func (r *QueryRouter) listKeyMappingsPostgres(ctx context.Context, params UnifiedListKeyMappingsParams) ([]UnifiedListKeyMappingsRow, error) {
	pgParams := listKeyMappingsParams{
		Offset: params.Offset,
		Limit:  params.Limit,
	}
	if params.ID != "" {
		pgParams.ID = pgtypeUUID(params.ID)
	}
	if params.Kid != "" {
		pgParams.Kid = pgtypeText(params.Kid)
	}
	if params.KasID != "" {
		pgParams.KasID = pgtypeUUID(params.KasID)
	}
	if params.KasName != "" {
		pgParams.KasName = pgtypeText(params.KasName)
	}
	if params.KasUri != "" {
		pgParams.KasUri = pgtypeText(params.KasUri)
	}

	rows, err := r.postgres.listKeyMappings(ctx, pgParams)
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListKeyMappingsRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListKeyMappingsRow{
			Kid:               row.Kid,
			KasUri:            row.KasUri,
			NamespaceMappings: row.NamespaceMappings,
			AttributeMappings: row.AttributeMappings,
			ValueMappings:     row.ValueMappings,
			Total:             row.Total,
		}
	}
	return result, nil
}

func (r *QueryRouter) listKeyMappingsSQLite(ctx context.Context, params UnifiedListKeyMappingsParams) ([]UnifiedListKeyMappingsRow, error) {
	var idParam, kidParam, kasIDParam, kasNameParam, kasUriParam interface{}
	if params.ID != "" {
		idParam = params.ID
	}
	if params.Kid != "" {
		kidParam = params.Kid
	}
	if params.KasID != "" {
		kasIDParam = params.KasID
	}
	if params.KasName != "" {
		kasNameParam = params.KasName
	}
	if params.KasUri != "" {
		kasUriParam = params.KasUri
	}

	rows, err := r.sqlite.ListKeyMappings(ctx, sqlite.ListKeyMappingsParams{
		Offset:  int64(params.Offset),
		Limit:   int64(params.Limit),
		ID:      idParam,
		Kid:     kidParam,
		KasID:   kasIDParam,
		KasName: kasNameParam,
		KasUri:  kasUriParam,
	})
	if err != nil {
		return nil, err
	}

	result := make([]UnifiedListKeyMappingsRow, len(rows))
	for i, row := range rows {
		result[i] = UnifiedListKeyMappingsRow{
			Kid:               row.Kid,
			KasUri:            row.KasUri,
			NamespaceMappings: sqliteMetadataToBytes(row.NamespaceMappings),
			AttributeMappings: sqliteMetadataToBytes(row.AttributeMappings),
			ValueMappings:     sqliteMetadataToBytes(row.ValueMappings),
			Total:             row.Total,
		}
	}
	return result, nil
}

// ----------------------------------------------------------------
// Public Key Rotation Routing
// ----------------------------------------------------------------

// UnifiedRotatePublicKeyParams is the unified parameters for rotating public keys.
type UnifiedRotatePublicKeyParams struct {
	OldKeyID string
	NewKeyID string
}

// RotatePublicKeyForNamespace routes to the appropriate database backend.
func (r *QueryRouter) RotatePublicKeyForNamespace(ctx context.Context, params UnifiedRotatePublicKeyParams) ([]string, error) {
	if r.IsSQLite() {
		return r.sqlite.RotatePublicKeyForNamespace(ctx, sqlite.RotatePublicKeyForNamespaceParams{
			OldKeyID: params.OldKeyID,
			NewKeyID: params.NewKeyID,
		})
	}
	return r.postgres.rotatePublicKeyForNamespace(ctx, rotatePublicKeyForNamespaceParams{
		OldKeyID: params.OldKeyID,
		NewKeyID: params.NewKeyID,
	})
}

// RotatePublicKeyForAttributeDefinition routes to the appropriate database backend.
func (r *QueryRouter) RotatePublicKeyForAttributeDefinition(ctx context.Context, params UnifiedRotatePublicKeyParams) ([]string, error) {
	if r.IsSQLite() {
		return r.sqlite.RotatePublicKeyForAttributeDefinition(ctx, sqlite.RotatePublicKeyForAttributeDefinitionParams{
			OldKeyID: params.OldKeyID,
			NewKeyID: params.NewKeyID,
		})
	}
	return r.postgres.rotatePublicKeyForAttributeDefinition(ctx, rotatePublicKeyForAttributeDefinitionParams{
		OldKeyID: params.OldKeyID,
		NewKeyID: params.NewKeyID,
	})
}

// RotatePublicKeyForAttributeValue routes to the appropriate database backend.
func (r *QueryRouter) RotatePublicKeyForAttributeValue(ctx context.Context, params UnifiedRotatePublicKeyParams) ([]string, error) {
	if r.IsSQLite() {
		return r.sqlite.RotatePublicKeyForAttributeValue(ctx, sqlite.RotatePublicKeyForAttributeValueParams{
			OldKeyID: params.OldKeyID,
			NewKeyID: params.NewKeyID,
		})
	}
	return r.postgres.rotatePublicKeyForAttributeValue(ctx, rotatePublicKeyForAttributeValueParams{
		OldKeyID: params.OldKeyID,
		NewKeyID: params.NewKeyID,
	})
}
