package sql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"strconv"
	"time"

	"connectrpc.com/connect"
	"github.com/creasty/defaults"
	"github.com/go-viper/mapstructure/v2"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	ent "github.com/opentdf/platform/service/entity"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	// SQL drivers
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/mattn/go-sqlite3"
)

var (
	ErrCreationFailed     = errors.New("resource creation failed")
	ErrGetRetrievalFailed = errors.New("resource retrieval failed")
	ErrNotFound           = errors.New("resource not found")
	ErrConnectionFailed   = errors.New("SQL connection failed")
	ErrInvalidDriver      = errors.New("invalid SQL driver")
	ErrQueryFailed        = errors.New("SQL query failed")
)

const (
	DefaultConnMaxLifetime = 30 * time.Minute
	DefaultMaxOpenConns    = 25
	DefaultMaxIdleConns    = 5
	DefaultConnTimeout     = 10 * time.Second
	DefaultQueryTimeout    = 30 * time.Second
)

// SQLEntityResolutionServiceV2 implements the v2 Entity Resolution Service for SQL databases
type SQLEntityResolutionServiceV2 struct {
	entityresolutionV2.UnimplementedEntityResolutionServiceServer
	Config SQLConfig
	DB     *sql.DB
	Logger *logger.Logger
	trace.Tracer
}

// SQLConfig holds the configuration for SQL connection and query mapping
type SQLConfig struct {
	// Database connection settings
	Driver         string        `mapstructure:"driver" json:"driver"`
	DSN            string        `mapstructure:"dsn" json:"dsn"`
	Host           string        `mapstructure:"host" json:"host"`
	Port           int           `mapstructure:"port" json:"port"`
	Database       string        `mapstructure:"database" json:"database"`
	Username       string        `mapstructure:"username" json:"username"`
	Password       string        `mapstructure:"password" json:"password"`
	SSLMode        string        `mapstructure:"ssl_mode" json:"ssl_mode" default:"prefer"`
	
	// Connection pool settings
	MaxOpenConns    int           `mapstructure:"max_open_conns" json:"max_open_conns" default:"25"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns" json:"max_idle_conns" default:"5"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime" json:"conn_max_lifetime"`
	
	// Query timeouts
	ConnectTimeout time.Duration `mapstructure:"connect_timeout" json:"connect_timeout"`
	QueryTimeout   time.Duration `mapstructure:"query_timeout" json:"query_timeout"`
	
	// Query configuration
	QueryMapping QueryMapping `mapstructure:"query_mapping" json:"query_mapping"`
	
	// Column mapping
	ColumnMapping ColumnMapping `mapstructure:"column_mapping" json:"column_mapping"`
	
	// Feature flags
	InferID InferredIdentityConfig `mapstructure:"inferid,omitempty" json:"inferid,omitempty"`
}

// QueryMapping defines SQL queries for different entity types
type QueryMapping struct {
	// Query for finding user by username
	UsernameQuery string `mapstructure:"username_query" json:"username_query"`
	
	// Query for finding user by email
	EmailQuery string `mapstructure:"email_query" json:"email_query"`
	
	// Query for finding client by client ID
	ClientIDQuery string `mapstructure:"client_id_query" json:"client_id_query"`
	
	// Optional queries for additional data
	GroupsQuery      string `mapstructure:"groups_query" json:"groups_query"`
	AttributesQuery  string `mapstructure:"attributes_query" json:"attributes_query"`
}

// ColumnMapping defines how SQL columns map to entity properties
type ColumnMapping struct {
	Username    string   `mapstructure:"username" json:"username" default:"username"`
	Email       string   `mapstructure:"email" json:"email" default:"email"`
	DisplayName string   `mapstructure:"display_name" json:"display_name" default:"display_name"`
	ClientID    string   `mapstructure:"client_id" json:"client_id" default:"client_id"`
	Groups      string   `mapstructure:"groups" json:"groups" default:"groups"`
	Additional  []string `mapstructure:"additional" json:"additional"`
}

// InferredIdentityConfig matches the pattern from other ERS implementations
type InferredIdentityConfig struct {
	From EntityImpliedFrom `mapstructure:"from,omitempty" json:"from,omitempty"`
}

type EntityImpliedFrom struct {
	ClientID bool `mapstructure:"clientid,omitempty" json:"clientid,omitempty"`
	Email    bool `mapstructure:"email,omitempty" json:"email,omitempty"`
	Username bool `mapstructure:"username,omitempty" json:"username,omitempty"`
}

// RegisterSQLERS creates and registers the SQL Entity Resolution Service for v2
func RegisterSQLERS(config config.ServiceConfig, logger *logger.Logger) (*SQLEntityResolutionServiceV2, serviceregistry.HandlerServer) {
	var sqlConfig SQLConfig
	if err := mapstructure.Decode(config, &sqlConfig); err != nil {
		logger.Error("Failed to decode SQL configuration", slog.Any("error", err))
		log.Fatalf("Failed to decode SQL configuration: %v", err)
	}

	// Set defaults using creasty/defaults
	defaults.Set(&sqlConfig)
	
	// Set defaults that can't be handled by the defaults tag
	if sqlConfig.ConnectTimeout == 0 {
		sqlConfig.ConnectTimeout = DefaultConnTimeout
	}
	if sqlConfig.QueryTimeout == 0 {
		sqlConfig.QueryTimeout = DefaultQueryTimeout
	}
	if sqlConfig.ConnMaxLifetime == 0 {
		sqlConfig.ConnMaxLifetime = DefaultConnMaxLifetime
	}
	if sqlConfig.MaxOpenConns == 0 {
		sqlConfig.MaxOpenConns = DefaultMaxOpenConns
	}
	if sqlConfig.MaxIdleConns == 0 {
		sqlConfig.MaxIdleConns = DefaultMaxIdleConns
	}

	// Set default column mappings
	if sqlConfig.ColumnMapping.Username == "" {
		sqlConfig.ColumnMapping.Username = "username"
	}
	if sqlConfig.ColumnMapping.Email == "" {
		sqlConfig.ColumnMapping.Email = "email"
	}
	if sqlConfig.ColumnMapping.DisplayName == "" {
		sqlConfig.ColumnMapping.DisplayName = "display_name"
	}
	if sqlConfig.ColumnMapping.ClientID == "" {
		sqlConfig.ColumnMapping.ClientID = "client_id"
	}
	if sqlConfig.ColumnMapping.Groups == "" {
		sqlConfig.ColumnMapping.Groups = "groups"
	}

	// Validate driver
	if sqlConfig.Driver == "" {
		logger.Error("SQL driver not specified in configuration")
		log.Fatalf("SQL driver not specified in configuration")
	}

	// Build DSN if not provided
	if sqlConfig.DSN == "" {
		sqlConfig.DSN = buildDSN(sqlConfig)
	}

	logger.Debug("SQL entity resolution v2 configuration", "config", sqlConfig)
	
	// Initialize database connection
	db, err := sql.Open(sqlConfig.Driver, sqlConfig.DSN)
	if err != nil {
		logger.Error("Failed to open SQL connection", slog.Any("error", err), slog.String("driver", sqlConfig.Driver))
		log.Fatalf("Failed to open SQL connection with driver %s: %v", sqlConfig.Driver, err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(sqlConfig.MaxOpenConns)
	db.SetMaxIdleConns(sqlConfig.MaxIdleConns)
	db.SetConnMaxLifetime(sqlConfig.ConnMaxLifetime)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), sqlConfig.ConnectTimeout)
	defer cancel()
	
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		logger.Error("Failed to ping SQL database", slog.Any("error", err), slog.String("driver", sqlConfig.Driver))
		log.Fatalf("Failed to ping SQL database with driver %s: %v", sqlConfig.Driver, err)
	}

	sqlSVC := &SQLEntityResolutionServiceV2{
		Config: sqlConfig,
		DB:     db,
		Logger: logger,
	}
	
	return sqlSVC, nil
}

// buildDSN constructs a DSN from individual connection parameters
func buildDSN(config SQLConfig) string {
	switch config.Driver {
	case "pgx", "postgres":
		return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			config.Host, config.Port, config.Username, config.Password, config.Database, config.SSLMode)
	case "mysql":
		return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s",
			config.Username, config.Password, config.Host, config.Port, config.Database)
	case "sqlite3":
		return config.Database
	default:
		return ""
	}
}

// LogValue implements slog.LogValuer for secure logging
func (c SQLConfig) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("driver", c.Driver),
		slog.String("dsn", "[REDACTED]"),
		slog.String("host", c.Host),
		slog.Int("port", c.Port),
		slog.String("database", c.Database),
		slog.String("username", c.Username),
		slog.String("password", "[REDACTED]"),
		slog.String("ssl_mode", c.SSLMode),
		slog.Int("max_open_conns", c.MaxOpenConns),
		slog.Int("max_idle_conns", c.MaxIdleConns),
		slog.Duration("conn_max_lifetime", c.ConnMaxLifetime),
		slog.Any("query_mapping", c.QueryMapping),
		slog.Any("column_mapping", c.ColumnMapping),
		slog.Any("inferid", c.InferID),
	)
}

// Close closes the database connection
func (s *SQLEntityResolutionServiceV2) Close() error {
	if s.DB != nil {
		return s.DB.Close()
	}
	return nil
}

// ResolveEntities implements the v2 ResolveEntities method
func (s *SQLEntityResolutionServiceV2) ResolveEntities(ctx context.Context, req *connect.Request[entityresolutionV2.ResolveEntitiesRequest]) (*connect.Response[entityresolutionV2.ResolveEntitiesResponse], error) {
	if s.Tracer != nil {
		var span trace.Span
		ctx, span = s.Tracer.Start(ctx, "SQL.ResolveEntities")
		defer span.End()
	}

	resp, err := EntityResolution(ctx, req.Msg, s.Config, s.DB, s.Logger)
	return connect.NewResponse(&resp), err
}

// CreateEntityChainsFromTokens implements the v2 CreateEntityChainsFromTokens method
func (s *SQLEntityResolutionServiceV2) CreateEntityChainsFromTokens(ctx context.Context, req *connect.Request[entityresolutionV2.CreateEntityChainsFromTokensRequest]) (*connect.Response[entityresolutionV2.CreateEntityChainsFromTokensResponse], error) {
	if s.Tracer != nil {
		var span trace.Span
		ctx, span = s.Tracer.Start(ctx, "SQL.CreateEntityChainsFromTokens")
		defer span.End()
	}

	resp, err := CreateEntityChainsFromTokens(ctx, req.Msg, s.Config, s.Logger)
	return connect.NewResponse(&resp), err
}

// EntityResolution handles the core entity resolution logic for v2 protocol
func EntityResolution(ctx context.Context, req *entityresolutionV2.ResolveEntitiesRequest, sqlConfig SQLConfig, db *sql.DB, logger *logger.Logger) (entityresolutionV2.ResolveEntitiesResponse, error) {
	var resolvedEntities []*entityresolutionV2.EntityRepresentation
	
	for idx, ident := range req.GetEntities() {
		logger.Debug("resolving entity", "type", fmt.Sprintf("%T", ident.GetEntityType()), "ephemeral_id", ident.GetEphemeralId())
		
		var rows []map[string]interface{}
		var queryErr error

		switch entityType := ident.GetEntityType().(type) {
		case *entity.Entity_ClientId:
			rows, queryErr = queryByClientID(ctx, db, sqlConfig, entityType.ClientId)
		case *entity.Entity_EmailAddress:
			rows, queryErr = queryByEmail(ctx, db, sqlConfig, entityType.EmailAddress)
		case *entity.Entity_UserName:
			rows, queryErr = queryByUsername(ctx, db, sqlConfig, entityType.UserName)
		default:
			logger.Warn("unsupported entity type", "type", fmt.Sprintf("%T", entityType))
			continue
		}

		if queryErr != nil {
			logger.Error("SQL query failed", "error", queryErr.Error())
			return entityresolutionV2.ResolveEntitiesResponse{}, 
				connect.NewError(connect.CodeInternal, ErrGetRetrievalFailed)
		}

		var jsonEntities []*structpb.Struct
		
		if len(rows) == 0 {
			// Handle entity not found - check if we should infer the identity
			if shouldInferEntity(ident, sqlConfig) {
				entityStruct, err := entityToStructPb(ident)
				if err != nil {
					logger.Error("failed to create inferred entity struct", "error", err.Error())
					return entityresolutionV2.ResolveEntitiesResponse{}, 
						connect.NewError(connect.CodeInternal, ErrCreationFailed)
				}
				jsonEntities = append(jsonEntities, entityStruct)
			} else {
				entityNotFoundErr := entityresolutionV2.EntityNotFoundError{
					Code:    int32(codes.NotFound),
					Message: ErrNotFound.Error(),
					Entity:  ident.String(),
				}
				logger.Error("entity not found", "entity", ident.String())
				return entityresolutionV2.ResolveEntitiesResponse{}, 
					connect.NewError(connect.Code(entityNotFoundErr.GetCode()), ErrNotFound)
			}
		} else {
			// Convert SQL rows to JSON structures
			for _, row := range rows {
				entityStruct, err := structpb.NewStruct(row)
				if err != nil {
					logger.Error("failed to create struct from row", "error", err.Error())
					return entityresolutionV2.ResolveEntitiesResponse{}, 
						connect.NewError(connect.CodeInternal, ErrCreationFailed)
				}
				
				jsonEntities = append(jsonEntities, entityStruct)
			}
		}

		// Ensure the original ID field is populated following v2 patterns
		originalID := ident.GetEphemeralId()
		if originalID == "" {
			originalID = ent.EntityIDPrefix + strconv.Itoa(idx)
		}

		resolvedEntities = append(resolvedEntities, &entityresolutionV2.EntityRepresentation{
			OriginalId:      originalID,
			AdditionalProps: jsonEntities,
		})
	}

	return entityresolutionV2.ResolveEntitiesResponse{
		EntityRepresentations: resolvedEntities,
	}, nil
}

// CreateEntityChainsFromTokens handles JWT-based entity chain creation for v2 protocol
func CreateEntityChainsFromTokens(ctx context.Context, req *entityresolutionV2.CreateEntityChainsFromTokensRequest, sqlConfig SQLConfig, logger *logger.Logger) (entityresolutionV2.CreateEntityChainsFromTokensResponse, error) {
	var entityChains []*entity.EntityChain
	
	// For each token in the tokens form an entity chain
	for _, tok := range req.GetTokens() {
		entities, err := getEntitiesFromToken(ctx, sqlConfig, tok.GetJwt(), logger)
		if err != nil {
			return entityresolutionV2.CreateEntityChainsFromTokensResponse{}, err
		}
		entityChains = append(entityChains, &entity.EntityChain{
			EphemeralId: tok.GetEphemeralId(),
			Entities:    entities,
		})
	}

	return entityresolutionV2.CreateEntityChainsFromTokensResponse{
		EntityChains: entityChains,
	}, nil
}

// queryByUsername executes the username query and returns rows
func queryByUsername(ctx context.Context, db *sql.DB, config SQLConfig, username string) ([]map[string]interface{}, error) {
	if config.QueryMapping.UsernameQuery == "" {
		return nil, fmt.Errorf("username query not configured")
	}
	return ExecuteQuery(ctx, db, config, config.QueryMapping.UsernameQuery, username)
}

// queryByEmail executes the email query and returns rows
func queryByEmail(ctx context.Context, db *sql.DB, config SQLConfig, email string) ([]map[string]interface{}, error) {
	if config.QueryMapping.EmailQuery == "" {
		return nil, fmt.Errorf("email query not configured")
	}
	return ExecuteQuery(ctx, db, config, config.QueryMapping.EmailQuery, email)
}

// queryByClientID executes the client ID query and returns rows
func queryByClientID(ctx context.Context, db *sql.DB, config SQLConfig, clientID string) ([]map[string]interface{}, error) {
	if config.QueryMapping.ClientIDQuery == "" {
		return nil, fmt.Errorf("client ID query not configured")
	}
	return ExecuteQuery(ctx, db, config, config.QueryMapping.ClientIDQuery, clientID)
}

// ExecuteQuery executes a parameterized SQL query and returns the results as maps
func ExecuteQuery(ctx context.Context, db *sql.DB, config SQLConfig, query string, param string) ([]map[string]interface{}, error) {
	// Add query timeout to context
	queryCtx, cancel := context.WithTimeout(ctx, config.QueryTimeout)
	defer cancel()

	rows, err := db.QueryContext(queryCtx, query, param)
	if err != nil {
		return nil, fmt.Errorf("query execution failed: %w", err)
	}
	defer rows.Close()

	// Get column names
	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("failed to get column names: %w", err)
	}

	var results []map[string]interface{}
	
	for rows.Next() {
		// Create a slice to hold column values
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		// Scan the row
		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		// Convert to map
		row := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]
			
			// Convert byte arrays to strings
			if b, ok := val.([]byte); ok {
				val = string(b)
			}
			
			row[col] = val
		}
		
		results = append(results, row)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return results, nil
}

// shouldInferEntity determines if an entity should be inferred when not found in database
func shouldInferEntity(ident *entity.Entity, config SQLConfig) bool {
	switch ident.GetEntityType().(type) {
	case *entity.Entity_ClientId:
		return config.InferID.From.ClientID
	case *entity.Entity_EmailAddress:
		return config.InferID.From.Email
	case *entity.Entity_UserName:
		return config.InferID.From.Username
	default:
		return false
	}
}

// entityToStructPb converts an entity to a protobuf Struct
func entityToStructPb(ident *entity.Entity) (*structpb.Struct, error) {
	entityBytes, err := protojson.Marshal(ident)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal entity: %w", err)
	}
	
	var entityStruct structpb.Struct
	if err := entityStruct.UnmarshalJSON(entityBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON to struct: %w", err)
	}
	
	return &entityStruct, nil
}

// getEntitiesFromToken extracts entities from a JWT token
func getEntitiesFromToken(ctx context.Context, config SQLConfig, jwtString string, logger *logger.Logger) ([]*entity.Entity, error) {
	token, err := jwt.ParseString(jwtString, jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	claims, err := token.AsMap(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to extract claims from JWT: %w", err)
	}

	var entities []*entity.Entity
	entityID := 0

	// Extract client ID (azp claim)
	if clientID, ok := claims["azp"].(string); ok && clientID != "" {
		entities = append(entities, &entity.Entity{
			EntityType:  &entity.Entity_ClientId{ClientId: clientID},
			EphemeralId: fmt.Sprintf("jwtentity-%d-clientid-%s", entityID, clientID),
			Category:    entity.Entity_CATEGORY_ENVIRONMENT,
		})
		entityID++
	}

	// Extract username (preferred_username claim)
	if username, ok := claims["preferred_username"].(string); ok && username != "" {
		entities = append(entities, &entity.Entity{
			EntityType:  &entity.Entity_UserName{UserName: username},
			EphemeralId: fmt.Sprintf("jwtentity-%d-username-%s", entityID, username),
			Category:    entity.Entity_CATEGORY_SUBJECT,
		})
		entityID++
	}

	// Extract email if available
	if email, ok := claims["email"].(string); ok && email != "" {
		entities = append(entities, &entity.Entity{
			EntityType:  &entity.Entity_EmailAddress{EmailAddress: email},
			EphemeralId: fmt.Sprintf("jwtentity-%d-email-%s", entityID, email),
			Category:    entity.Entity_CATEGORY_SUBJECT,
		})
		entityID++
	}

	return entities, nil
}