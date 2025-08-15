package sql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	// Database drivers would be imported here:
	// _ "github.com/lib/pq"           // PostgreSQL driver
	// _ "github.com/go-sql-driver/mysql" // MySQL driver
	// _ "github.com/mattn/go-sqlite3" // SQLite driver

	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
)

// SQLProvider implements the Provider interface for SQL databases
type SQLProvider struct {
	name   string
	config SQLConfig
	db     *sql.DB
	mapper types.Mapper
}

// NewSQLProvider creates a new SQL provider
func NewSQLProvider(ctx context.Context, name string, config SQLConfig) (*SQLProvider, error) {
	provider := &SQLProvider{
		name:   name,
		config: config,
		mapper: NewSQLMapper(),
	}

	// Build connection string based on driver
	connStr, err := provider.buildConnectionString()
	if err != nil {
		return nil, types.WrapMultiStrategyError(
			types.ErrorTypeConfiguration,
			"failed to build connection string",
			err,
			map[string]interface{}{
				"provider": name,
				"driver":   config.Driver,
			},
		)
	}

	// Open database connection
	db, err := sql.Open(config.Driver, connStr)
	if err != nil {
		return nil, types.WrapMultiStrategyError(
			types.ErrorTypeProvider,
			"failed to open database connection",
			err,
			map[string]interface{}{
				"provider": name,
				"driver":   config.Driver,
			},
		)
	}

	// Configure connection pool
	db.SetMaxOpenConns(config.MaxOpenConnections)
	db.SetMaxIdleConns(config.MaxIdleConnections)
	db.SetConnMaxLifetime(config.ConnMaxLifetime)
	db.SetConnMaxIdleTime(config.ConnMaxIdleTime)

	provider.db = db

	// Test the connection
	ctx, cancel := context.WithTimeout(context.Background(), config.HealthCheckTime)
	defer cancel()

	if err := provider.HealthCheck(ctx); err != nil {
		_ = db.Close()
		return nil, types.WrapMultiStrategyError(
			types.ErrorTypeProvider,
			"database connection test failed",
			err,
			map[string]interface{}{
				"provider": name,
				"driver":   config.Driver,
			},
		)
	}

	return provider, nil
}

// Name returns the provider instance name
func (p *SQLProvider) Name() string {
	return p.name
}

// Type returns the provider type
func (p *SQLProvider) Type() string {
	return "sql"
}

// ResolveEntity executes SQL query to resolve entity information
func (p *SQLProvider) ResolveEntity(ctx context.Context, strategy types.MappingStrategy, params map[string]interface{}) (*types.RawResult, error) {
	// Validate that we have a SQL query
	if strategy.Query == "" {
		return nil, types.NewProviderError("no SQL query configured for strategy", map[string]interface{}{
			"provider": p.name,
			"strategy": strategy.Name,
		})
	}

	// Create query context with timeout
	queryCtx, cancel := context.WithTimeout(ctx, p.config.QueryTimeout)
	defer cancel()

	// Execute the query with parameters
	rows, err := p.db.QueryContext(queryCtx, strategy.Query, p.buildQueryArgs(params)...)
	if err != nil {
		return nil, types.WrapMultiStrategyError(
			types.ErrorTypeProvider,
			"SQL query execution failed",
			err,
			map[string]interface{}{
				"provider": p.name,
				"strategy": strategy.Name,
				"query":    strategy.Query,
			},
		)
	}
	defer rows.Close()

	// Check for errors from query execution
	if err := rows.Err(); err != nil {
		return nil, types.WrapMultiStrategyError(
			types.ErrorTypeProvider,
			"SQL query iteration failed",
			err,
			map[string]interface{}{
				"provider": p.name,
				"strategy": strategy.Name,
			},
		)
	}

	// Get column information
	columns, err := rows.Columns()
	if err != nil {
		return nil, types.WrapMultiStrategyError(
			types.ErrorTypeProvider,
			"failed to get column information",
			err,
			map[string]interface{}{
				"provider": p.name,
				"strategy": strategy.Name,
			},
		)
	}

	// Create result structure
	result := &types.RawResult{
		Data:     make(map[string]interface{}),
		Metadata: make(map[string]interface{}),
	}

	// Process results - expect single row for entity resolution
	if rows.Next() {
		// Create slice to hold column values
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		// Scan the row
		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, types.WrapMultiStrategyError(
				types.ErrorTypeProvider,
				"failed to scan SQL result row",
				err,
				map[string]interface{}{
					"provider": p.name,
					"strategy": strategy.Name,
				},
			)
		}

		// Map columns to result data
		for i, column := range columns {
			result.Data[column] = p.convertSQLValue(values[i])
		}
	}

	// Add metadata
	result.Metadata["provider_type"] = "sql"
	result.Metadata["provider_name"] = p.name
	result.Metadata["query"] = strategy.Query
	result.Metadata["column_count"] = len(columns)
	result.Metadata["row_found"] = len(result.Data) > 0

	return result, nil
}

// HealthCheck verifies the SQL database is accessible
func (p *SQLProvider) HealthCheck(ctx context.Context) error {
	// Use configured health check query or default
	query := p.config.HealthCheckQuery
	if query == "" {
		query = "SELECT 1"
	}

	// Create context with timeout
	healthCtx, cancel := context.WithTimeout(ctx, p.config.HealthCheckTime)
	defer cancel()

	// Execute health check query
	var result interface{}
	err := p.db.QueryRowContext(healthCtx, query).Scan(&result)
	if err != nil {
		return types.WrapMultiStrategyError(
			types.ErrorTypeHealth,
			"SQL health check query failed",
			err,
			map[string]interface{}{
				"provider": p.name,
				"query":    query,
				"driver":   p.config.Driver,
			},
		)
	}

	return nil
}

// GetMapper returns the provider's mapper implementation
func (p *SQLProvider) GetMapper() types.Mapper {
	return p.mapper
}

// Close closes the database connection
func (p *SQLProvider) Close() error {
	if p.db != nil {
		if err := p.db.Close(); err != nil {
			return types.WrapMultiStrategyError(
				types.ErrorTypeProvider,
				"failed to close database connection",
				err,
				map[string]interface{}{
					"provider": p.name,
					"driver":   p.config.Driver,
				},
			)
		}
	}
	return nil
}

// buildConnectionString creates a connection string based on the driver
func (p *SQLProvider) buildConnectionString() (string, error) {
	switch strings.ToLower(p.config.Driver) {
	case "postgres":
		return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			p.config.Host, p.config.Port, p.config.Username, p.config.Password,
			p.config.Database, p.config.SSLMode), nil

	case "mysql":
		return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true",
			p.config.Username, p.config.Password, p.config.Host, p.config.Port,
			p.config.Database), nil

	case "sqlite", "sqlite3":
		return p.config.Database, nil

	default:
		return "", fmt.Errorf("unsupported database driver: %s", p.config.Driver)
	}
}

// buildQueryArgs extracts query arguments from parameters in order
func (p *SQLProvider) buildQueryArgs(params map[string]interface{}) []interface{} {
	// For parameterized queries, we need to maintain parameter order
	// This is a simplified implementation - in practice, you might want
	// to parse the query to determine parameter order
	args := make([]interface{}, 0)

	// Add parameters in a consistent order (alphabetical by key)
	// This assumes the SQL query uses positional parameters ($1, $2, etc.)
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}

	// Sort keys for consistent parameter ordering
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[i] > keys[j] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}

	for _, key := range keys {
		args = append(args, params[key])
	}

	return args
}

// convertSQLValue converts SQL result values to appropriate Go types
func (p *SQLProvider) convertSQLValue(value interface{}) interface{} {
	// Handle NULL values
	if value == nil {
		return nil
	}

	// Convert byte arrays to strings (common for text fields)
	if bytes, ok := value.([]byte); ok {
		return string(bytes)
	}

	// Return value as-is for other types
	return value
}
