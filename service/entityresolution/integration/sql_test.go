package integration

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"testing"

	"github.com/creasty/defaults"
	"github.com/opentdf/platform/service/entityresolution/integration/internal"
	sqlv2 "github.com/opentdf/platform/service/entityresolution/sql/v2"
	"github.com/opentdf/platform/service/logger"
	tc "github.com/testcontainers/testcontainers-go"
	"go.opentelemetry.io/otel/trace/noop"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/mattn/go-sqlite3"
)

// TestSQLEntityResolutionV2 runs all ERS tests against SQL implementation using the generic contract test framework
func TestSQLEntityResolutionV2(t *testing.T) {
	contractSuite := internal.NewContractTestSuite()
	adapter := NewSQLTestAdapter()

	contractSuite.RunContractTestsWithAdapter(t, adapter)
}

// TestSQLiteEntityResolutionV2 runs all ERS tests against SQLite specifically
func TestSQLiteEntityResolutionV2(t *testing.T) {
	// This is the same as TestSQLEntityResolutionV2 but with a more specific name
	// It uses the same adapter which defaults to SQLite
	contractSuite := internal.NewContractTestSuite()
	adapter := NewSQLTestAdapter()

	contractSuite.RunContractTestsWithAdapter(t, adapter)
}

// TestPostgreSQLEntityResolutionV2 runs all ERS tests against PostgreSQL specifically
func TestPostgreSQLEntityResolutionV2(t *testing.T) {
	if pgContainer == nil {
		t.Skip("PostgreSQL container not available")
	}

	// For PostgreSQL-specific testing, we would need a PostgreSQL-specific adapter
	// For now, we'll skip this as the current SQL adapter defaults to SQLite
	t.Skip("PostgreSQL-specific adapter not yet implemented - use the generic SQL adapter")
}

var pgContainer tc.Container
var sqliteConfig *SQLiteTestConfig
var postgresqlConfig *PostgreSQLTestConfig

// SQLiteTestConfig holds SQLite-specific test configuration
type SQLiteTestConfig struct {
	Driver string `json:"driver" default:"sqlite3"`
	DSN    string `json:"dsn" default:":memory:"`
}

// PostgreSQLTestConfig holds PostgreSQL-specific test configuration
type PostgreSQLTestConfig struct {
	Host     string `json:"host" default:"localhost"`
	Port     int    `json:"port" default:"5432"`
	User     string `json:"user" default:"postgres"`
	Password string `json:"password" default:"postgres"`
	Database string `json:"database" default:"opentdf_ers_test"`
}

// initPostgreSQLConfig initializes the PostgreSQL configuration with defaults
func initPostgreSQLConfig() error {
	if postgresqlConfig == nil {
		postgresqlConfig = &PostgreSQLTestConfig{}
		if err := defaults.Set(postgresqlConfig); err != nil {
			return fmt.Errorf("failed to set PostgreSQL config defaults: %w", err)
		}
	}
	return nil
}

// CreateSQLiteV2Service creates a configured SQLite v2 ERS service for testing
func CreateSQLiteV2Service() (*sqlv2.SQLEntityResolutionServiceV2, error) {
	// Create a fresh in-memory SQLite database for this service
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database: %w", err)
	}

	// Create tables and load fixtures in the new database
	if err := CreateSQLiteTestTablesInDB(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create test tables: %w", err)
	}

	if err := LoadSQLiteFixturesInDB(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to load fixtures: %w", err)
	}

	sqlConfig := map[string]any{
		"driver": "sqlite3",
		"dsn":    ":memory:",
		"query_mapping": map[string]any{
			"username_query":  "SELECT username, email, display_name FROM users WHERE username = ?",
			"email_query":     "SELECT username, email, display_name FROM users WHERE email = ?",
			"client_id_query": "SELECT client_id, display_name, description FROM clients WHERE client_id = ?",
		},
		"column_mapping": map[string]any{
			"username":     "username",
			"email":        "email",
			"display_name": "display_name",
			"client_id":    "client_id",
		},
		"inferid": map[string]any{
			"from": map[string]any{
				"clientid": true,
				"email":    true,
				"username": true,
			},
		},
	}

	testLogger := logger.CreateTestLogger()
	service, _ := sqlv2.RegisterSQLERS(sqlConfig, testLogger)

	// Set a no-op tracer for testing to prevent nil pointer dereference
	service.Tracer = noop.NewTracerProvider().Tracer("test-sqlite-v2")

	// Replace the service's database with our prepared one
	service.Close() // Close the service's default connection
	service.DB = db // Use our prepared database

	return service, nil
}

// CreatePostgreSQLV2Service creates a configured PostgreSQL v2 ERS service for testing
func CreatePostgreSQLV2Service() (*sqlv2.SQLEntityResolutionServiceV2, error) {
	if pgContainer == nil {
		return nil, fmt.Errorf("PostgreSQL container not available")
	}

	// Initialize PostgreSQL config if not already done
	if err := initPostgreSQLConfig(); err != nil {
		return nil, err
	}

	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		postgresqlConfig.Host, postgresqlConfig.Port,
		postgresqlConfig.User, postgresqlConfig.Password, postgresqlConfig.Database)

	sqlConfig := map[string]any{
		"driver": "pgx",
		"dsn":    dsn,
		"query_mapping": map[string]any{
			"username_query":  "SELECT username, email, display_name FROM users WHERE username = $1",
			"email_query":     "SELECT username, email, display_name FROM users WHERE email = $1",
			"client_id_query": "SELECT client_id, display_name, description FROM clients WHERE client_id = $1",
		},
		"column_mapping": map[string]any{
			"username":     "username",
			"email":        "email",
			"display_name": "display_name",
			"client_id":    "client_id",
		},
		"inferid": map[string]any{
			"from": map[string]any{
				"clientid": true,
				"email":    true,
				"username": true,
			},
		},
	}

	testLogger := logger.CreateTestLogger()
	service, _ := sqlv2.RegisterSQLERS(sqlConfig, testLogger)

	// Set a no-op tracer for testing to prevent nil pointer dereference
	service.Tracer = noop.NewTracerProvider().Tracer("test-postgresql-v2")

	return service, nil
}

// SQLTestDataInjector implements test data injection for SQL backends
type SQLTestDataInjector struct {
	db     *sql.DB
	logger *logger.Logger
}

// NewSQLTestDataInjector creates a new SQL test data injector
func NewSQLTestDataInjector(db *sql.DB, logger *logger.Logger) *SQLTestDataInjector {
	return &SQLTestDataInjector{
		db:     db,
		logger: logger,
	}
}

// InjectTestData injects contract test data into SQL database
func (injector *SQLTestDataInjector) InjectTestData(ctx context.Context, dataSet *internal.ContractTestDataSet) error {
	// Create tables if they don't exist
	if err := injector.createTables(ctx); err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	// Inject users
	for _, user := range dataSet.Users {
		if err := injector.insertUser(ctx, user); err != nil {
			injector.logger.Error("failed to insert user", slog.String("username", user.Username), slog.String("error", err.Error()))
			return fmt.Errorf("failed to insert user %s: %w", user.Username, err)
		}
	}

	// Inject clients
	for _, client := range dataSet.Clients {
		if err := injector.insertClient(ctx, client); err != nil {
			injector.logger.Error("failed to insert client", slog.String("client_id", client.ClientID), slog.String("error", err.Error()))
			return fmt.Errorf("failed to insert client %s: %w", client.ClientID, err)
		}
	}

	injector.logger.Info("contract test data injected successfully into SQL database")
	return nil
}

// CleanupTestData removes all test data from SQL database
func (injector *SQLTestDataInjector) CleanupTestData(ctx context.Context) error {
	queries := []string{
		"DELETE FROM clients",
		"DELETE FROM users",
	}

	for _, query := range queries {
		if _, err := injector.db.ExecContext(ctx, query); err != nil {
			return fmt.Errorf("failed to execute cleanup query %s: %w", query, err)
		}
	}

	injector.logger.Info("SQL test data cleanup completed")
	return nil
}

// ValidateTestData validates that test data exists in SQL database
func (injector *SQLTestDataInjector) ValidateTestData(ctx context.Context, dataSet *internal.ContractTestDataSet) error {
	// Validate users exist
	for _, user := range dataSet.Users {
		if err := injector.validateUser(ctx, user); err != nil {
			return fmt.Errorf("user validation failed for %s: %w", user.Username, err)
		}
	}

	// Validate clients exist
	for _, client := range dataSet.Clients {
		if err := injector.validateClient(ctx, client); err != nil {
			return fmt.Errorf("client validation failed for %s: %w", client.ClientID, err)
		}
	}

	injector.logger.Info("SQL test data validation completed successfully")
	return nil
}

// createTables creates the necessary tables for test data
func (injector *SQLTestDataInjector) createTables(ctx context.Context) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			username VARCHAR(255) PRIMARY KEY,
			email VARCHAR(255) UNIQUE NOT NULL,
			display_name VARCHAR(255) NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS clients (
			client_id VARCHAR(255) PRIMARY KEY,
			description TEXT,
			display_name VARCHAR(255)
		)`,
	}

	for _, query := range queries {
		if _, err := injector.db.ExecContext(ctx, query); err != nil {
			return fmt.Errorf("failed to execute table creation query: %w", err)
		}
	}

	return nil
}

// insertUser inserts a user into the SQL database
func (injector *SQLTestDataInjector) insertUser(ctx context.Context, user internal.TestUser) error {
	query := `INSERT OR REPLACE INTO users (username, email, display_name, password_hash) VALUES (?, ?, ?, ?)`
	passwordHash := user.Password
	if passwordHash == "" {
		passwordHash = "test-password-hash"
	}
	_, err := injector.db.ExecContext(ctx, query, user.Username, user.Email, user.DisplayName, passwordHash)
	return err
}

// insertClient inserts a client into the SQL database
func (injector *SQLTestDataInjector) insertClient(ctx context.Context, client internal.TestClient) error {
	query := `INSERT OR REPLACE INTO clients (client_id, description, display_name) VALUES (?, ?, ?)`
	_, err := injector.db.ExecContext(ctx, query, client.ClientID, client.Description, client.ClientID)
	return err
}

// validateUser validates that a user exists in the SQL database
func (injector *SQLTestDataInjector) validateUser(ctx context.Context, user internal.TestUser) error {
	query := `SELECT username, email, display_name FROM users WHERE username = ?`
	row := injector.db.QueryRowContext(ctx, query, user.Username)

	var username, email, displayName string
	err := row.Scan(&username, &email, &displayName)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("user not found")
		}
		return fmt.Errorf("query failed: %w", err)
	}

	if email != user.Email {
		return fmt.Errorf("email mismatch: expected %s, got %s", user.Email, email)
	}

	return nil
}

// validateClient validates that a client exists in the SQL database
func (injector *SQLTestDataInjector) validateClient(ctx context.Context, client internal.TestClient) error {
	query := `SELECT client_id, description FROM clients WHERE client_id = ?`
	row := injector.db.QueryRowContext(ctx, query, client.ClientID)

	var clientID, description string
	err := row.Scan(&clientID, &description)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("client not found")
		}
		return fmt.Errorf("query failed: %w", err)
	}

	return nil
}

// SQLTestAdapter implements ERSTestAdapter for SQL ERS testing
type SQLTestAdapter struct {
	service interface {
		internal.ERSImplementation
		Close() error
	}
}

// NewSQLTestAdapter creates a new SQL test adapter
func NewSQLTestAdapter() *SQLTestAdapter {
	return &SQLTestAdapter{}
}

// GetScopeName returns the scope name for SQL ERS
func (a *SQLTestAdapter) GetScopeName() string {
	return "SQL"
}

// SetupTestData injects test data into the SQL database
func (a *SQLTestAdapter) SetupTestData(ctx context.Context, testDataSet *internal.ContractTestDataSet) error {
	// Create the SQL service first so we can access the database
	service, err := CreateSQLiteV2Service()
	if err != nil {
		return err
	}
	a.service = service

	// Use the SQL test data injector to inject the contract test data
	injector := NewSQLTestDataInjector(service.DB, service.Logger)
	return injector.InjectTestData(ctx, testDataSet)
}

// CreateERSService creates and returns a configured SQL ERS service
func (a *SQLTestAdapter) CreateERSService(ctx context.Context) (internal.ERSImplementation, error) {
	if a.service == nil {
		return nil, fmt.Errorf("service not initialized - call SetupTestData first")
	}
	return a.service, nil
}

// TeardownTestData cleans up SQL test data and resources
func (a *SQLTestAdapter) TeardownTestData(ctx context.Context) error {
	if a.service != nil {
		return a.service.Close()
	}
	return nil
}

// CreateSQLiteTestTablesInDB creates test tables in a specific SQLite database
func CreateSQLiteTestTablesInDB(db *sql.DB) error {
	// Users table
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			email TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		return fmt.Errorf("failed to create users table: %w", err)
	}

	// Clients table
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS clients (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			client_id TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			description TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		return fmt.Errorf("failed to create clients table: %w", err)
	}

	// Groups table
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS groups (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			description TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		return fmt.Errorf("failed to create groups table: %w", err)
	}

	// User groups junction table
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS user_groups (
			user_id INTEGER NOT NULL,
			group_id INTEGER NOT NULL,
			PRIMARY KEY (user_id, group_id),
			FOREIGN KEY (user_id) REFERENCES users(id),
			FOREIGN KEY (group_id) REFERENCES groups(id)
		)
	`); err != nil {
		return fmt.Errorf("failed to create user_groups table: %w", err)
	}

	return nil
}

// LoadSQLiteFixturesInDB loads test data into a specific SQLite database
func LoadSQLiteFixturesInDB(db *sql.DB) error {
	ctx := context.Background()

	// Insert users
	for _, user := range internal.TestUsers {
		if _, err := db.ExecContext(ctx,
			"INSERT OR IGNORE INTO users (username, email, display_name, password_hash) VALUES (?, ?, ?, ?)",
			user.Username, user.Email, user.DisplayName, user.Password); err != nil {
			return fmt.Errorf("failed to insert user %s: %w", user.Username, err)
		}
	}

	// Insert clients
	for _, client := range internal.TestClients {
		if _, err := db.ExecContext(ctx,
			"INSERT OR IGNORE INTO clients (client_id, display_name, description) VALUES (?, ?, ?)",
			client.ClientID, client.DisplayName, client.Description); err != nil {
			return fmt.Errorf("failed to insert client %s: %w", client.ClientID, err)
		}
	}

	// Insert groups
	for _, group := range internal.TestGroups {
		if _, err := db.ExecContext(ctx,
			"INSERT OR IGNORE INTO groups (name, display_name, description) VALUES (?, ?, ?)",
			group.Name, group.DisplayName, group.Description); err != nil {
			return fmt.Errorf("failed to insert group %s: %w", group.Name, err)
		}
	}

	// Insert user-group relationships
	for _, group := range internal.TestGroups {
		for _, memberUsername := range group.Members {
			if _, err := db.ExecContext(ctx, `
				INSERT OR IGNORE INTO user_groups (user_id, group_id) 
				SELECT u.id, g.id FROM users u, groups g 
				WHERE u.username = ? AND g.name = ?`,
				memberUsername, group.Name); err != nil {
				return fmt.Errorf("failed to insert user-group relationship %s-%s: %w", memberUsername, group.Name, err)
			}
		}
	}

	return nil
}

// ConnectToTestPostgreSQL creates a connection to the test PostgreSQL instance
func ConnectToTestPostgreSQL() (*sql.DB, error) {
	if pgContainer == nil {
		return nil, fmt.Errorf("PostgreSQL container not available")
	}

	// Initialize PostgreSQL config if not already done
	if err := initPostgreSQLConfig(); err != nil {
		return nil, err
	}

	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		postgresqlConfig.Host, postgresqlConfig.Port,
		postgresqlConfig.User, postgresqlConfig.Password, postgresqlConfig.Database)

	return sql.Open("pgx", dsn)
}



