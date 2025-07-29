package integration

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strconv"
	"testing"
	"time"

	"github.com/creasty/defaults"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/opentdf/platform/service/entityresolution/integration/internal"
	sqlv2 "github.com/opentdf/platform/service/entityresolution/sql/v2"
	"github.com/opentdf/platform/service/logger"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.opentelemetry.io/otel/trace/noop"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// TestPostgreSQLEntityResolutionV2 runs all ERS tests against PostgreSQL implementation using the generic contract test framework
func TestPostgreSQLEntityResolutionV2(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping PostgreSQL integration tests in short mode")
	}

	contractSuite := internal.NewContractTestSuite()
	adapter := NewPostgreSQLTestAdapter()

	contractSuite.RunContractTestsWithAdapter(t, adapter)
}

var postgresContainer tc.Container
var postgresConfig *PostgreSQLTestConfig

// PostgreSQLTestConfig holds PostgreSQL-specific test configuration
type PostgreSQLTestConfig struct {
	Host     string `json:"host" default:"localhost"`
	Port     int    `json:"port" default:"5432"`
	User     string `json:"user" default:"postgres"`
	Password string `json:"password" default:"postgres"`
	Database string `json:"database" default:"opentdf_ers_test"`
}

// PostgreSQLTestAdapter implements ERSTestAdapter for PostgreSQL ERS testing
type PostgreSQLTestAdapter struct {
	service       *sqlv2.SQLEntityResolutionServiceV2
	db            *sql.DB
	config        *PostgreSQLTestConfig
	containerSetup bool
}

// NewPostgreSQLTestAdapter creates a new PostgreSQL test adapter
func NewPostgreSQLTestAdapter() *PostgreSQLTestAdapter {
	config := &PostgreSQLTestConfig{}
	if err := defaults.Set(config); err != nil {
		panic(fmt.Errorf("failed to set PostgreSQL config defaults: %w", err))
	}

	return &PostgreSQLTestAdapter{
		config: config,
	}
}

// GetScopeName returns the scope name for PostgreSQL ERS
func (a *PostgreSQLTestAdapter) GetScopeName() string {
	return "PostgreSQL"
}

// SetupTestData sets up PostgreSQL container and injects test data
func (a *PostgreSQLTestAdapter) SetupTestData(ctx context.Context, testDataSet *internal.ContractTestDataSet) error {
	// Setup PostgreSQL container if not already done
	if !a.containerSetup {
		if err := a.setupPostgreSQLContainer(ctx); err != nil {
			return fmt.Errorf("failed to setup PostgreSQL container: %w", err)
		}
		a.containerSetup = true
	}

	// Connect to PostgreSQL database
	if err := a.connectToPostgreSQL(); err != nil {
		return fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}

	// Create tables
	if err := a.createPostgreSQLTables(); err != nil {
		return fmt.Errorf("failed to create PostgreSQL tables: %w", err)
	}

	// Inject test data using the contract test dataset
	if err := a.injectTestData(ctx, testDataSet); err != nil {
		return fmt.Errorf("failed to inject test data: %w", err)
	}

	return nil
}

// CreateERSService creates and returns a configured PostgreSQL ERS service
func (a *PostgreSQLTestAdapter) CreateERSService(ctx context.Context) (internal.ERSImplementation, error) {
	if a.db == nil {
		return nil, fmt.Errorf("database not initialized - call SetupTestData first")
	}

	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		a.config.Host, a.config.Port,
		a.config.User, a.config.Password, a.config.Database)

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

	a.service = service
	return service, nil
}

// TeardownTestData cleans up PostgreSQL test data and resources
func (a *PostgreSQLTestAdapter) TeardownTestData(ctx context.Context) error {
	if a.service != nil {
		if err := a.service.Close(); err != nil {
			slog.Warn("Failed to close PostgreSQL service", "error", err.Error())
		}
		a.service = nil
	}
	if a.db != nil {
		if err := a.db.Close(); err != nil {
			slog.Warn("Failed to close PostgreSQL database", "error", err.Error())
		}
		a.db = nil
	}
	if postgresContainer != nil {
		if err := postgresContainer.Terminate(ctx); err != nil {
			// Log warning but don't fail the test - container might already be terminated
			slog.Warn("Failed to terminate PostgreSQL container", "error", err.Error())
		}
		postgresContainer = nil
		a.containerSetup = false
	}
	return nil
}

// createPostgreSQLContainerConfig returns a PostgreSQL container configuration
func (a *PostgreSQLTestAdapter) createPostgreSQLContainerConfig() internal.ContainerConfig {
	return internal.ContainerConfig{
		Image:        "postgres:15-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     a.config.User,
			"POSTGRES_PASSWORD": a.config.Password,
			"POSTGRES_DB":       a.config.Database,
		},
		WaitStrategy: wait.ForAll(
			wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(60*time.Second),
			wait.ForSQL("5432/tcp", "pgx", func(host string, port nat.Port) string {
				return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
					host, port.Int(), a.config.User, a.config.Password, a.config.Database)
			}).WithStartupTimeout(60*time.Second),
		),
		Timeout: 2 * time.Minute,
	}
}

// setupPostgreSQLContainer starts a PostgreSQL container for testing
func (a *PostgreSQLTestAdapter) setupPostgreSQLContainer(ctx context.Context) error {
	containerConfig := a.createPostgreSQLContainerConfig() 

	req := tc.ContainerRequest{
		Image:        containerConfig.Image,
		ExposedPorts: containerConfig.ExposedPorts,
		Env:          containerConfig.Env,
		WaitingFor:   containerConfig.WaitStrategy,
		HostConfigModifier: func(hostConfig *container.HostConfig) {
			hostConfig.AutoRemove = true
		},
	}

	container, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return fmt.Errorf("failed to start PostgreSQL container: %w", err)
	}

	postgresContainer = container

	// Get mapped port
	mappedPort, err := container.MappedPort(ctx, "5432")
	if err != nil {
		return fmt.Errorf("failed to get mapped port: %w", err)
	}

	// Update config with actual container details
	a.config.Port = mappedPort.Int()

	// Wait for PostgreSQL to be fully ready
	if err := a.waitForPostgreSQLReady(ctx); err != nil {
		return fmt.Errorf("PostgreSQL container not ready: %w", err)
	}

	return nil
}

// waitForPostgreSQLReady waits for PostgreSQL to be fully operational
func (a *PostgreSQLTestAdapter) waitForPostgreSQLReady(ctx context.Context) error {
	return internal.WaitForContainer(ctx, func() error {
		dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
			a.config.Host, a.config.Port,
			a.config.User, a.config.Password, a.config.Database)

		db, err := sql.Open("pgx", dsn)
		if err != nil {
			return fmt.Errorf("failed to open database: %w", err)
		}
		defer db.Close()

		if err := db.Ping(); err != nil {
			return fmt.Errorf("failed to ping database: %w", err)
		}

		return nil
	}, 30, 2*time.Second)
}

// connectToPostgreSQL establishes connection to PostgreSQL database
func (a *PostgreSQLTestAdapter) connectToPostgreSQL() error {
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		a.config.Host, a.config.Port,
		a.config.User, a.config.Password, a.config.Database)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("failed to open PostgreSQL database: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return fmt.Errorf("failed to ping PostgreSQL database: %w", err)
	}

	a.db = db
	return nil
}

// createPostgreSQLTables creates test tables in the PostgreSQL database
func (a *PostgreSQLTestAdapter) createPostgreSQLTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			username VARCHAR(255) UNIQUE NOT NULL,
			email VARCHAR(255) UNIQUE NOT NULL,
			display_name VARCHAR(255) NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS clients (
			id SERIAL PRIMARY KEY,
			client_id VARCHAR(255) UNIQUE NOT NULL,
			display_name VARCHAR(255) NOT NULL,
			description TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS groups (
			id SERIAL PRIMARY KEY,
			name VARCHAR(255) UNIQUE NOT NULL,
			display_name VARCHAR(255) NOT NULL,
			description TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS user_groups (
			user_id INTEGER NOT NULL,
			group_id INTEGER NOT NULL,
			PRIMARY KEY (user_id, group_id),
			FOREIGN KEY (user_id) REFERENCES users(id),
			FOREIGN KEY (group_id) REFERENCES groups(id)
		)`,
	}

	for _, query := range queries {
		if _, err := a.db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute table creation query: %w", err)
		}
	}

	return nil
}

// injectTestData injects contract test data into the PostgreSQL database
func (a *PostgreSQLTestAdapter) injectTestData(ctx context.Context, testDataSet *internal.ContractTestDataSet) error {
	// Insert users
	for _, user := range testDataSet.Users {
		if err := a.insertUser(ctx, user); err != nil {
			return fmt.Errorf("failed to insert user %s: %w", user.Username, err)
		}
	}

	// Insert clients
	for _, client := range testDataSet.Clients {
		if err := a.insertClient(ctx, client); err != nil {
			return fmt.Errorf("failed to insert client %s: %w", client.ClientID, err)
		}
	}

	return nil
}

// insertUser inserts a user into the PostgreSQL database
func (a *PostgreSQLTestAdapter) insertUser(ctx context.Context, user internal.TestUser) error {
	query := `INSERT INTO users (username, email, display_name, password_hash) VALUES ($1, $2, $3, $4) 
		ON CONFLICT (username) DO UPDATE SET 
		email = EXCLUDED.email, 
		display_name = EXCLUDED.display_name, 
		password_hash = EXCLUDED.password_hash`
	
	passwordHash := user.Password
	if passwordHash == "" {
		passwordHash = "test-password-hash"
	}
	_, err := a.db.ExecContext(ctx, query, user.Username, user.Email, user.DisplayName, passwordHash)
	return err
}

// insertClient inserts a client into the PostgreSQL database
func (a *PostgreSQLTestAdapter) insertClient(ctx context.Context, client internal.TestClient) error {
	query := `INSERT INTO clients (client_id, display_name, description) VALUES ($1, $2, $3) 
		ON CONFLICT (client_id) DO UPDATE SET 
		display_name = EXCLUDED.display_name, 
		description = EXCLUDED.description`
	
	displayName := client.DisplayName
	if displayName == "" {
		displayName = client.ClientID
	}
	_, err := a.db.ExecContext(ctx, query, client.ClientID, displayName, client.Description)
	return err
}

// Helper function to get PostgreSQL configuration for use in other tests
func GetPostgreSQLConfig() *PostgreSQLTestConfig {
	if postgresConfig == nil {
		postgresConfig = &PostgreSQLTestConfig{}
		if err := defaults.Set(postgresConfig); err != nil {
			panic(fmt.Errorf("failed to set PostgreSQL config defaults: %w", err))
		}
	}
	return postgresConfig
}

// Helper function to get PostgreSQL DSN for use in other tests
func GetPostgreSQLDSN(config *PostgreSQLTestConfig) string {
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		config.Host, strconv.Itoa(config.Port),
		config.User, config.Password, config.Database)
}