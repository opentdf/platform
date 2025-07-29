# Entity Resolution Service Testing Guide

This guide covers the testing infrastructure for the OpenTDF Entity Resolution Service (ERS).

## Overview

The ERS supports multiple backends for entity resolution:
- **Claims**: JWT token processing and claims extraction
- **Keycloak**: Identity provider integration with Admin API
- **LDAP**: Enterprise LDAP directory integration
- **SQL**: Database-backed entity resolution (SQLite and PostgreSQL)

## Running Tests

### All Tests
```bash
go test ./integration -v
```

### Backend-Specific Tests
```bash
# Claims tests (fast)
go test ./integration -run TestClaims -v

# SQLite tests (fast)
go test ./integration -run TestSQLite -v

# PostgreSQL tests (requires Docker)
go test ./integration -run TestPostgreSQL -v

# LDAP tests (requires Docker)
go test ./integration -run TestLDAP -v

# Keycloak tests (requires Docker, longer startup time)
go test ./integration -run TestKeycloak -v -timeout=10m
```

### Skip Container-Based Tests
```bash
go test ./integration -v -short
```

## Test Architecture

### Contract Testing Framework
All ERS implementations use a unified contract testing framework that ensures consistent behavior across backends.

**Key Components:**
- `internal/contract_tests.go` - Common test scenarios
- `internal/test_data.go` - Standardized test datasets
- `internal/contract_framework_test.go` - Framework validation

### Test Adapters
Each backend implements the `ERSTestAdapter` interface:

```go
type ERSTestAdapter interface {
    GetScopeName() string
    SetupTestData(ctx context.Context, testDataSet *ContractTestDataSet) error
    CreateERSService(ctx context.Context) (ERSImplementation, error)
    TeardownTestData(ctx context.Context) error
}
```

## Backend-Specific Testing

### Claims Testing
**File:** `claims_test.go`
**Features:**
- JWT signing and validation infrastructure
- Claims entity processing
- Malformed/expired token handling
- No external dependencies

**Configuration:**
```go
// Automatically generates RSA keys for JWT signing
adapter := NewClaimsTestAdapter()
```

### SQLite Testing
**File:** `sql_sqlite_test.go`
**Features:**
- In-memory database for fast execution
- Complete SQL schema creation
- Transaction-based test isolation

**Configuration:**
```go
// Uses SQLite in-memory database
adapter := NewSQLiteTestAdapter()
```

### PostgreSQL Testing
**File:** `sql_postgres_test.go`
**Features:**
- Docker container with PostgreSQL 15
- Full database lifecycle management
- Production-like testing environment

**Configuration:**
```go
config := &PostgreSQLTestConfig{
    Host:     "localhost",
    Port:     5432, // Auto-assigned by testcontainers
    User:     "postgres",
    Password: "postgres", 
    Database: "opentdf_ers_test",
}
```

### LDAP Testing
**File:** `ldap_test.go`
**Features:**
- OpenLDAP container with test data
- TLS support and connection pooling
- Real LDAP operations testing

**Configuration:**
```go
config := &LDAPTestConfig{
    Host:             "localhost",
    Port:             389, // Auto-assigned by testcontainers
    Organization:     "OpenTDF Test",
    Domain:           "opentdf.test",
    AdminPassword:    "admin_password",
    BaseDN:           "dc=opentdf,dc=test",
}
```

### Keycloak Testing
**File:** `keycloak_test.go`
**Features:**
- Keycloak container with Admin API integration
- Real authentication flows
- User/client lifecycle management

**Configuration:**
```go
config := &KeycloakTestConfig{
    URL:          "http://localhost:8080",
    Realm:        "opentdf",
    ClientID:     "test-client",
    ClientSecret: "test-secret",
    AdminUser:    "admin",
    AdminPass:    "admin_password",
}
```

## Container Management

### Generic Container Helpers
**File:** `internal/container_helpers.go`

Provides generic container lifecycle management infrastructure:

```go
// Each adapter creates its own container configuration
adapter := NewPostgreSQLTestAdapter()
config := adapter.createPostgreSQLContainerConfig()
manager := NewContainerManager(config)

// Start container
ctx := context.Background()
err := manager.Start(ctx)

// Get mapped port
port, err := manager.GetMappedPort(ctx, "5432")

// Cleanup
defer manager.Stop(ctx)
```

### Container Test Suite
For managing multiple containers:

```go
suite := NewContainerTestSuite()

// Each adapter provides its own configuration
postgresAdapter := NewPostgreSQLTestAdapter()
keycloakAdapter := NewKeycloakTestAdapter()

suite.AddContainer("postgres", postgresAdapter.createPostgreSQLContainerConfig())
suite.AddContainer("keycloak", keycloakAdapter.createKeycloakContainerConfig())

// Start all containers
err := suite.StartAll(ctx)
defer suite.StopAll(ctx)
```

## Test Data

### Standard Test Dataset
**File:** `internal/test_data.go`

Provides consistent test data across all backends:

```go
type ContractTestDataSet struct {
    Users   []TestUser
    Clients []TestClient
}

// Standard users: alice, bob, charlie
// Standard clients: test-client-1, test-client-2
```

### Test Data Injection
Each adapter handles backend-specific data injection:

- **Claims**: JWT key generation and token creation
- **SQL**: Database table creation and row insertion
- **LDAP**: LDAP entry creation via LDAP operations
- **Keycloak**: User/client creation via Admin API

## Performance and Reliability

### Test Execution Times
- **Claims**: ~0.1s (no external dependencies)
- **SQLite**: ~0.4s (in-memory database)
- **PostgreSQL**: ~3.5s (includes container startup)
- **LDAP**: ~10s (includes container startup and data injection)
- **Keycloak**: ~30s (includes container startup and configuration)

### Reliability Features
- Automatic container cleanup on test completion
- Retry logic for container readiness checks
- Graceful handling of container lifecycle errors
- Parallel test execution safety

## Troubleshooting

### Common Issues

**Docker/Podman Setup:**
```bash
# For Podman users
export TESTCONTAINERS_PODMAN=true
export TESTCONTAINERS_RYUK_CONTAINER_PRIVILEGED=true

# For Colima users  
export DOCKER_HOST="unix://${HOME}/.colima/default/docker.sock"
export TESTCONTAINERS_RYUK_DISABLED=true
```

**Port Conflicts:**
- Tests use random ports assigned by testcontainers
- No manual port configuration needed

**Container Startup Timeouts:**
```bash
# Increase timeout for slow systems
go test ./integration -timeout=15m
```

**Debug Container Issues:**
```bash
# Enable container logs
TESTCONTAINERS_DEBUG=true go test ./integration -v
```

### Test Isolation
- Each test run uses fresh containers
- In-memory databases for SQLite tests
- Separate realms/databases per test execution
- No shared state between test runs

## Integration with CI/CD

### GitHub Actions
```yaml
- name: Run Integration Tests
  run: |
    # Start Docker daemon
    # Run tests with appropriate timeout
    go test ./integration -v -timeout=15m
```

### Local Development
```bash
# Quick tests during development
go test ./integration -run TestSQLite -v

# Full test suite before commits
make test-integration
```

## Future Enhancements

### Planned Improvements
1. **Caching Layer**: Query result caching for SQL/LDAP backends
2. **Performance Metrics**: OpenTelemetry integration for monitoring
3. **Load Testing**: Benchmark tests for performance validation
4. **Multi-Database**: Support for MySQL and other SQL databases
5. **HA Testing**: High availability and failover testing