# Entity Resolution Service Testing Guide

This guide covers the testing infrastructure for the OpenTDF Entity Resolution Service (ERS).

## Overview

The ERS supports multiple backends for entity resolution:
- **Claims**: JWT token processing and claims extraction
- **Keycloak**: Identity provider integration with Admin API
- **Multi-Strategy**: Configurable multi-provider entity resolution (supports LDAP, SQL, and JWT claims providers)

## Running Tests

### All Tests
```bash
go test ./integration -v
```

### Backend-Specific Tests
```bash
# Claims tests (fast)
go test ./integration -run TestClaims -v

# Multi-Strategy tests (fast, uses JWT claims provider)
go test ./integration -run TestMultiStrategy -v

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

### Multi-Strategy Testing
**File:** `multistrategy_test.go`
**Features:**
- Configurable multi-provider entity resolution
- Strategy-based JWT claims processing
- Failure strategy testing (fail-fast vs continue)
- Entity chain creation and validation
- No external dependencies (uses JWT claims provider)

**Configuration:**
```go
// Uses JWT claims provider for testing
adapter := NewMultiStrategyTestAdapter()
```

**Supported Providers:**
- JWT Claims Provider (used in tests)
- SQL Provider (SQLite/PostgreSQL support)
- LDAP Provider (enterprise directory integration)

**Strategy Testing:**
- Multiple mapping strategies with conditions
- JWT claim matching and processing
- Provider failover and fallback mechanisms

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
- **Multi-Strategy**: JWT claims extraction and strategy matching
- **Keycloak**: User/client creation via Admin API

## Performance and Reliability

### Test Execution Times
- **Claims**: ~0.1s (no external dependencies)
- **Multi-Strategy**: ~0.4s (JWT claims provider, no external dependencies)
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
go test ./integration -run TestMultiStrategy -v

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