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

## Developer Guide: Adding ERS Implementations and Tests

### Quick Start: Adding a New ERS Implementation

To integrate a new Entity Resolution Service backend with the testing framework:

#### 1. Create Your Test Adapter

Implement the `ERSTestAdapter` interface in a new file (e.g., `mybackend_test.go`):

```go
type MyBackendTestAdapter struct {
    config MyBackendConfig
    // ... backend-specific fields
}

func NewMyBackendTestAdapter() *MyBackendTestAdapter {
    return &MyBackendTestAdapter{
        config: getMyBackendConfig(),
    }
}

func (a *MyBackendTestAdapter) GetScopeName() string {
    return "MyBackend"
}

func (a *MyBackendTestAdapter) SetupTestData(ctx context.Context, testDataSet *internal.ContractTestDataSet) error {
    // Inject test users and clients into your backend
    // Use testDataSet.Users and testDataSet.Clients
    return nil
}

func (a *MyBackendTestAdapter) CreateERSService(ctx context.Context) (internal.ERSImplementation, error) {
    // Return your ERS implementation
    return mybackend.NewMyBackendERS(a.config), nil
}

func (a *MyBackendTestAdapter) TeardownTestData(ctx context.Context) error {
    // Clean up any resources
    return nil
}
```

#### 2. Add Your Tests to the Unified Suite

```go
func TestMyBackend_ContractTests(t *testing.T) {
    adapter := NewMyBackendTestAdapter()
    internal.RunContractTestSuite(t, adapter)
}

func TestMyBackend_EntityChainTests(t *testing.T) {
    adapter := NewMyBackendTestAdapter()
    internal.RunEntityChainContractTests(t, adapter)
}
```

That's it! Your backend will automatically run through all contract tests.

### Best Practices for ERS Integration

#### ✅ Use Dynamic Test Data

**Good:** Use the parameterized test data generators
```go
func (a *MyBackendTestAdapter) SetupTestData(ctx context.Context, testDataSet *internal.ContractTestDataSet) error {
    // Use provided test data
    for _, user := range testDataSet.Users {
        err := a.backend.CreateUser(user.Username, user.Email, user.DisplayName)
        if err != nil {
            return err
        }
    }
    return nil
}
```

**Avoid:** Hardcoding test data
```go
// Don't do this - hardcoded and inflexible
users := []User{
    {Username: "alice", Email: "alice@test.com"},
    {Username: "bob", Email: "bob@test.com"},
}
```

#### ✅ Use Flexible Test Expectations

**Good:** Use range-based validation
```go
// Test your specific business logic
expectation := internal.FlexibleEntityChainExpectation{
    EphemeralID:    "test-token-1",
    MinEntityCount: 1,                    // At least 1 entity
    MaxEntityCount: 5,                    // At most 5 entities
    RequiredClaims: []string{"username"}, // Must have username
    AllowImplementationGaps: true,        // Accept variations
}
```

**Avoid:** Exact count expectations
```go
// Don't do this - brittle
assert.Equal(t, 2, len(chain.Entities))
```

#### ✅ Use Environment-Aware Configuration

**Good:** Leverage the configuration system
```go
func getMyBackendConfig() MyBackendConfig {
    config := internal.GetTestConfig()
    return MyBackendConfig{
        DatabaseURL: config.PostgresConnectionString("mydb", "user", "pass"),
        Timeout:     config.ContainerStartupTimeout,
        // ... other configurable settings
    }
}
```

**Avoid:** Hardcoded configuration
```go
// Don't do this - not configurable
config := MyBackendConfig{
    DatabaseURL: "postgres://localhost:5432/mydb",
    Timeout:     2 * time.Minute,
}
```

#### ✅ Generate Realistic JWTs for Testing

**Good:** Use dynamic JWT generation with multi-strategy routing support
```go
// Basic JWT generation with current timestamps
aliceToken := internal.CreateTestJWT("web-client", "alice", "alice@company.com")

// Multi-strategy routing scenarios (uses different audiences for routing decisions)
internalToken := internal.CreateInternalJWT("web-client", "alice", "alice@company.com")     // Routes to JWT claims
externalToken := internal.CreateExternalJWT("partner-app", "bob", "bob@partner.org", "ext_456") // Routes to DB lookup  
customerToken := internal.CreateCustomerJWT("customer-app", "charlie", "charlie@customer.com") // Routes to customer DB

// Custom claims for specific test scenarios
customToken := internal.CreateTestJWTWithClaims("test-client", "testuser", "test@example.com", map[string]interface{}{
    "aud": []string{"custom-audience"},
    "iss": "custom-issuer",
    "role": "admin",
})

// Complete test set for comprehensive multi-strategy testing
testSet := internal.CreateMultiStrategyTestSet()
// Returns map with keys: "internal-user", "external-partner", "customer-portal", "device-context", "fallback-email"
```

**Avoid:** Static test tokens
```go
// Don't do this - same token everywhere, breaks multi-strategy routing tests
token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Advanced Integration Patterns

#### Container-Based Backends

If your backend requires containers (databases, external services):

```go
func (a *MyBackendTestAdapter) SetupTestData(ctx context.Context, testDataSet *internal.ContractTestDataSet) error {
    // Start your container
    config := internal.GetTestConfig()
    containerConfig := internal.ContainerConfig{
        Image:        config.GetBackendImage(), // Configurable image
        ExposedPorts: []string{"5432/tcp"},
        Env: map[string]string{
            "POSTGRES_DB":       "testdb",
            "POSTGRES_USER":     "testuser", 
            "POSTGRES_PASSWORD": "testpass",
        },
        WaitStrategy: wait.ForListeningPort("5432/tcp").
                     WithStartupTimeout(config.ContainerStartupTimeout),
        Timeout: config.ContainerRunTimeout,
    }
    
    manager := internal.NewContainerManager(containerConfig)
    err := manager.Start(ctx)
    if err != nil {
        return err
    }
    
    // Store manager for cleanup
    a.containerManager = manager
    
    // Inject test data
    return a.injectTestData(testDataSet)
}
```

#### Multi-Strategy Patterns

For complex routing/strategy-based backends, use the built-in multi-strategy JWT helpers:

```go
func NewMyMultiStrategyTestAdapter() *MyMultiStrategyTestAdapter {
    return &MyMultiStrategyTestAdapter{
        config: createMultiStrategyConfig(),
    }
}

func (a *MyMultiStrategyTestAdapter) SetupTestData(ctx context.Context, testDataSet *internal.ContractTestDataSet) error {
    // Use multi-strategy test set to create tokens for different routing scenarios
    testSet := internal.CreateMultiStrategyTestSet()
    
    // Test internal routing (JWT claims provider)
    internalToken := internal.CreateInternalJWT("web-client", "alice", "alice@company.com")
    a.testTokens["internal"] = internalToken
    
    // Test external routing (database lookup provider)  
    externalToken := internal.CreateExternalJWT("partner-app", "bob", "bob@partner.org", "ext_user_456")
    a.testTokens["external"] = externalToken
    
    // Test environment context routing
    deviceToken := internal.CreateEnvironmentJWT("mobile-app", "192.168.1.100", "device-12345") 
    a.testTokens["environment"] = deviceToken
    
    return nil
}

func (a *MyMultiStrategyTestAdapter) testRoutingScenarios(t *testing.T) {
    // Test that different audiences route to different providers
    for scenario, token := range a.testTokens {
        t.Run(fmt.Sprintf("Route_%s", scenario), func(t *testing.T) {
            response := a.callERS(token)
            // Verify the response matches expected routing behavior
            a.validateRoutingStrategy(t, scenario, response)
        })
    }
}
```

**Multi-Strategy JWT Audience Patterns:**
- `internal`, `opentdf-internal` → JWT claims provider (zero-latency)
- `external`, `partner`, `customer` → Database lookup provider 
- `device-context` → Environment entity provider
- No specific audience → Fallback email lookup

**Example Multi-Strategy Configuration Testing:**
```go
func (a *MyMultiStrategyTestAdapter) testFailureStrategies(t *testing.T) {
    // Test fail-fast vs continue strategies
    testCases := []struct {
        strategy types.FailureStrategy
        token    string
        expectError bool
    }{
        {types.FailureStrategyFailFast, "invalid-token", true},
        {types.FailureStrategyContinue, "partial-token", false}, // Should try fallback strategies
    }
    
    for _, tc := range testCases {
        t.Run(fmt.Sprintf("FailureStrategy_%s", tc.strategy), func(t *testing.T) {
            adapter := a.withFailureStrategy(tc.strategy)
            result, err := adapter.resolveToken(tc.token)
            
            if tc.expectError && err == nil {
                t.Errorf("Expected error with %s strategy", tc.strategy)
            }
            if !tc.expectError && err != nil {
                t.Errorf("Expected success with %s strategy, got: %v", tc.strategy, err)
            }
        })
    }
}
```

### Testing Your Integration

#### 1. Validate JWT Processing
```bash
# Test JWT generation works correctly
go test ./integration/internal -v -run TestCreateTestJWT
```

#### 2. Run Contract Tests
```bash
# Test your backend implementation
go test ./integration -run TestMyBackend -v
```

#### 3. Test Configuration
```bash
# Test with custom configuration
TEST_POSTGRES_PORT=5433 TEST_CONTAINER_STARTUP_TIMEOUT=3m go test ./integration -run TestMyBackend -v
```

### Common Patterns

#### Test Data Injection
```go
func (a *MyBackendTestAdapter) injectUsers(users []internal.TestUser) error {
    for _, user := range users {
        // Inject each user using your backend's API
        err := a.backend.CreateUser(internal.UserRequest{
            Username:    user.Username,
            Email:       user.Email,
            DisplayName: user.DisplayName,
            Groups:      user.Groups,
        })
        if err != nil {
            return fmt.Errorf("failed to create user %s: %w", user.Username, err)
        }
    }
    return nil
}
```

#### Flexible Validation
```go
func validateMyBackendResults(t *testing.T, chains []*entity.EntityChain) {
    rule := internal.FlexibleChainValidationRule{
        Description: "MyBackend entity chain validation",
        Expectations: []internal.FlexibleEntityChainExpectation{
            internal.ExpectBasicUserChain("user-token-1"),
            internal.ExpectClientChain("client-token-1"),
        },
        AllowPartialSuccess: false,
        MinSuccessCount:     2,
    }
    
    err := internal.ValidateEntityChainFlexible(chains, rule)
    assert.NoError(t, err)
}
```

### Environment Variables

Configure your tests using environment variables:

- `TEST_POSTGRES_HOST` - PostgreSQL host (default: localhost)  
- `TEST_POSTGRES_PORT` - PostgreSQL port (default: 5432)
- `TEST_KEYCLOAK_URL` - Keycloak URL (default: http://localhost:8080)
- `TEST_CONTAINER_STARTUP_TIMEOUT` - Container startup timeout (default: 2m)
- `TEST_CONTAINER_RUN_TIMEOUT` - Container run timeout (default: 4m)
- `TEST_JWT_VALIDITY` - JWT validity duration (default: 1h)
- `TEST_DATA_VARIATION` - Enable varied test data (default: true)

## Future Enhancements

### Planned Improvements
1. **Container Configuration**: Configurable image versions and timeouts
2. **Caching Layer**: Query result caching for SQL/LDAP backends
3. **Performance Metrics**: OpenTelemetry integration for monitoring
4. **Load Testing**: Benchmark tests for performance validation
5. **Multi-Database**: Support for MySQL and other SQL databases
6. **HA Testing**: High availability and failover testing