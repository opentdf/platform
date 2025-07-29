# Entity Resolution Service Integration Tests

Integration tests for OpenTDF Entity Resolution Service (ERS) implementations using a unified contract testing framework.

## Overview

The **Contract Testing Framework** ensures all ERS implementations (LDAP, SQL, Keycloak, Claims) behave consistently by running identical test suites against each backend through a standardized adapter interface.

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                Contract Test Suite                      │
│  • Username/Email/Client ID resolution                 │
│  • Mixed entity types • Entity inference               │
│  • Error handling • JWT token chains                   │
└─────────────────────┬───────────────────────────────────┘
              ┌───────┼───────┐
        ┌─────▼──┐ ┌──▼───┐ ┌▼──────┐
        │  LDAP  │ │ SQL  │ │Future │
        │Adapter │ │Adapter│ │Adapters│
        └────────┘ └──────┘ └───────┘
```

## Quick Start

```bash
# Prerequisites: Docker/Podman running
cd service/entityresolution/integration

# Run all tests
go test -v

# Run specific implementation
go test -v -run TestLDAPEntityResolutionV2
go test -v -run TestSQLEntityResolutionV2
```

### Docker Environment Setup
```bash
# For Podman users
export TESTCONTAINERS_PODMAN=true
export TESTCONTAINERS_RYUK_CONTAINER_PRIVILEGED=true

# For Colima users  
export DOCKER_HOST="unix://${HOME}/.colima/default/docker.sock"
export TESTCONTAINERS_RYUK_DISABLED=true
```

## Test Infrastructure

| Implementation | Container | Port | Status |
|---------------|-----------|------|--------|
| **LDAP** | `osixia/openldap:1.5.0` | 38900, 63600 | ✅ Complete |
| **SQL** | `postgres:15-alpine` + SQLite | 54323 | ✅ Complete |
| **Keycloak** | TBD | TBD | ⚠️ Framework ready |
| **Claims** | None (JWT-based) | - | ❌ Missing |

### Standard Test Data
- **Users**: alice, bob, charlie (with groups: users, admins, managers)
- **Clients**: test-client-1, test-client-2, opentdf-sdk
- **Scenarios**: Valid lookups, inference, mixed types, error cases

## Adding New Implementations

Create `<name>_test.go` implementing the adapter interface:

```go
type ERSTestAdapter interface {
    GetScopeName() string
    SetupTestData(ctx context.Context, testDataSet *ContractTestDataSet) error
    CreateERSService(ctx context.Context) (ERSImplementation, error)
    TeardownTestData(ctx context.Context) error
}

// Usage
func TestNewEntityResolutionV2(t *testing.T) {
    contractSuite := internal.NewContractTestSuite()
    adapter := NewTestAdapter()
    contractSuite.RunContractTestsWithAdapter(t, adapter)
}
```

All contract tests automatically run against your new adapter!

## Troubleshooting

**Port conflicts**: Ensure ports 38900, 63600, 54323 are available  
**Container issues**: `docker ps -a` and `docker logs <container>`  
**Debug mode**: `TESTCONTAINERS_DEBUG=true go test -v`  
**Cleanup**: `docker container prune -f`

## Current Implementation Status

- ✅ **LDAP**: Full container integration with OpenLDAP, TLS support
- ✅ **SQL**: SQLite (in-memory) + PostgreSQL container support  
- ⚠️ **Keycloak**: Adapter exists but needs Admin API integration
- ❌ **Claims**: Missing adapter implementation entirely