# Entity Resolution Service Testing Guide

The OpenTDF platform now includes comprehensive testing infrastructure for the Entity Resolution Service (ERS) with support for SQL and LDAP providers.

## Quick Start

### 1. Start ERS Test Services

```bash
# From the repository root
docker-compose --profile ers-test up -d

# Wait for services to start (about 30 seconds)
docker-compose ps | grep ers
```

### 2. Run ERS Integration Tests

```bash
# Run all multi-strategy ERS tests (previously skipped)
go test ./service/entityresolution/integration -run TestMultiStrategy -v

# Run specific provider tests
go test ./service/entityresolution/integration -run TestMultiStrategy_SQLOnly -v
go test ./service/entityresolution/integration -run TestMultiStrategy_LDAPOnly -v
```

### 3. Cleanup

```bash
docker-compose --profile ers-test down -v
```

## What This Enables

**Before**: 5 tests skipped in normal mode due to missing SQL/LDAP services
```bash
go test ./service/entityresolution/integration -v
# Output: 5 tests SKIP (1 LDAP + 4 Keycloak unavailable)
```

**After**: Complete test coverage with ERS test services
```bash
docker-compose --profile ers-test up -d
go test ./service/entityresolution/integration -v
# Output: All tests pass, only Keycloak tests skip (expected)
```

## Available Services

### PostgreSQL Test Database (port 5433)
- **Purpose**: SQL provider testing for multi-strategy ERS
- **Database**: `ers_test` with pre-loaded organizational data
- **Schema**: Users, clients, groups, permissions tables
- **Data**: 8 test users (alice, bob, charlie, etc.) with departmental structure

### OpenLDAP Test Server (port 1389)
- **Purpose**: LDAP provider testing for multi-strategy ERS  
- **Base DN**: `dc=opentdf,dc=test`
- **Structure**: Organizational units for users, clients, groups
- **Data**: Directory entries matching SQL test data for consistency

### LDAP Admin UI (port 6443, optional)
- **Enable**: `docker-compose --profile ers-admin up -d`
- **URL**: https://localhost:6443
- **Purpose**: Browse LDAP directory during development

## Integration with Existing Services

The ERS test services use different ports to avoid conflicts:
- **Main PostgreSQL**: 5432 → **ERS PostgreSQL**: 5433
- **Standard LDAP**: 389 → **ERS LDAP**: 1389
- **Standard LDAPS**: 636 → **ERS LDAPS**: 1636

All services can run simultaneously with the main OpenTDF stack.

## Test Data Consistency

Test data is designed to be consistent across all ERS backends:

```bash
# SQL: Query users table
psql "postgres://ers_test_user:ers_test_pass@localhost:5433/ers_test" -c "SELECT username, email FROM ers_users;"

# LDAP: Search users
ldapsearch -x -H ldap://localhost:1389 -b "ou=users,dc=opentdf,dc=test" "(objectclass=person)" uid mail

# Both return: alice, bob, charlie, diana, eve, grace, henry + service accounts
```

## Development Workflow

1. **Start Services**: `docker-compose --profile ers-test up -d`
2. **Develop**: Make changes to multi-strategy ERS code
3. **Test**: Run integration tests to verify all providers work
4. **Debug**: Use LDAP admin UI or direct database queries
5. **Cleanup**: `docker-compose --profile ers-test down -v`

## Benefits

- ✅ **Complete Test Coverage**: No more skipped SQL/LDAP tests
- ✅ **Consistent Environment**: Reproducible test conditions
- ✅ **Zero External Dependencies**: Self-contained test infrastructure  
- ✅ **Developer Friendly**: Easy to start, inspect, and debug
- ✅ **CI/CD Ready**: Perfect for automated testing pipelines

## CI/CD Integration

```yaml
# GitHub Actions example
- name: Start ERS Test Services
  run: docker-compose --profile ers-test up -d

- name: Wait for Services
  run: sleep 30

- name: Run ERS Integration Tests
  run: go test ./service/entityresolution/integration -v

- name: Cleanup
  run: docker-compose --profile ers-test down -v
```

## Configuration Examples

### Complete OpenTDF Configuration
**File**: `opentdf-ers-test.yaml`
- Full OpenTDF platform configuration with multi-strategy ERS
- Demonstrates SQL + LDAP + JWT providers with multiple strategies
- Ready for production-like testing

### Docker Integration
The multi-strategy ERS integrates seamlessly with the main Docker Compose configuration using profiles, eliminating the need for manual environment variable configuration.

## Configuration Patterns

### SQL Provider Configuration
```yaml
providers:
  sql_postgres:
    type: sql
    connection:
      driver: postgres
      host: localhost
      port: 5433
      database: ers_test
      username: ers_test_user
      password: ers_test_pass
      ssl_mode: disable
```

### LDAP Provider Configuration  
```yaml
providers:
  ldap_directory:
    type: ldap
    connection:
      host: localhost
      port: 1389
      use_tls: false
      bind_dn: "cn=readonly,dc=opentdf,dc=test"
      bind_password: "readonly_password"
```

### Strategy Mapping Examples
```yaml
mapping_strategies:
  - name: sql_user_resolution
    provider: sql_postgres
    entity_type: subject
    conditions:
      jwt_claims:
        - claim: preferred_username
          operator: exists
    query: |
      SELECT username, email, department 
      FROM ers_users 
      WHERE username = $1 AND active = true
```

## Next Steps

With this infrastructure in place, the OpenTDF platform now supports:
- ✅ **Full multi-strategy ERS testing** with SQL and LDAP backends
- ✅ **Comprehensive entity resolution contract testing**
- ✅ **Reliable integration testing** without external service dependencies
- ✅ **Consistent test environments** for development and CI/CD
- ✅ **Production-ready configurations** with real provider examples
- ✅ **Automated testing workflows** with complete Docker integration