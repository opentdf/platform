# Entity Resolution Service (ERS)

The Entity Resolution Service is a core component of the OpenTDF platform that resolves entity identities (users, clients, groups) from external identity systems for policy evaluation and access control decisions.

## Overview

ERS enables the OpenTDF platform to:
- **Resolve Entities**: Look up users by username, email, or client ID
- **Create Entity Chains**: Extract entity information from JWT tokens  
- **Support Multiple Backends**: LDAP, SQL databases, and other identity systems
- **Enable Policy Decisions**: Provide entity context for attribute-based access control

## Available Implementations

### Claims Entity Resolution Service
- **Location**: [`./claims/`](./claims/)
- **Backends**: JWT token processing with RSA/ECDSA signing
- **Features**: Token validation, claims extraction, no external dependencies
- **Use Case**: JWT-based authentication systems, microservice architectures

### Keycloak Entity Resolution Service
- **Location**: [`./keycloak/`](./keycloak/)
- **Backends**: Keycloak identity provider with Admin API
- **Features**: Real-time user/client lookup, realm management, OAuth2/OIDC integration
- **Use Case**: Organizations using Keycloak for identity management

### LDAP Entity Resolution Service
- **Location**: [`./ldap/`](./ldap/)
- **Backends**: LDAP, Active Directory
- **Features**: Multi-server failover, secure LDAPS connections, flexible attribute mapping
- **Use Case**: Organizations with existing LDAP/AD infrastructure

### SQL Entity Resolution Service  
- **Location**: [`./sql/`](./sql/)
- **Backends**: PostgreSQL, MySQL, SQLite
- **Features**: Connection pooling, parameterized queries, multiple database support
- **Use Case**: Custom database schemas, high-performance requirements

## Quick Start

### 1. Choose Your Implementation
Select the ERS implementation that matches your identity backend:
- Use **Claims ERS** for JWT-based authentication systems
- Use **Keycloak ERS** for Keycloak identity provider integration
- Use **LDAP ERS** for Active Directory or OpenLDAP
- Use **SQL ERS** for custom database schemas

### 2. Configure Your Service
```yaml
services:
  entityresolution:
    mode: claims    # JWT token processing
    # OR
    mode: keycloak  # Keycloak identity provider
    # OR  
    mode: ldap      # LDAP/Active Directory
    # OR
    mode: sql       # Database backends
    # Implementation-specific configuration
```

### 3. Test Your Setup
```bash
# Run integration tests
cd service/entityresolution/integration
go test -v
```

📖 **For comprehensive testing documentation, see [`./integration/README.md`](./integration/README.md)**

## Common Configuration Patterns

### Entity Inference
When entities are not found in your backend, ERS can optionally infer them:

```yaml
inferid:
  from:
    username: true   # Infer username entities
    email: true      # Infer email entities  
    clientid: false  # Don't infer client entities
```

### Timeout Configuration
```yaml
connect_timeout: "10s"  # Connection establishment
read_timeout: "30s"     # Query execution (LDAP)
query_timeout: "30s"    # Query execution (SQL)
```

### Logging & Security
- Passwords and sensitive connection details are automatically redacted
- Enable debug logging for troubleshooting:
  ```yaml
  logger:
    level: debug
  ```

## Architecture

### Protocol Support
- **v1 Protocol**: Uses `authorization.Entity` and singular method names
- **v2 Protocol**: Uses `entity.Entity` and plural method names (`CreateEntityChainsFromTokens`)

### Integration Testing
ERS uses a **contract testing framework** that ensures all implementations behave consistently:

- **Location**: [`./integration/`](./integration/)
- **Framework**: Testcontainers with real infrastructure (OpenLDAP, PostgreSQL, Keycloak)
- **Coverage**: Username/email/client resolution, entity inference, error handling, JWT processing
- **Backends**: Claims, SQLite, PostgreSQL, LDAP, Keycloak

📋 **Complete testing guide**: [`./integration/README.md`](./integration/README.md)  
🔧 **Implementation patterns**: [`./integration/README_ADAPTER_PATTERN.md`](./integration/README_ADAPTER_PATTERN.md)

## Testing

ERS includes comprehensive integration testing with a contract testing framework ensuring consistent behavior across all implementations.

### Quick Start Testing
```bash
cd service/entityresolution/integration

# Fast tests (no Docker)
go test -v -short

# Full test suite (Docker required)  
go test -v
```

### Test Backends
- **Claims**: JWT token processing with RSA signing
- **SQLite**: In-memory database testing
- **PostgreSQL**: Real database with containers
- **LDAP**: OpenLDAP container with TLS
- **Keycloak**: Full Keycloak integration with Admin API

📋 **Complete testing guide**: [`./integration/README.md`](./integration/README.md)

## Implementation Details

| Feature | Claims ERS | Keycloak ERS | LDAP ERS | SQL ERS |
|---------|------------|--------------|----------|---------|
| **External Dependencies** | None | Keycloak server | LDAP server | Database |
| **Connection Management** | Stateless | HTTP client pool | Connection pooling | Connection pooling |
| **Security** | JWT signature validation | OAuth2/OIDC | LDAPS/StartTLS | SSL/TLS support |
| **Query Flexibility** | JWT claims extraction | Admin API calls | LDAP filters | Custom SQL queries |
| **Group Support** | JWT group claims | Keycloak roles/groups | LDAP groups | SQL joins |
| **Performance** | Fastest (no I/O) | HTTP API latency | LDAP-optimized | SQL-optimized |
| **Use Case** | Microservices, JWTs | Keycloak deployments | Enterprise directories | Custom schemas |

## Development

### Adding New ERS Implementations
The contract testing framework makes it easy to add new backends:

1. **Implement ERSTestAdapter interface** (4 methods)
2. **Add your test file** with contract suite integration
3. **All existing tests run automatically** against your implementation

See [`./integration/README_ADAPTER_PATTERN.md`](./integration/README_ADAPTER_PATTERN.md) for detailed guidance.

### Running Tests

**Quick tests** (no Docker required):
```bash
cd service/entityresolution/integration
go test -v -short  # Claims and SQLite only
```

**Full test suite** (requires Docker):
```bash
go test -v  # All backends including containers
```

**Backend-specific tests**:
```bash
go test -v -run TestClaims          # JWT processing (fast)
go test -v -run TestSQLite          # In-memory database (fast)  
go test -v -run TestPostgreSQL      # Docker PostgreSQL
go test -v -run TestLDAP            # Docker OpenLDAP
go test -v -run TestKeycloak        # Docker Keycloak (slowest)
```

📖 **Full testing documentation**: [`./integration/README.md`](./integration/README.md)

## Migration Between Implementations

| Moving From | To | Key Changes |
|-------------|----|-----------| 
| **External system** | **Claims** | Implement JWT token validation, configure signing keys |
| **External system** | **Keycloak** | Set up Keycloak server, configure Admin API access |
| **LDAP** | **SQL** | Replace LDAP filters with SQL queries, update attribute mapping |
| **SQL** | **LDAP** | Replace SQL queries with LDAP filters, configure directory access |
| **Any v1** | **Any v2** | Update protocol imports, change `Id` to `EphemeralId` |
| **Multiple backends** | **Claims** | Consolidate to JWT-based authentication for simplified architecture |

## Troubleshooting

### Common Issues
1. **Connection failures**: Verify backend connectivity and credentials
2. **Entity not found**: Check query/filter syntax and data existence  
3. **Permission errors**: Ensure service account has appropriate access
4. **Performance issues**: Review connection pool settings and query optimization

### Debug Mode
```bash
# Enable detailed logging
TESTCONTAINERS_DEBUG=true go test -v

# Service debug logging
logger:
  level: debug
```

## Security Best Practices

- **Use TLS/SSL** for all database and LDAP connections
- **Store credentials securely** using environment variables or secret management
- **Implement network security** with firewalls and VPNs
- **Monitor access logs** for suspicious activity
- **Regular security updates** for dependencies and infrastructure

## Performance Optimization

### Connection Tuning
```yaml
# LDAP
connect_timeout: "10s"
read_timeout: "30s"

# SQL  
max_open_conns: 25
max_idle_conns: 5
conn_max_lifetime: "30m"
```

### Query Optimization
- **Index database columns** used in WHERE clauses (username, email, client_id)
- **Use efficient LDAP filters** with proper attribute indexing
- **Monitor query execution time** and optimize slow queries
- **Consider result caching** for frequently accessed entities

## Contributing

When contributing to ERS:
1. **Follow existing patterns** in your chosen implementation
2. **Add comprehensive tests** using the contract testing framework
3. **Update documentation** for any new configuration options
4. **Consider security implications** of changes
5. **Test with realistic data** volumes and network conditions