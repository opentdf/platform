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

### Multi-Strategy Entity Resolution Service
- **Location**: [`./multi-strategy/`](./multi-strategy/)
- **Backends**: SQL, LDAP, JWT Claims (all in one service)
- **Features**: Dynamic strategy selection, data transformations, cross-backend failover
- **Failure Strategies**: `fail-fast` (default) for strict error handling, `continue` for resilient failover
- **Use Case**: Organizations with heterogeneous identity systems, complex authorization requirements

## Quick Start

### 1. Choose Your Implementation
Select the ERS implementation that matches your identity backend:
- Use **Claims ERS** for JWT-based authentication systems
- Use **Keycloak ERS** for Keycloak identity provider integration
- Use **Multi-Strategy ERS** for LDAP, SQL databases, and multiple backends with intelligent routing

### 2. Configure Your Service
```yaml
services:
  entityresolution:
    mode: claims    # JWT token processing
    # OR
    mode: keycloak  # Keycloak identity provider
    # OR
    mode: multi-strategy  # LDAP, SQL, and JWT Claims with intelligent routing
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

### Data Transformations (Multi-Strategy ERS)
Multi-Strategy ERS supports data transformations to normalize values from different sources:

#### Common Transformations
- **`csv_to_array`**: Converts `"admin,user,finance"` → `["admin", "user", "finance"]`
- **`array`**: Ensures value is returned as an array type
- **`string`**: Converts any value to string representation
- **`lowercase`**: Converts strings to lowercase
- **`uppercase`**: Converts strings to uppercase

#### SQL-Specific Transformations
- **`postgres_array`**: Handles PostgreSQL array format `{item1,item2,item3}`

#### LDAP-Specific Transformations
- **`ldap_dn_to_cn_array`**: Converts DN arrays to CN arrays
- **`ldap_dn_to_cn`**: Extracts CN from single DN
- **`ldap_attribute_values`**: Handles multi-valued LDAP attributes
- **`ad_group_name`**: Extracts group names from AD DNs

#### Claims-Specific Transformations  
- **`jwt_extract_scope`**: Parses OAuth2 space-separated scopes
- **`jwt_normalize_groups`**: Handles various group formats

Example usage:
```yaml
output_mapping:
  - source_column: user_groups
    claim_name: groups
    transformation: csv_to_array  # Converts CSV to array
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

| Feature | Claims ERS | Keycloak ERS | Multi-Strategy ERS |
|---------|------------|--------------|-------------------|
| **External Dependencies** | None | Keycloak server | SQL + LDAP + Claims (configurable) |
| **Connection Management** | Stateless | HTTP client pool | Multiple connection pools |
| **Security** | JWT signature validation | OAuth2/OIDC | All security types (LDAPS/StartTLS/SSL/TLS) |
| **Query Flexibility** | JWT claims extraction | Admin API calls | All query types (LDAP filters + SQL queries + JWT claims) |
| **Group Support** | JWT group claims | Keycloak roles/groups | All group types (LDAP + SQL joins + JWT claims) |
| **Data Transformations** | Basic | None | **Advanced (16 types)** |
| **Failover Support** | None | None | **Cross-backend intelligent failover** |
| **Performance** | Fastest (no I/O) | HTTP API latency | **Intelligent routing (JWT-first → DB → LDAP)** |
| **Backend Support** | JWT only | Keycloak only | **SQL databases + LDAP directories + JWT claims** |
| **Use Case** | Microservices, JWTs | Keycloak deployments | **Any identity system - unified approach** |

> **Note**: For LDAP or SQL backends, use **Multi-Strategy ERS** instead of the deprecated individual implementations.

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
| **Deprecated LDAP mode** | **Multi-Strategy** | Configure LDAP provider with strategies, enable transformations |
| **Deprecated SQL mode** | **Multi-Strategy** | Configure SQL provider with strategies, enable transformations |
| **Any v1** | **Any v2** | Update protocol imports, change `Id` to `EphemeralId` |
| **Multiple backends** | **Claims** | Consolidate to JWT-based authentication for simplified architecture |
| **Multiple backends** | **Multi-Strategy** | **Unified service with intelligent routing and cross-backend failover** |
| **Multiple ERS services** | **Multi-Strategy** | **Single service supporting all backends with strategy-based routing** |

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