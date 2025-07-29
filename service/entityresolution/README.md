# Entity Resolution Service (ERS)

The Entity Resolution Service is a core component of the OpenTDF platform that resolves entity identities (users, clients, groups) from external identity systems for policy evaluation and access control decisions.

## Overview

ERS enables the OpenTDF platform to:
- **Resolve Entities**: Look up users by username, email, or client ID
- **Create Entity Chains**: Extract entity information from JWT tokens  
- **Support Multiple Backends**: LDAP, SQL databases, and other identity systems
- **Enable Policy Decisions**: Provide entity context for attribute-based access control

## Available Implementations

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
- Use **LDAP ERS** for Active Directory or OpenLDAP
- Use **SQL ERS** for custom database schemas

### 2. Configure Your Service
```yaml
services:
  entityresolution:
    mode: ldap  # or 'sql'
    # Implementation-specific configuration
```

### 3. Test Your Setup
```bash
# Run integration tests
cd service/entityresolution/integration
go test -v
```

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
- **Framework**: Testcontainers with real infrastructure (OpenLDAP, PostgreSQL)
- **Coverage**: Username/email/client resolution, entity inference, error handling

See [`./integration/README.md`](./integration/README.md) for complete testing documentation.

## Implementation Details

| Feature | LDAP ERS | SQL ERS |
|---------|----------|---------|
| **Multi-backend** | Multiple LDAP servers | Multiple DB types |
| **Connection Management** | Connection pooling | Connection pooling |
| **Security** | LDAPS/StartTLS | SSL/TLS support |
| **Query Flexibility** | LDAP filters | Custom SQL queries |
| **Group Support** | LDAP groups | SQL joins |
| **Performance** | LDAP-optimized | SQL-optimized |

## Development

### Adding New ERS Implementations
The contract testing framework makes it easy to add new backends:

1. **Implement ERSTestAdapter interface** (4 methods)
2. **Add your test file** with contract suite integration
3. **All existing tests run automatically** against your implementation

See [`./integration/README_ADAPTER_PATTERN.md`](./integration/README_ADAPTER_PATTERN.md) for detailed guidance.

### Running Tests
```bash
# All implementations
cd service/entityresolution/integration
go test -v

# Specific implementation  
go test -v -run TestLDAPEntityResolutionV2
go test -v -run TestSQLEntityResolutionV2
```

## Migration Between Implementations

| Moving From | To | Key Changes |
|-------------|----|-----------| 
| LDAP | SQL | Replace LDAP filters with SQL queries, update attribute mapping |
| SQL v1 | SQL v2 | Update protocol imports, change `Id` to `EphemeralId` |

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