# SQL Entity Resolution Service

The SQL Entity Resolution Service provides entity resolution capabilities by querying SQL databases to resolve entities such as users, clients, and other identity information. This service supports both v1 and v2 protocols and works with PostgreSQL, MySQL, and SQLite databases.

## Features

- **Multi-Database Support**: PostgreSQL, MySQL, and SQLite
- **Protocol Flexibility**: Support for both v1 and v2 protocols
- **Connection Pooling**: Configurable connection pool settings for optimal performance
- **Parameterized Queries**: SQL injection protection through parameterized queries
- **Flexible Query Configuration**: Customizable SQL queries for different entity types
- **Column Mapping**: Configurable mapping between SQL columns and entity properties
- **Entity Inference**: Support for inferring entities when not found in the database
- **JWT Token Processing**: Extract entity chains from JWT tokens
- **Comprehensive Testing**: Full test suite with in-memory SQLite for testing
- **Context-Aware**: Proper context handling and timeout support

## Protocol Versions

### v1 Protocol
- Uses `authorization.Entity` types
- Method: `CreateEntityChainFromJwt` (singular)
- Field: `Id` for entity identification
- Import: `github.com/opentdf/platform/protocol/go/entityresolution`

### v2 Protocol  
- Uses `entity.Entity` types
- Method: `CreateEntityChainsFromTokens` (plural)
- Field: `EphemeralId` for entity identification
- Import: `github.com/opentdf/platform/protocol/go/entityresolution/v2`

## Configuration

### Basic Configuration

```yaml
entityresolution:
  sql:
    # Database connection settings
    driver: "pgx"                    # Database driver: pgx, mysql, sqlite3
    host: "localhost"
    port: 5432
    database: "opentdf"
    username: "opentdf_user"
    password: "secure_password"
    ssl_mode: "require"              # PostgreSQL SSL mode
    
    # Alternative: Direct DSN (overrides individual connection settings)
    # dsn: "host=localhost port=5432 user=opentdf_user password=secure_password dbname=opentdf sslmode=require"
    
    # Connection pool settings
    max_open_conns: 25               # Maximum open connections
    max_idle_conns: 5                # Maximum idle connections  
    conn_max_lifetime: "30m"         # Connection maximum lifetime
    
    # Query timeouts
    connect_timeout: "10s"           # Connection establishment timeout
    query_timeout: "30s"             # Individual query timeout
    
    # SQL query configuration
    query_mapping:
      username_query: "SELECT id, username, email, display_name, department FROM users WHERE username = $1"
      email_query: "SELECT id, username, email, display_name, department FROM users WHERE email = $1"
      client_id_query: "SELECT id, client_id, name, description FROM clients WHERE client_id = $1"
      
      # Optional queries for additional data
      groups_query: "SELECT group_name FROM user_groups WHERE username = $1"
      attributes_query: "SELECT attr_name, attr_value FROM user_attributes WHERE username = $1"
    
    # Column mapping configuration
    column_mapping:
      username: "username"
      email: "email"
      display_name: "display_name"
      client_id: "client_id"
      groups: "groups"
      additional: ["department", "name", "description", "role"]
    
    # Entity inference configuration
    inferid:
      from:
        username: true               # Infer username entities when not found
        email: true                  # Infer email entities when not found
        clientid: true               # Infer client ID entities when not found
```

### Database-Specific Configuration

#### PostgreSQL

```yaml
entityresolution:
  sql:
    driver: "pgx"
    host: "localhost"
    port: 5432
    database: "opentdf"
    username: "opentdf_user"
    password: "secure_password"
    ssl_mode: "require"
    query_mapping:
      username_query: "SELECT id, username, email, display_name FROM users WHERE username = $1"
      email_query: "SELECT id, username, email, display_name FROM users WHERE email = $1"
      client_id_query: "SELECT id, client_id, name FROM clients WHERE client_id = $1"
```

#### MySQL

```yaml
entityresolution:
  sql:
    driver: "mysql"
    host: "localhost"
    port: 3306
    database: "opentdf"
    username: "opentdf_user"
    password: "secure_password"
    query_mapping:
      username_query: "SELECT id, username, email, display_name FROM users WHERE username = ?"
      email_query: "SELECT id, username, email, display_name FROM users WHERE email = ?"
      client_id_query: "SELECT id, client_id, name FROM clients WHERE client_id = ?"
```

#### SQLite

```yaml
entityresolution:
  sql:
    driver: "sqlite3"
    database: "/path/to/opentdf.db"
    query_mapping:
      username_query: "SELECT id, username, email, display_name FROM users WHERE username = ?"
      email_query: "SELECT id, username, email, display_name FROM users WHERE email = ?"
      client_id_query: "SELECT id, client_id, name FROM clients WHERE client_id = ?"
```

## Database Schema Requirements

The SQL ERS is flexible and can work with various database schemas. You need to configure appropriate queries that return the data you want to include in entity representations.

### Example Schema

```sql
-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255),
    department VARCHAR(100),
    role VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Clients table
CREATE TABLE clients (
    id SERIAL PRIMARY KEY,
    client_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Optional: User groups table
CREATE TABLE user_groups (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) REFERENCES users(username),
    group_name VARCHAR(255),
    UNIQUE(username, group_name)
);

-- Optional: User attributes table
CREATE TABLE user_attributes (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) REFERENCES users(username),
    attr_name VARCHAR(255),
    attr_value TEXT,
    UNIQUE(username, attr_name)
);
```

## Advanced Query Examples

### Complex JOINs

```sql
-- Query with JOIN to include group information
SELECT 
    u.id, 
    u.username, 
    u.email, 
    u.display_name, 
    u.department,
    STRING_AGG(ug.group_name, ',') as groups
FROM users u
LEFT JOIN user_groups ug ON u.username = ug.username
WHERE u.username = $1
GROUP BY u.id, u.username, u.email, u.display_name, u.department
```

### Attribute Aggregation

```sql
-- Query to include user attributes as JSON
SELECT 
    u.id,
    u.username,
    u.email,
    u.display_name,
    JSON_OBJECT_AGG(ua.attr_name, ua.attr_value) as attributes
FROM users u
LEFT JOIN user_attributes ua ON u.username = ua.username
WHERE u.username = $1
GROUP BY u.id, u.username, u.email, u.display_name
```

## Usage Examples

### Service Registration

#### v1 Protocol
```go
package main

import (
    "github.com/opentdf/platform/service/entityresolution/sql"
    "github.com/opentdf/platform/service/logger"
    "github.com/opentdf/platform/service/pkg/config"
)

func registerSQLERS() {
    config := config.ServiceConfig{
        "driver": "pgx",
        "host": "localhost",
        "port": 5432,
        "database": "opentdf",
        "username": "opentdf_user",
        "password": "secure_password",
        "query_mapping": map[string]string{
            "username_query": "SELECT id, username, email, display_name FROM users WHERE username = $1",
            "email_query": "SELECT id, username, email, display_name FROM users WHERE email = $1",
            "client_id_query": "SELECT id, client_id, name FROM clients WHERE client_id = $1",
        },
    }
    
    logger := logger.CreateLogger()
    service, handler := sql.RegisterSQLERS(config, logger)
}
```

#### v2 Protocol
```go
import sqlERS "github.com/opentdf/platform/service/entityresolution/sql/v2"

// Register the v2 service
service, handler := sqlERS.RegisterSQLERS(config, logger)
```

### Entity Resolution

#### v1 Protocol
```go
// Resolve entities by username
req := &entityresolution.ResolveEntitiesRequest{
    Entities: []*authorization.Entity{
        {
            Id: "user-1",
            EntityType: &authorization.Entity_UserName{
                UserName: "alice",
            },
        },
    },
}

resp, err := service.ResolveEntities(ctx, connect.NewRequest(req))
```

#### v2 Protocol  
```go
// Resolve entities by username
req := &entityresolutionV2.ResolveEntitiesRequest{
    Entities: []*entity.Entity{
        {
            EphemeralId: "user-123", 
            EntityType: &entity.Entity_UserName{UserName: "alice"},
        },
    },
}

resp, err := service.ResolveEntities(ctx, connect.NewRequest(req))
```

### JWT Entity Chain Creation

#### v1 Protocol
```go
// Create entity chains from JWT tokens
req := &entityresolution.CreateEntityChainFromJwtRequest{
    Tokens: []*authorization.Token{
        {
            Id: "token-1",
            Jwt: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
        },
    },
}

resp, err := service.CreateEntityChainFromJwt(ctx, connect.NewRequest(req))
```

#### v2 Protocol
```go
// Create entity chains from JWT tokens  
req := &entityresolutionV2.CreateEntityChainsFromTokensRequest{
    Tokens: []*entity.Token{
        {
            EphemeralId: "token-1",
            Jwt: jwtTokenString,
        },
    },
}

resp, err := service.CreateEntityChainsFromTokens(ctx, connect.NewRequest(req))
```

## Security Considerations

### SQL Injection Prevention

The SQL ERS uses parameterized queries to prevent SQL injection attacks:

```go
// Safe - uses parameterized query
rows, err := db.QueryContext(ctx, "SELECT * FROM users WHERE username = ?", username)

// Unsafe - never do this
query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", username)
```

### Connection Security

- **TLS/SSL**: Configure SSL mode for PostgreSQL connections
- **Credentials**: Store database credentials securely (environment variables, secrets management)
- **Network**: Use firewalls and VPNs to restrict database access
- **Authentication**: Use strong database authentication methods

### Data Privacy

- **Logging**: Sensitive data is redacted in logs
- **Connection Strings**: DSN and passwords are not logged
- **Query Parameters**: Query parameters are marked as "[REDACTED]" in logs

## Performance Tuning

### Connection Pool Settings

```yaml
max_open_conns: 25        # Adjust based on database capacity
max_idle_conns: 5         # Keep some connections warm
conn_max_lifetime: "30m"  # Prevent stale connections
```

### Query Optimization

- **Indexes**: Ensure proper indexes on columns used in WHERE clauses
- **Query Plans**: Analyze query execution plans
- **Result Limits**: Consider adding LIMIT clauses for large result sets

### Monitoring

- Monitor connection pool metrics
- Track query execution times
- Monitor database performance

## Testing

The SQL ERS includes comprehensive tests using in-memory SQLite:

```bash
# Run tests
go test ./service/entityresolution/sql/...

# Run tests with coverage
go test -cover ./service/entityresolution/sql/...

# Run benchmarks
go test -bench=. ./service/entityresolution/sql/...
```

### Integration Testing

Integration tests use the contract testing framework with real databases:

```bash
# Navigate to integration directory
cd service/entityresolution/integration

# Run SQL-specific tests
go test -v -run TestSQLEntityResolutionV2
go test -v -run TestSQLiteEntityResolutionV2
```

## Migration Guide

### From LDAP ERS

The SQL ERS follows similar patterns as the LDAP ERS:

| LDAP ERS | SQL ERS |
|----------|---------|
| `servers` | `host` + `port` |
| `bind_dn` + `bind_password` | `username` + `password` |
| `user_filter` | `username_query` |
| `email_filter` | `email_query` |
| `client_id_filter` | `client_id_query` |
| `attribute_mapping` | `column_mapping` |

### From v1 to v2 Protocol

Key changes when upgrading:
- Update import paths to `/v2`
- Change `Id` to `EphemeralId` in entity definitions
- Update method calls: `CreateEntityChainFromJwt` → `CreateEntityChainsFromTokens`
- Update entity types: `authorization.Entity` → `entity.Entity`

## Troubleshooting

### Common Issues

1. **Connection Failures**
   - Check database connectivity
   - Verify credentials
   - Ensure database is running

2. **Query Errors**
   - Validate SQL syntax
   - Check parameter placeholders (? vs $1)
   - Verify table/column names

3. **Performance Issues**
   - Check connection pool settings
   - Analyze query execution plans
   - Consider adding database indexes

### Debug Logging

Enable debug logging to troubleshoot issues:

```yaml
logger:
  level: debug
```

This will log:
- SQL query execution
- Connection attempts
- Entity resolution results
- Performance metrics

## Best Practices

1. **Use Connection Pooling**: Configure appropriate pool settings
2. **Index Database Columns**: Ensure columns used in WHERE clauses are indexed
3. **Parameterized Queries**: Always use parameterized queries
4. **Error Handling**: Implement proper error handling and logging
5. **Security**: Use TLS/SSL and secure credential storage
6. **Monitoring**: Monitor performance and connection health
7. **Testing**: Test with realistic data volumes
8. **Documentation**: Document your database schema and queries

## Contributing

When contributing to the SQL ERS:

1. Follow the existing code patterns
2. Add comprehensive tests
3. Update documentation
4. Consider security implications
5. Test with multiple database types
6. Follow Go best practices