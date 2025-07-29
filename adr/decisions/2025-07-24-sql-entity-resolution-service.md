---
status: 'proposed'
date: '2025-07-24'
tags:
 - entity-resolution
 - sql
 - database
 - data-warehouse
 - configuration
driver: '@jrschumacher'
consulted:
  - '@elizabethhealy'
  - '@damorris25'
  - '@biscoe916'
---
# SQL Entity Resolution Service Implementation

## Context and Problem Statement

Organizations need to integrate OpenTDF with SQL-based identity and user data systems including custom databases, data warehouses, analytics platforms, and legacy user stores to extract rich organizational context for authorization decisions. **SQL ERS serves as the critical bridge between database systems and OpenTDF's authorization system**, transforming database records into claims that drive SubjectMapping evaluation and fine-grained access control.

Current ERS implementations require either:

1. **Keycloak Integration**: Additional infrastructure and potential security concerns with admin APIs, often missing rich organizational context stored in separate systems
2. **Custom ERS Development**: Significant development effort for each database schema or data platform

**The Key Insight**: Organizations often store authoritative user context (department, clearance level, project assignments, cost centers, analytics data) in SQL databases, data warehouses, or custom applications that IdPs don't integrate with. SQL ERS extracts this rich context directly from these authoritative data sources, enabling fine-grained authorization policies based on any organizational data.

## Decision Drivers

* **Authorization Integration**: Rich organizational data extraction that feeds directly into SubjectMapping evaluation via JSONPath selectors
* **Data Source Flexibility**: Support for diverse SQL databases, data warehouses, and analytics platforms
* **Organizational Context**: Access to authoritative user data often stored separately from identity providers
* **Query Flexibility**: Configuration-driven SQL queries that support any organizational schema needed for policy decisions
* **Performance**: Efficient queries with proper connection pooling and database optimization
* **Security**: Parameterized queries and secure connection handling to prevent SQL injection

## Considered Options

* **Option 1**: Basic SQL ERS with fixed table schema assumptions
* **Option 2**: Flexible SQL ERS with configurable queries and result mapping
* **Option 3**: Database-specific ERS implementations (PostgreSQL, MySQL, etc.)

## Decision Outcome

Chosen option: "**Option 2: Flexible SQL ERS with configurable queries**", because it provides maximum deployment flexibility while maintaining simplicity and security.

### Consequences

* 🟩 **Good**, because extracts rich organizational context from any SQL-accessible data source that directly feeds SubjectMapping evaluation
* 🟩 **Good**, because supports complex queries across multiple tables for comprehensive organizational data (users, groups, projects, analytics)
* 🟩 **Good**, because enables integration with data warehouses, analytics platforms, and custom business applications
* 🟩 **Good**, because provides secure, read-only access to authoritative organizational data sources
* 🟩 **Good**, because enables fine-grained authorization policies based on business data and analytics
* 🟨 **Neutral**, because requires SQL knowledge and understanding of JSONPath selectors for advanced configurations
* 🟥 **Bad**, because performance depends on proper database indexing and query optimization

## Implementation Specification

### Core Architecture

**Directory Structure**:
```
service/entityresolution/sql/
├── sql_entity_resolution.go   # Main ERS implementation
├── config.go                 # Configuration structures
├── connection.go             # Database connection management
├── mapper.go                 # Result mapping logic
├── query.go                  # SQL query execution
└── v2/sql_entity_resolution.go   # V2 API implementation
```

**Dependencies**:
- Database drivers: `lib/pq` (PostgreSQL), `go-sql-driver/mysql` (MySQL), `modernc.org/sqlite` (SQLite)
- Standard OpenTDF ERS interfaces and service registration

### Configuration Schema

```yaml
services:
  entityresolution:
    mode: "sql"
    connection:
      # Database connection
      driver: "postgres"  # postgres, mysql, sqlite
      dsn: "postgres://user:pass@host:5432/database?sslmode=require"
      
      # Connection pool management
      max_open_conns: 25
      max_idle_conns: 10
      conn_max_lifetime: "1h"
      conn_max_idle_time: "15m"
      
      # Query timeouts
      query_timeout: "30s"
      
    # Single search strategy - simple and predictable
    search:
      # SQL query to find and enrich user data
      query: |
        SELECT 
          u.email,
          u.username,
          u.department,
          u.clearance_level,
          u.cost_center,
          u.manager_email,
          u.employee_type,
          array_agg(DISTINCT g.group_name) as groups,
          array_agg(DISTINCT p.project_code) as authorized_projects,
          json_build_object(
            'last_login', u.last_login_at,
            'account_status', u.account_status,
            'hire_date', u.hire_date
          ) as metadata
        FROM users u
        LEFT JOIN user_groups ug ON u.id = ug.user_id
        LEFT JOIN groups g ON ug.group_id = g.id
        LEFT JOIN user_projects up ON u.id = up.user_id
        LEFT JOIN projects p ON up.project_id = p.id
        WHERE u.email = $1 AND u.active = true
        GROUP BY u.id, u.email, u.username, u.department, u.clearance_level, 
                 u.cost_center, u.manager_email, u.employee_type, u.last_login_at,
                 u.account_status, u.hire_date
      
    # Rich organizational data mapping for authorization
    attribute_mappings:
      - sql: "email"
        attr: "email"
      - sql: "username"
        attr: "username"
      - sql: "department"
        attr: "department"              # → .department selector in SubjectMappings
      - sql: "clearance_level"
        attr: "security_clearance"     # → .security_clearance selector
      - sql: "cost_center"
        attr: "cost_center"            # → .cost_center selector
      - sql: "manager_email"
        attr: "manager"                # → .manager selector
      - sql: "employee_type"
        attr: "employee_type"          # → .employee_type selector
      - sql: "groups"
        attr: "groups"                 # → .groups[] selector
      - sql: "authorized_projects"
        attr: "authorized_projects"    # → .authorized_projects[] selector
      - sql: "metadata"
        attr: "user_metadata"          # → .user_metadata.* selectors

    # Health check configuration
    health_check:
      enabled: true
      interval: "60s"
      query: "SELECT 1"  # Simple connectivity test
```

### Core Implementation

**Service Interface Implementation**:
```go
type SQLEntityResolutionService struct {
    entityresolution.UnimplementedEntityResolutionServiceServer
    config SQLConfig
    db     *sql.DB
    logger *logger.Logger
    trace.Tracer
}

func (s *SQLEntityResolutionService) ResolveEntities(
    ctx context.Context, 
    req *connect.Request[entityresolution.ResolveEntitiesRequest],
) (*connect.Response[entityresolution.ResolveEntitiesResponse], error) {
    // Implementation details below
}
```

**Simplified Entity Resolution Flow**:
1. **Entity Value Extraction**: Extract entity identifier value from request
2. **Database Connection**: Get connection from pool with timeout handling
3. **Query Execution**: Execute configured SQL query with parameterized value
4. **Result Processing**: Process SQL result set and handle NULL values
5. **Attribute Mapping**: Map SQL columns to consistent claim names for authorization
6. **Response Construction**: Build EntityRepresentation with mapped attributes

**Query Implementation**:
```go
type SQLConfig struct {
    Connection struct {
        Driver             string        `mapstructure:"driver"`
        DSN                string        `mapstructure:"dsn"`
        MaxOpenConns       int           `mapstructure:"max_open_conns"`
        MaxIdleConns       int           `mapstructure:"max_idle_conns"`
        ConnMaxLifetime    time.Duration `mapstructure:"conn_max_lifetime"`
        QueryTimeout       time.Duration `mapstructure:"query_timeout"`
    } `mapstructure:"connection"`
    
    Search struct {
        Query string `mapstructure:"query"`  // Single SQL query
    } `mapstructure:"search"`
    
    AttributeMappings []AttributeMapping `mapstructure:"attribute_mappings"`
}

type AttributeMapping struct {
    SQL  string `mapstructure:"sql"`   // SQL column name
    Attr string `mapstructure:"attr"`  // Claim name for authorization
}

func (s *SQLEntityResolutionService) executeQuery(
    ctx context.Context,
    entityValue string,
) (map[string]interface{}, error) {
    ctx, cancel := context.WithTimeout(ctx, s.config.Connection.QueryTimeout)
    defer cancel()
    
    row := s.db.QueryRowContext(ctx, s.config.Search.Query, entityValue)
    
    // Dynamic column scanning based on query result
    columns, err := row.Columns()
    if err != nil {
        return nil, err
    }
    
    values := make([]interface{}, len(columns))
    valuePtrs := make([]interface{}, len(columns))
    
    for i := range values {
        valuePtrs[i] = &values[i]
    }
    
    if err := row.Scan(valuePtrs...); err != nil {
        return nil, err
    }
    
    result := make(map[string]interface{})
    for i, col := range columns {
        result[col] = values[i]
    }
    
    return result, nil
}
```

### Security Features

**Query Security**:
- Parameterized queries prevent SQL injection attacks
- Read-only database user recommendations
- Connection string security (password management, SSL requirements)
- Query timeout enforcement to prevent resource exhaustion

**Connection Security**:
- TLS/SSL connections enforced through DSN configuration
- Connection pooling limits to prevent resource exhaustion
- Proper credential management and rotation support

**Input Validation**:
- Entity value sanitization before query execution
- Result set validation and type checking
- Configuration validation on startup

### Error Handling and Resilience

**Database Connection Management**:
- Connection pool health monitoring
- Automatic connection retry with exponential backoff
- Graceful degradation on database unavailability
- Detailed error logging for troubleshooting

**Query Error Handling**:
- Handle various SQL errors (timeouts, constraint violations, etc.)
- Proper NULL value handling in result sets
- Entity not found vs. database error differentiation
- Structured error responses for different failure scenarios

### Performance Considerations

**Query Optimization**:
- Index recommendations for common query patterns
- Connection pooling for high-throughput scenarios
- Query result caching at application level (future enhancement)
- Prepared statement usage for repeated queries

**Result Processing**:
- Efficient JSON handling for complex data types
- Array aggregation for group/project memberships
- Minimal memory allocation during result processing

### Testing Strategy

**Unit Tests**:
- Configuration parsing and validation
- SQL query parameterization and execution
- Result mapping logic and NULL handling
- Error handling scenarios

**Integration Tests**:
- Test with PostgreSQL, MySQL, and SQLite databases
- Complex query validation with JOINs and aggregations
- Connection pool behavior under load
- Database failover scenarios

**Performance Tests**:
- Load testing with concurrent queries
- Large result set processing benchmarks
- Connection pool scaling validation
- Memory usage analysis

## Validation

Implementation success will be measured by:
- Successfully resolving entities from PostgreSQL, MySQL, and SQLite with rich organizational data
- Single entity type per ERS providing predictable, consistent output schemas
- End-to-end authorization flow validation: SQL data → flattening → SubjectMapping evaluation → access decisions
- Security audit confirming secure connection handling and parameterized query execution
- Performance benchmarks meeting production requirements with complex queries and JOINs
- Integration test coverage > 80%

## Multi-Instance Deployment Pattern

**Single Entity Type Per ERS**: Each SQL ERS instance handles one entity type for predictable results and clear authorization context.

### User ERS Configuration
```yaml
# Primary user ERS - handles human users with rich organizational data
services:
  entityresolution_users:
    mode: "sql"
    connection:
      driver: "postgres"
      dsn: "postgres://readonly_user:pass@userdb.corp.com:5432/hr_system?sslmode=require"
      max_open_conns: 20
      max_idle_conns: 5
    search:
      query: |
        SELECT u.email, u.department, u.clearance_level, u.cost_center,
               array_agg(g.group_name) as groups,
               array_agg(p.project_code) as authorized_projects
        FROM users u
        LEFT JOIN user_groups ug ON u.id = ug.user_id
        LEFT JOIN groups g ON ug.group_id = g.id  
        LEFT JOIN user_projects up ON u.id = up.user_id
        LEFT JOIN projects p ON up.project_id = p.id
        WHERE u.email = $1 AND u.active = true
        GROUP BY u.id, u.email, u.department, u.clearance_level, u.cost_center
    attribute_mappings:
      - sql: "department"
        attr: "department"
      - sql: "clearance_level"
        attr: "security_clearance"
      - sql: "groups"
        attr: "groups"
```

### Analytics ERS Configuration
```yaml
# Analytics ERS - handles user behavior and risk data
services:
  entityresolution_analytics:
    mode: "sql"
    connection:
      driver: "postgres"
      dsn: "postgres://analytics_user:pass@analytics.corp.com:5432/user_analytics?sslmode=require"
    search:
      query: |
        SELECT u.email, u.risk_score, u.last_login_location, u.device_trust_level,
               json_build_object(
                 'avg_session_duration', ua.avg_session_duration,
                 'failed_login_attempts', ua.failed_login_attempts,
                 'data_access_pattern', ua.access_pattern_category
               ) as behavioral_data
        FROM user_profiles u
        JOIN user_analytics ua ON u.user_id = ua.user_id
        WHERE u.email = $1 AND u.active = true
    attribute_mappings:
      - sql: "risk_score"
        attr: "risk_score"              # → .risk_score selector
      - sql: "last_login_location"
        attr: "last_location"           # → .last_location selector
      - sql: "device_trust_level"
        attr: "device_trust"            # → .device_trust selector
      - sql: "behavioral_data"
        attr: "behavior_analytics"      # → .behavior_analytics.* selectors
```

**Benefits**:
- ✅ **Predictable Output**: Each ERS has consistent, known data schema
- ✅ **Authorization Clarity**: SubjectMappings know exactly what selectors are available
- ✅ **Simple Configuration**: No complex routing or entity type detection within ERS
- ✅ **Data Source Flexibility**: Different entity types can use different databases, schemas, or data sources

## Authorization Integration Flow

The complete flow demonstrating how SQL data becomes authorization decisions:

### Example Scenario
**User**: `alice@corp.com` requests access to a financial report  
**Database Records**:
```sql
-- User table
email: alice@corp.com, department: Finance, clearance_level: Confidential, cost_center: FC-1001

-- Group memberships  
groups: [finance-analysts, report-viewers, regional-managers]

-- Project assignments
authorized_projects: [budget-2025, quarterly-forecasts, audit-prep]

-- Analytics data
risk_score: 85, last_location: New York Office, device_trust: high
```

### Integration Steps

1. **ERS Resolution**: SQL ERS executes query and maps results
   ```json
   {
     "email": "alice@corp.com",
     "department": "Finance",
     "security_clearance": "Confidential",
     "cost_center": "FC-1001", 
     "groups": ["finance-analysts", "report-viewers", "regional-managers"],
     "authorized_projects": ["budget-2025", "quarterly-forecasts", "audit-prep"],
     "risk_score": 85,
     "device_trust": "high"
   }
   ```

2. **Attribute Flattening**: Converts to JSONPath selectors for SubjectMapping evaluation
   ```
   .email → "alice@corp.com"
   .department → "Finance"
   .security_clearance → "Confidential"
   .groups[] → "finance-analysts", "report-viewers", "regional-managers"
   .authorized_projects[] → "budget-2025", "quarterly-forecasts", "audit-prep"
   .risk_score → 85
   .device_trust → "high"
   ```

3. **SubjectMapping Evaluation**: Policy conditions match against flattened attributes
   ```yaml
   # Financial report access policy
   conditions:
     - subject_external_selector_value: ".department"
       operator: "IN"
       subject_external_values: ["Finance", "Accounting"]
     - subject_external_selector_value: ".security_clearance"
       operator: "IN" 
       subject_external_values: ["Confidential", "Secret"]
     - subject_external_selector_value: ".authorized_projects[]"
       operator: "IN"
       subject_external_values: ["budget-2025"]
     - subject_external_selector_value: ".risk_score"
       operator: "GREATER_THAN"
       subject_external_values: ["75"]
   ```

4. **Access Decision**: All conditions match → **PERMIT** access to financial report

This demonstrates how SQL organizational data directly drives fine-grained authorization decisions through the OpenTDF policy system.

## More Information

**Database-Specific Considerations**:
- **PostgreSQL**: Full JSON support, array aggregations, advanced indexing (GIN, GiST)
- **MySQL**: JSON functions, GROUP_CONCAT for arrays, InnoDB optimizations
- **SQLite**: Embedded scenarios, JSON1 extension, simpler deployment models
- **Data Warehouses**: BigQuery, Snowflake, Redshift compatibility for analytics use cases

**Authorization Policy Examples**:
```yaml
# Department and clearance-based access
conditions:
  - subject_external_selector_value: ".department"
    operator: "IN"
    subject_external_values: ["Finance", "Accounting", "Executive"]
  - subject_external_selector_value: ".security_clearance"
    operator: "IN"
    subject_external_values: ["Confidential", "Secret"]

# Risk-based access control
conditions:
  - subject_external_selector_value: ".risk_score"
    operator: "GREATER_THAN"
    subject_external_values: ["80"]
  - subject_external_selector_value: ".device_trust"
    operator: "IN"
    subject_external_values: ["high", "verified"]

# Project and group-based access
conditions:
  - subject_external_selector_value: ".authorized_projects[]"
    operator: "IN"
    subject_external_values: ["classified-project-alpha"]
  - subject_external_selector_value: ".groups[]"
    operator: "IN"
    subject_external_values: ["project-leads", "senior-analysts"]
```

**Future Enhancements**:
- Query result caching with configurable TTL for frequently accessed entities
- Prepared statement optimization for repeated query patterns
- Metrics and monitoring integration for SQL ERS performance and query latency
- Support for additional database drivers (Oracle, SQL Server, etc.)
- Advanced query templating for dynamic WHERE clauses and JOINs
- Integration with database connection pooling solutions (PgBouncer, etc.)

This implementation provides a robust, secure, and flexible foundation for extracting rich organizational context from SQL databases and seamlessly integrating it with OpenTDF's fine-grained authorization system.