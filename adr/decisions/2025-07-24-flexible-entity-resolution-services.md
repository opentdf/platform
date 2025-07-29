---
status: 'proposed'
date: '2025-07-24'
tags:
 - entity-resolution
 - ldap
 - sql
 - identity-provider
 - configuration
driver: 'ryan'
deciders: 'ryan, claude'
consulted: 'platform team'
informed: 'opentdf community'
---
# Strategic Entity Resolution Service Architecture

## Context and Problem Statement

The OpenTDF platform requires a strategic evolution from single-purpose ERS implementations (Keycloak, Claims) to a flexible, configurable architecture that can integrate with any organizational identity and data source. **ERS serves as the critical bridge between external organizational systems and OpenTDF's authorization engine**, transforming diverse data sources into rich claims that drive fine-grained access control decisions.

## Strategic Challenges

1. **Beyond Identity Providers**: Organizations need to integrate authorization context from diverse sources - not just IdPs, but HR systems, databases, analytics platforms, and custom applications
2. **Organizational Context Gap**: Current ERS implementations focus on basic identity resolution but miss the rich organizational context (department, projects, clearance, risk scores) needed for sophisticated authorization policies
3. **Administrative Burden**: Creating custom ERS implementations for each data source is unsustainable and doesn't scale across diverse organizational architectures
4. **Authorization Integration**: ERS outputs must seamlessly integrate with SubjectMappings and JSONPath selectors for policy evaluation
5. **Security and Performance**: Each integration must maintain security best practices while providing performant access to organizational data

## Strategic Vision

**ERS Evolution**: Move from "identity resolution" to "organizational context extraction" - providing a standardized, configurable interface to any system containing user, group, or organizational data needed for authorization decisions.

## Decision Drivers

* **Security**: Read-only access, secure connection defaults, minimal attack surface
* **Authorization Integration**: Rich attribute extraction that feeds directly into SubjectMapping evaluation
* **Flexibility**: Configuration-driven attribute mapping that supports any organizational context needed for policy decisions
* **Maintainability**: Reusable implementations that reduce custom ERS development
* **Performance**: Efficient entity resolution under load with proper attribute caching
* **Compatibility**: Leverage existing ERS protobuf interface and service registration patterns

## Considered Options

* **Option 1**: Continue building one-off ERS implementations per data source
* **Option 2**: Implement standardized, configurable ERS implementations for common organizational data sources
* **Option 3**: Build a generic plugin architecture for arbitrary data sources
* **Option 4**: Create a unified ERS that handles multiple data source types

## Decision Outcome

Chosen option: "**Option 2: Standardized configurable ERS implementations**", because it provides the optimal balance of flexibility, security, and maintainability while addressing the majority of organizational data integration needs.

### Consequences

* 🟩 **Good**, because provides standardized approach to organizational context extraction across diverse data sources
* 🟩 **Good**, because extracted attributes directly integrate with SubjectMappings for fine-grained authorization
* 🟩 **Good**, because covers majority of organizational needs: directory services (LDAP) and database systems (SQL)
* 🟩 **Good**, because single entity type per ERS ensures predictable output schemas and authorization clarity
* 🟩 **Good**, because configuration-driven approach eliminates custom development for most deployment scenarios
* 🟩 **Good**, because maintains existing ERS protobuf interface compatibility
* 🟩 **Good**, because establishes foundation for additional ERS implementations (NoSQL, APIs, etc.)
* 🟨 **Neutral**, because introduces new dependencies and configuration complexity
* 🟥 **Bad**, because requires administrators to understand data source query syntax for advanced configurations

## Validation

Implementation will be validated through:
- Integration tests with real LDAP servers (OpenLDAP, Active Directory) including rich attribute extraction
- SQL database compatibility tests (PostgreSQL, MySQL, SQLite) with complex queries and joins
- End-to-end authorization flow tests: ERS attribute extraction → flattening → SubjectMapping evaluation → access decisions
- Authorization integration validation with common organizational attributes (department, groups, projects)
- Performance benchmarks under load with attribute-heavy entities
- Security audit of connection handling and credential management

## Pros and Cons of the Options

### Option 1: Continue Custom ERS Development

* 🟩 **Good**, because provides maximum customization for specific data sources
* 🟩 **Good**, because follows existing Keycloak ERS patterns
* 🟥 **Bad**, because requires significant development effort for each new data source
* 🟥 **Bad**, because creates maintenance burden with multiple implementations
* 🟥 **Bad**, because doesn't scale across diverse organizational architectures

### Option 2: Standardized Configurable ERS Implementations

* 🟩 **Good**, because provides secure, read-only access to organizational data sources
* 🟩 **Good**, because configuration-driven approach eliminates custom development for most scenarios
* 🟩 **Good**, because LDAP covers enterprise directory services (Active Directory, OpenLDAP)
* 🟩 **Good**, because SQL covers databases, data warehouses, and analytics platforms
* 🟩 **Good**, because leverages existing ERS architecture and protobuf interfaces
* 🟩 **Good**, because supports rich organizational context extraction for fine-grained authorization
* 🟩 **Good**, because single entity type per ERS ensures predictable authorization behavior
* 🟨 **Neutral**, because requires learning data source query syntax for advanced configurations
* 🟥 **Bad**, because may not support highly specialized or proprietary data sources

### Option 3: Generic Plugin Architecture

* 🟩 **Good**, because maximally flexible for future extensibility
* 🟨 **Neutral**, because could theoretically support any data source
* 🟥 **Bad**, because significant architectural complexity and development overhead
* 🟥 **Bad**, because plugin security model introduces additional attack vectors
* 🟥 **Bad**, because doesn't provide immediate value for common organizational needs

### Option 4: Unified Multi-Source ERS

* 🟩 **Good**, because single ERS instance could handle multiple data sources
* 🟨 **Neutral**, because reduces deployment complexity in some scenarios
* 🟥 **Bad**, because creates unpredictable output schemas and authorization complexity
* 🟥 **Bad**, because mixing entity types leads to authorization mismatches
* 🟥 **Bad**, because violates single responsibility principle

## Implementation Details

### LDAP ERS Architecture

**Library**: `go-ldap/ldap/v3` for mature TLS support and connection management

**Configuration Schema**:
```yaml
services:
  entityresolution:
    mode: "ldap"
    connection:
      servers: ["ldaps://primary.ad.corp:636", "ldaps://backup.ad.corp:636"]
      auth_method: "simple"  # simple, anonymous
      bind_dn: "cn=svc-opentdf,ou=service-accounts,dc=corp,dc=com"
      bind_password: "secret"
      tls_verify: true
      timeout: "30s"
    search:
      base_dn: "ou=users,dc=corp,dc=com"  # Single authoritative source
      scope: "subtree"
      # Single search strategy - find users by email
      filter: "(&(objectClass=person)(mail={value}))"
    # Rich organizational attribute extraction and mapping
    attribute_mappings:
      - ldap: "mail"
        attr: "email"
      - ldap: "sAMAccountName"
        attr: "username" 
      - ldap: "displayName"
        attr: "display_name"
      - ldap: "department"
        attr: "department"           # Organizational department
      - ldap: "memberOf"
        attr: "groups"              # Group memberships  
      - ldap: "clearanceLevel"
        attr: "security_clearance"  # Security clearance level
      - ldap: "projectCodes"
        attr: "authorized_projects" # Authorized project codes
      - ldap: "costCenter"
        attr: "cost_center"         # Cost center assignment
```

**Key Features**:
- **Single Entity Focus**: One ERS instance handles one entity type with predictable output schema
- **Rich Organizational Context**: Extract comprehensive LDAP attributes needed for authorization decisions
- **Authorization Integration**: Direct mapping from LDAP attributes to consistent claim names for authorization
- **Simple Configuration**: Single base DN and search filter eliminates ambiguity and authorization mismatches
- **Flexible Deployment**: Multiple ERS instances can handle different entity types (users, service accounts, etc.)
- **Security**: LDAPS by default with TLS verification and multi-server failover

### SQL ERS Architecture

**Configuration Schema**:
```yaml
services:
  entityresolution:
    mode: "sql"
    connection:
      driver: "postgres"  # postgres, mysql, sqlite
      dsn: "postgres://user:pass@host:5432/database?sslmode=require"
      max_open_conns: 10
      max_idle_conns: 5
      conn_max_lifetime: "1h"
    mappings:
      - entity_type: "email_address"
        query: |
          SELECT u.email, u.username, u.department, u.clearance_level, 
                 u.cost_center, array_agg(g.group_name) as groups,
                 array_agg(p.project_code) as project_codes
          FROM users u 
          LEFT JOIN user_groups ug ON u.id = ug.user_id
          LEFT JOIN groups g ON ug.group_id = g.id
          LEFT JOIN user_projects up ON u.id = up.user_id  
          LEFT JOIN projects p ON up.project_id = p.id
          WHERE u.email = $1
          GROUP BY u.id, u.email, u.username, u.department, u.clearance_level, u.cost_center
        result_mapping:
          email: "email"
          username: "username"  
          department: "department"              # → .department selector
          clearance_level: "security_clearance" # → .security_clearance selector
          groups: "groups"                      # → .groups[] selector
          project_codes: "authorized_projects"  # → .authorized_projects[] selector
          cost_center: "billing_code"           # → .billing_code selector
```

**Key Features**:
- **Single Entity Focus**: One ERS instance handles one entity type with consistent query patterns and output schema
- **Rich Data Integration**: Support complex joins across user, group, and project tables for comprehensive organizational context
- **Authorization Integration**: Direct result mapping from SQL columns to claims that feed SubjectMapping JSONPath selectors
- **Simple Configuration**: Single query per ERS eliminates result ambiguity and ensures predictable authorization context
- **Database Flexibility**: Multi-database support (PostgreSQL, MySQL, SQLite) with connection pooling
- **Security**: Parameterized queries prevent SQL injection

### Service Registration Integration

Both implementations integrate with the existing service registration pattern. **Each ERS instance handles a single entity type** for predictable results:

```go
const (
    KeycloakMode = "keycloak"
    ClaimsMode   = "claims"
    LDAPMode     = "ldap"      // New
    SQLMode      = "sql"       // New
)

func RegisterFunc(srp serviceregistry.RegistrationParams) (entityresolutionconnect.EntityResolutionServiceHandler, serviceregistry.HandlerServer) {
    var inputConfig ERSConfig
    if err := mapstructure.Decode(srp.Config, &inputConfig); err != nil {
        panic(err)
    }
    
    switch inputConfig.Mode {
    case LDAPMode:
        return ldap.RegisterLDAPERS(srp.Config, srp.Logger)
    case SQLMode:
        return sql.RegisterSQLERS(srp.Config, srp.Logger)
    case ClaimsMode:
        return claims.RegisterClaimsERS(srp.Config, srp.Logger)
    default:
        return keycloak.RegisterKeycloakERS(srp.Config, srp.Logger)
    }
}
```

### Multi-Instance Deployment Pattern

For handling different entity types, deploy multiple ERS instances:

```yaml
# User ERS - handles human users
services:
  entityresolution_users:
    mode: "ldap"
    search:
      base_dn: "ou=users,dc=corp,dc=com"
      filter: "(&(objectClass=person)(mail={value}))"
    # ... user-specific attribute mappings

# Service Account ERS - handles service principals  
services:
  entityresolution_services:
    mode: "ldap"
    search:
      base_dn: "ou=computers,dc=corp,dc=com"
      filter: "(&(objectClass=computer)(servicePrincipalName=*{value}*))"
    # ... service-specific attribute mappings
```

## More Information

## Authorization Integration Flow

The complete flow from external identity source to access decision:

1. **Entity Lookup**: Client provides entity identifier (`email_address: "alice@corp.com"`)
2. **ERS Resolution**: LDAP/SQL ERS extracts rich organizational attributes
   ```json
   {
     "email": "alice@corp.com",
     "department": "Engineering", 
     "security_clearance": "Secret",
     "groups": ["developers", "team-leads"],
     "authorized_projects": ["proj-alpha", "proj-beta"]
   }
   ```
3. **Attribute Flattening**: Converts to JSONPath selectors
   ```
   .email → "alice@corp.com"
   .department → "Engineering" 
   .security_clearance → "Secret"
   .groups[] → "developers", "team-leads"
   .authorized_projects[] → "proj-alpha", "proj-beta"
   ```
4. **SubjectMapping Evaluation**: Conditions match against flattened attributes
   ```yaml
   conditions:
     - subject_external_selector_value: ".department"
       operator: "IN"
       subject_external_values: ["Engineering", "Research"]
     - subject_external_selector_value: ".security_clearance" 
       operator: "IN"
       subject_external_values: ["Secret", "TopSecret"]
   ```
5. **Access Decision**: Matching conditions grant access to protected attribute values

## Strategic Roadmap

**Phase 1: Foundation ERS Implementations**
1. LDAP ERS implementation for directory services integration
2. SQL ERS implementation for database and analytics platform integration  
3. Enhanced Claims ERS for JWT-based organizational context
4. Single entity type architecture ensuring predictable authorization behavior

**Phase 2: Integration and Optimization**
1. End-to-end authorization flow validation and testing
2. Performance optimization for attribute-heavy organizational queries
3. Configuration templates and documentation for common deployment patterns
4. Multi-instance deployment patterns and best practices

**Phase 3: Advanced Capabilities**
1. Additional ERS implementations based on organizational needs (NoSQL, REST APIs, message queues)
2. Advanced query templating and dynamic configuration capabilities
3. Integration with external configuration management and secrets systems

## Future ERS Expansion

The standardized ERS architecture enables future implementations for additional organizational data sources:

- **NoSQL ERS**: MongoDB, DynamoDB, Elasticsearch for modern data stores
- **API ERS**: REST/GraphQL APIs for SaaS platforms and custom services
- **Message Queue ERS**: Kafka, RabbitMQ for real-time organizational context
- **File-based ERS**: CSV, JSON, YAML for simple configuration-driven scenarios

Each following the same principles:
- Single entity type per ERS instance
- Configuration-driven attribute extraction and mapping
- Consistent attribute output that integrates with SubjectMapping evaluation
- Secure, read-only access patterns

## Performance and Caching Strategy

**ERS implementations should remain simple and stateless** - caching is handled by upstream and downstream systems:

**Upstream Caching** (Recommended):
- **LDAP**: Directory server query result caching, connection pooling
- **SQL**: Database query plan caching, connection pooling, read replicas
- **Load Balancers**: Cache responses at the infrastructure level

**Downstream Caching**:
- **Authorization Service**: Cache flattened entity representations and SubjectMapping evaluation results
- **Platform-level**: Cache authorization decisions at the policy decision point

**Why ERS doesn't cache**:
- Configuration-driven nature makes cache invalidation complex
- Entity data freshness requirements vary by organization
- Simpler to scale and troubleshoot without ERS-level caching
- Upstream systems are better positioned to understand data staleness

This ADR establishes the strategic foundation for a comprehensive, flexible ERS ecosystem that can adapt to any organizational architecture while maintaining security, performance, and operational simplicity.