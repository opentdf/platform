---
status: 'proposed'
date: '2025-07-31'
tags:
 - entity-resolution
 - sql
 - ldap
 - multi-strategy
 - configuration
 - jwt-mapping
driver: '@jrschumacher'
consulted:
  - '@elizabethhealy'
  - '@damorris25'
  - '@biscoe916'
---
# Multi-Strategy Entity Resolution Service Implementation

## Context and Problem Statement

Organizations need to integrate OpenTDF with diverse identity and data systems including SQL databases, LDAP directories, data warehouses, analytics platforms, and legacy systems to extract rich organizational context for authorization decisions. **Multi-Strategy ERS serves as the unified bridge between any data source and OpenTDF's authorization system**, transforming data from multiple backends into claims that drive SubjectMapping evaluation and fine-grained access control.

Current ERS implementations have significant limitations:

1. **Single Backend Limitation**: Each ERS instance supports only one backend type (SQL or LDAP)
2. **Hardcoded JWT Assumptions**: Fixed assumptions about JWT structure and claim mapping
3. **Operational Complexity**: Multiple ERS instances require separate deployment, monitoring, and configuration
4. **Limited Failover**: No cross-backend failover or caching strategies

**The Key Insight**: Modern identity systems are heterogeneous. A single user might exist in corporate LDAP, have analytics data in PostgreSQL, and contractor information in external databases. Multi-Strategy ERS provides unified access to all these data sources through intelligent strategy selection based on JWT context.

## Decision Drivers

* **Unified Access**: Single ERS instance can access multiple backend types (SQL, LDAP, JWT claims)
* **JWT Context Awareness**: Dynamic strategy selection based on JWT claims, audience, issuer, and token type
* **Operational Efficiency**: Reduce deployment complexity from multiple ERS instances to single service
* **Flexible Mapping**: Support different input/output mappings per strategy for heterogeneous data sources
* **High Availability**: Cross-backend failover and caching strategies
* **Security**: Parameterized queries and proper escaping across all backend types
* **Performance**: Connection pooling, caching, and optimized query execution

## Considered Options

* **Option 1**: Continue with separate ERS implementations per backend type
* **Option 2**: Multi-Strategy ERS with provider-based architecture and flexible JWT mapping
* **Option 3**: Plugin-based ERS with dynamic backend loading

## Decision Outcome

Chosen option: "**Option 2: Multi-Strategy ERS with provider-based architecture**", because it provides unified access to heterogeneous data sources while maintaining clear separation of concerns and operational simplicity.

### Consequences

* 🟩 **Good**, because enables unified access to any organizational data source that directly feeds SubjectMapping evaluation
* 🟩 **Good**, because reduces operational complexity from multiple ERS instances to single service
* 🟩 **Good**, because supports intelligent failover, caching, and A/B testing strategies
* 🟩 **Good**, because provides flexible JWT claim mapping without hardcoded assumptions
* 🟩 **Good**, because enables fine-grained authorization policies based on data from any source
* 🟨 **Neutral**, because requires more complex configuration compared to single-backend approach
* 🟥 **Bad**, because single service has larger blast radius if misconfigured

## Implementation Specification

### Core Architecture

**Directory Structure**:
```
service/entityresolution/
├── multi-strategy/                        # New multi-strategy implementation
│   ├── README.md                         # Multi-strategy ERS documentation
│   ├── multi_strategy_entity_resolution.go        # Main service implementation
│   ├── multi_strategy_entity_resolution_test.go
│   ├── config.go                         # Core configuration structures
│   ├── config_test.go
│   ├── strategy_matcher.go               # JWT condition matching logic
│   ├── strategy_matcher_test.go
│   ├── provider_manager.go               # Provider registration and lifecycle
│   ├── provider_manager_test.go
│   ├── providers/                        # Provider implementations (co-located)
│   │   ├── sql/
│   │   │   ├── sql_provider.go          # SQL provider implementation
│   │   │   ├── sql_provider_test.go
│   │   │   └── config.go               # SQL-specific configuration
│   │   ├── ldap/
│   │   │   ├── ldap_provider.go        # LDAP provider implementation
│   │   │   ├── ldap_provider_test.go
│   │   │   └── config.go              # LDAP-specific configuration
│   │   └── claims/
│   │       ├── claims_provider.go      # JWT claims provider
│   │       ├── claims_provider_test.go
│   │       └── config.go              # Claims provider configuration
│   └── v2/
│       ├── multi_strategy_entity_resolution.go    # V2 API implementation
│       └── multi_strategy_entity_resolution_test.go
├── sql/                                  # Existing SQL ERS (unchanged)
├── ldap/                                 # Existing LDAP ERS (unchanged)
├── keycloak/                             # Existing Keycloak ERS (unchanged)
└── claims/                               # Existing Claims ERS (unchanged)
```

**Dependencies**:
- Database drivers: `lib/pq` (PostgreSQL), `go-sql-driver/mysql` (MySQL), `modernc.org/sqlite` (SQLite)
- LDAP client: `go-ldap/ldap/v3` with TLS support
- JWT claims provider: Built-in fallback using validated JWT claims directly
- Standard OpenTDF ERS interfaces and service registration

### Field-Agnostic Philosophy

Multi-Strategy ERS makes **no assumptions** about the semantic meaning of data fields. Unlike V1 implementations that assume specific field names like "email" or "username", the multi-strategy approach treats all data as generic claims that get mapped through configuration.

**Key Principles**:
- **No Hardcoded Field Names**: The ERS doesn't know what "email" means - it just maps `source_column: "user_id"` to `claim_name: "primary_identifier"`
- **Semantic Interpretation in Policies**: Subject Mappings handle the semantic meaning through JSONPath selectors like `.primary_identifier`
- **Complete Flexibility**: Organizations can use any field names and map them to any claim names
- **Future-Proof**: New data types and organizational structures don't require code changes

**Example**: Same logical concept, different database schemas:
```yaml
# Company A: Uses "email" as primary identifier
output_mapping:
  - source_column: "email_address"
    claim_name: "primary_identifier"

# Company B: Uses employee ID as primary identifier  
output_mapping:
  - source_column: "employee_id"
    claim_name: "primary_identifier"

# Both work with the same Subject Mapping:
conditions:
  - subject_external_selector_value: ".primary_identifier"
    operator: "EXISTS"
```

### Configuration Schema

```yaml
services:
  entityresolution:
    mode: "multi-strategy"    # New mode alongside existing: keycloak, claims, ldap, sql
    
    # Define multiple providers with different backend types
    providers:
      primary_db:
        type: "sql"
        connection:
          driver: "postgres"
          dsn: "postgres://ers_user:secret@primary-db.corp.com:5432/identity?sslmode=require"
          max_open_conns: 25
          max_idle_conns: 10
          conn_max_lifetime: "1h"
          query_timeout: "30s"
          
      backup_db:
        type: "sql" 
        connection:
          driver: "postgres"
          dsn: "postgres://ers_user:secret@backup-db.corp.com:5432/identity?sslmode=require"
          max_open_conns: 10
          max_idle_conns: 5
          
      corporate_ldap:
        type: "ldap"
        connection:
          servers: 
            - "ldaps://primary.ad.corp.com:636"
            - "ldaps://backup.ad.corp.com:636"
          auth_method: "simple"
          bind_dn: "cn=svc-opentdf,ou=service-accounts,dc=corp,dc=com"
          bind_password: "secret"
          timeout: "30s"
          connection_pool_size: 10
          
      partner_ldap:
        type: "ldap"
        connection:
          servers: ["ldaps://partner.external.com:636"]
          bind_dn: "cn=opentdf-svc,ou=services,dc=partner,dc=com" 
          bind_password: "partner-secret"
          
      jwt_claims:
        type: "claims"
        # No connection needed - uses JWT claims directly
    
    # Strategy-based mapping with provider selection
    mapping_strategies:
      # Strategy 1: Try JWT claims first for zero-latency resolution
      - name: "jwt_claims_primary"
        provider: "jwt_claims"
        conditions:
          jwt_claims:
            - claim: "email"
              operator: "exists"
            - claim: "department"        # Only use if JWT has rich organizational context
              operator: "exists"
            - claim: "groups"           # Require sufficient data for authorization
              operator: "exists"
              
        # No input_mapping needed - provider reads JWT claims directly
        output_mapping:
          - source_claim: "email"
            claim_name: "primary_identifier"
          - source_claim: "department"
            claim_name: "organizational_unit"
          - source_claim: "groups"
            claim_name: "group_memberships"
            transformation: "csv_to_array"    # Handle "admin,user,finance" format
          - source_claim: "clearance"         # JWT uses different claim name
            claim_name: "access_level"
          - source_claim: "cost_center"
            claim_name: "cost_center"
          - source_claim: "manager_email"
            claim_name: "reporting_manager"

      # Strategy 2: Corporate employees from primary database (fallback for enrichment)
      - name: "corporate_users_primary"
        provider: "primary_db"
        conditions:
          jwt_claims:
            - claim: "email"
              operator: "exists"
            - claim: "iss"
              operator: "equals"
              values: ["https://keycloak.corp.com"]
            - claim: "aud"
              operator: "contains"
              values: ["opentdf-platform"]
              
        input_mapping:
          - jwt_claim: "email"
            parameter: "user_email"
            required: true
          - jwt_claim: "iss"
            parameter: "issuer_domain"
            
        query: |
          SELECT 
            u.email,
            u.username,
            u.department,
            u.clearance_level,
            u.cost_center,
            u.manager_email,
            array_agg(DISTINCT g.group_name) as groups,
            array_agg(DISTINCT p.project_code) as authorized_projects
          FROM users u
          LEFT JOIN user_groups ug ON u.id = ug.user_id
          LEFT JOIN groups g ON ug.group_id = g.id
          LEFT JOIN user_projects up ON u.id = up.user_id
          LEFT JOIN projects p ON up.project_id = p.id
          WHERE u.email = :user_email 
            AND u.active = true
            AND u.tenant = :issuer_domain
          GROUP BY u.id, u.email, u.username, u.department, u.clearance_level, u.cost_center, u.manager_email
          
        # Strategy-specific output mapping (field-agnostic)
        output_mapping:
          - source_column: "email"
            claim_name: "primary_identifier"      # No assumptions about what this represents
          - source_column: "username"
            claim_name: "secondary_identifier"
          - source_column: "department"
            claim_name: "organizational_unit"     # Generic organizational context
          - source_column: "clearance_level"
            claim_name: "access_level"            # Generic access level concept
          - source_column: "cost_center"
            claim_name: "cost_center"
          - source_column: "manager_email"
            claim_name: "reporting_manager"
          - source_column: "groups"
            claim_name: "group_memberships"       # Generic group concept
            transformation: "array"
          - source_column: "authorized_projects"
            claim_name: "project_assignments"     # Generic project access
            transformation: "array"

      # Strategy 3: Backup database failover strategy  
      - name: "corporate_users_backup"
        provider: "backup_db"
        conditions:
          jwt_claims:
            - claim: "email"
              operator: "exists"
            - claim: "iss"
              operator: "equals"
              values: ["https://keycloak.corp.com"]
            - claim: "backup_mode"
              operator: "equals"
              values: ["true"]
              
        input_mapping:
          - jwt_claim: "email"
            parameter: "user_email"
            required: true
            
        query: |
          SELECT u.email, u.username, u.department, u.clearance_level
          FROM users u
          WHERE u.email = :user_email AND u.active = true
          
        output_mapping:
          - source_column: "email"
            claim_name: "primary_identifier"
          - source_column: "username"
            claim_name: "secondary_identifier"
          - source_column: "department"
            claim_name: "organizational_unit"
          - source_column: "clearance_level"
            claim_name: "access_level"

      # Strategy 4: External contractors from partner LDAP
      - name: "contractor_users_ldap"
        provider: "partner_ldap"
        conditions:
          jwt_claims:
            - claim: "preferred_username"
              operator: "exists"
            - claim: "iss"
              operator: "equals"
              values: ["https://partner-sso.external.com"]
            - claim: "contractor_id"
              operator: "exists"
              
        input_mapping:
          - jwt_claim: "preferred_username"
            parameter: "username"
            required: true
          - jwt_claim: "contractor_id"
            parameter: "contractor_id"
            required: true
            
        ldap_search:
          base_dn: "ou=contractors,dc=partner,dc=com"
          filter: "(&(objectClass=person)(uid={{.username}})(contractorID={{.contractor_id}}))"
          scope: "subtree"
          attributes:
            - "uid"
            - "contractorID"
            - "partnerOrg"
            - "contractLevel"
            - "memberOf"
            
        output_mapping:
          - source_attribute: "uid"
            claim_name: "primary_identifier"
          - source_attribute: "contractorID"
            claim_name: "external_reference"
          - source_attribute: "partnerOrg"
            claim_name: "partner_organization"
          - source_attribute: "contractLevel"
            claim_name: "access_level"
          - source_attribute: "memberOf"
            claim_name: "group_memberships"
            transformation: "ldap_dn_to_cn_array"

    # Health check configuration
    health_check:
      enabled: true
      interval: "60s"
      provider_checks:
        - provider: "primary_db"
          query: "SELECT 1"
        - provider: "corporate_ldap"
          bind_test: true
        # Note: jwt_claims provider needs no health check - always available
```

### Core Implementation

**Service Interface Implementation**:
```go
type MultiStrategyEntityResolutionService struct {
    entityresolution.UnimplementedEntityResolutionServiceServer
    config      MultiStrategyConfig
    providers   map[string]Provider
    strategies  []MappingStrategy
    logger      *logger.Logger
    trace.Tracer
}

// Provider interface that all backends implement
type Provider interface {
    Name() string
    Type() string  // "sql", "ldap", "claims", etc.
    ResolveEntity(ctx context.Context, strategy MappingStrategy, params map[string]interface{}) (*RawResult, error)
    HealthCheck(ctx context.Context) error
}

func (s *MultiStrategyEntityResolutionService) ResolveEntities(
    ctx context.Context, 
    req *connect.Request[entityresolution.ResolveEntitiesRequest],
) (*connect.Response[entityresolution.ResolveEntitiesResponse], error) {
    // Implementation details below
}
```

**Strategy Selection Flow**:
1. **JWT Extraction**: Extract JWT claims from request
2. **Strategy Matching**: Find first strategy where conditions match JWT
3. **Provider Selection**: Get provider instance for selected strategy
4. **Parameter Extraction**: Extract parameters from JWT using input mapping
5. **Backend Query**: Execute strategy against provider with parameters
6. **Result Transformation**: Apply strategy-specific output mapping
7. **Response Construction**: Build EntityRepresentation with mapped claims

**Strategy Matching Implementation**:
```go
func (s *MultiStrategyEntityResolutionService) selectStrategy(jwt *JWT) (*MappingStrategy, error) {
    for _, strategy := range s.strategies {
        if s.matchesConditions(jwt, strategy.Conditions) {
            // Simple health check before using provider (except JWT claims)
            if strategy.Provider != "jwt_claims" {
                provider := s.providers[strategy.Provider]
                if err := provider.HealthCheck(ctx); err != nil {
                    s.logger.Warn("Provider unhealthy, trying next strategy", 
                                  "provider", strategy.Provider, "error", err)
                    continue
                }
            }
            return &strategy, nil
        }
    }
    return nil, ErrNoMatchingStrategy
}

func (s *MultiStrategyEntityResolutionService) matchesConditions(jwt *JWT, conditions Conditions) bool {
    for _, claimCondition := range conditions.JWTClaims {
        claimValue := jwt.GetClaim(claimCondition.Claim)
        
        switch claimCondition.Operator {
        case "exists":
            if claimValue == nil {
                return false
            }
        case "equals":
            if !s.valueEqualsIgnoreCase(claimValue, claimCondition.Values) {
                return false
            }
        case "contains":
            if !s.valueContainsIgnoreCase(claimValue, claimCondition.Values) {
                return false
            }
        case "regex":
            if !s.valueMatchesRegex(claimValue, claimCondition.Values) {
                return false
            }
        }
    }
    return true
}
```

**JWT Claims Provider Implementation**:
```go
// ClaimsProvider uses JWT claims directly as the data source
type ClaimsProvider struct {
    name string
}

func (p *ClaimsProvider) ResolveEntity(
    ctx context.Context, 
    strategy MappingStrategy, 
    params map[string]interface{},
) (*RawResult, error) {
    // Extract JWT from context (already validated by ERS)
    jwt := extractJWTFromContext(ctx)
    
    // Return JWT claims directly as "query result"
    result := &RawResult{
        Data: make(map[string]interface{}),
    }
    
    // Copy all JWT claims to result for output mapping
    for claim, value := range jwt.Claims {
        result.Data[claim] = value
    }
    
    return result, nil
}

func (p *ClaimsProvider) HealthCheck(ctx context.Context) error {
    return nil  // Always healthy - no external dependencies
}
```

### Security Features

**Query Security**:
- **Parameterized Queries**: All input parameters use parameterized queries/LDAP escaping to prevent injection
- **Input Validation**: All user input validated and sanitized before query execution
- **SQL Injection Prevention**: No template substitution in queries - all values are properly parameterized
- **Case-Insensitive Matching**: All string comparisons are case-insensitive to reduce configuration errors

**Connection Security**:
- **TLS/SSL**: All connections use secure protocols (LDAPS, SSL PostgreSQL)
- **Credential Management**: Support for environment variables and secret management systems
- **Connection Pooling**: Proper limits to prevent resource exhaustion
- **Provider Isolation**: Provider failures don't affect other providers

### Error Handling and Resilience

**Strategy Failover**:
- **Ordered Strategy Matching**: Strategies evaluated in configuration order
- **Graceful Degradation**: Continue to next strategy if current fails
- **Provider Health Monitoring**: Simple per-request health checks before provider usage
- **JWT Claims Fallback**: Ultimate fallback using JWT claims when all external systems fail

**Cross-Backend Failover Example**:
```yaml
mapping_strategies:
  # Try primary database first
  - name: "users_primary"
    provider: "primary_db"
    conditions: [...]
    
  # Fallback to LDAP if database fails  
  - name: "users_ldap_fallback"
    provider: "corporate_ldap"
    conditions: [...]  # Same conditions as primary!
    
  # JWT claims as fast path or fallback
  - name: "users_jwt_claims"
    provider: "jwt_claims"
    conditions: [...]  # Works when JWT has sufficient organizational data
```

### Performance Considerations

**Connection Management**:
- **Connection Pooling**: Per-provider connection pools with configurable limits
- **Connection Reuse**: Efficient connection sharing across concurrent requests
- **Health Monitoring**: Periodic health checks to maintain connection quality

**Caching Strategy**:
- **Application-Level Caching**: Optional caching layer for expensive queries
- **Cache Invalidation**: TTL-based and event-driven cache invalidation

**Query Optimization**:
- **Prepared Statements**: SQL providers use prepared statements for repeated queries
- **LDAP Indexing**: Optimize LDAP filters for indexed attributes
- **Parallel Provider Access**: Future enhancement for parallel strategy evaluation

### Testing Strategy

**Unit Tests**:
- **Strategy Matching**: JWT condition evaluation and strategy selection
- **Parameter Extraction**: Input mapping from JWT claims to query parameters
- **Output Mapping**: Result transformation from provider responses to claims
- **Provider Interface**: Mock providers for isolated testing

**Integration Tests**:
```
service/entityresolution/integration/
├── multi_strategy_test.go           # Multi-strategy core integration tests
├── multi_strategy_sql_test.go       # SQL provider integration tests
├── multi_strategy_ldap_test.go      # LDAP provider integration tests
├── multi_strategy_claims_test.go    # JWT claims provider integration tests
├── multi_strategy_failover_test.go  # Cross-provider failover tests
└── multi_strategy_performance_test.go # Load testing and benchmarks
```

**Strategy-Based Test Structure**:
```go
// multi_strategy_sql_test.go
func TestCorporateUsersStrategySQLProvider(t *testing.T) {
    // Test corporate_users_primary strategy with SQL provider
}

func TestContractorUsersStrategySQLProvider(t *testing.T) { 
    // Test contractor_users strategy with SQL provider
}

// multi_strategy_claims_test.go
func TestJWTClaimsProviderFastPath(t *testing.T) {
    // Test JWT claims provider for zero-latency resolution
}

// multi_strategy_failover_test.go
func TestSQLToLDAPToJWTFailover(t *testing.T) {
    // Test complete failover chain: SQL → LDAP → JWT claims
}

func TestStrategySelectionByJWTContext(t *testing.T) {
    // Test that different JWTs select appropriate strategies and providers
}
```

## Validation

Implementation success will be measured by:
- Successfully resolving entities from multiple backend types (SQL, LDAP, JWT claims) within single ERS instance
- Dynamic strategy selection based on JWT context with >95% accuracy
- Cross-backend failover working seamlessly without client awareness
- End-to-end authorization flow validation: Multi-strategy data → flattening → SubjectMapping evaluation → access decisions
- Performance benchmarks showing <10% overhead compared to single-backend ERS
- Integration test coverage > 85% with strategy-based test organization
- Security audit confirming proper parameter handling and connection security across all providers

## Authorization Integration Flow

The complete flow demonstrating how multi-strategy ERS enables rich authorization decisions:

### Example Scenario
**User**: `alice@corp.com` requests access to classified financial data  
**JWT Token with Rich Claims**:
```json
{
  "sub": "alice-123",
  "email": "alice@corp.com",
  "iss": "https://keycloak.corp.com",
  "aud": ["opentdf-platform"],
  "department": "Finance",
  "groups": "finance-analysts,senior-staff",
  "clearance": "Secret",
  "cost_center": "FC-1001"
}
```

### Integration Steps

1. **Strategy Selection**: Multi-Strategy ERS evaluates conditions in order
   - `jwt_claims_primary` matches first: email exists, department exists, groups exists
   - **Zero-latency resolution** - no external calls needed!
   
2. **JWT Claims Processing**: Extract claims directly from validated JWT
   - No parameter extraction or database queries needed
   - Claims already available in memory

3. **Field-Agnostic Output Mapping**: Transform JWT claims to generic claim names
   ```json
   {
     "primary_identifier": "alice@corp.com",
     "organizational_unit": "Finance", 
     "access_level": "Secret",                    // mapped from "clearance"
     "group_memberships": ["finance-analysts", "senior-staff"],  // CSV to array
     "cost_center": "FC-1001"
   }
   ```

4. **Authorization Evaluation**: SubjectMapping policies use generic claim selectors
   ```yaml
   conditions:
     - subject_external_selector_value: ".organizational_unit"
       operator: "IN"
       subject_external_values: ["Finance", "Accounting"]
     - subject_external_selector_value: ".access_level"
       operator: "IN"
       subject_external_values: ["Secret", "TopSecret"]
     - subject_external_selector_value: ".group_memberships[]"
       operator: "IN"
       subject_external_values: ["finance-analysts"]
   ```

5. **Access Decision**: All conditions match → **PERMIT** access to classified financial data

**Performance Benefits**:
- ⚡ **Sub-millisecond resolution** - no network latency
- 💰 **Zero infrastructure cost** - no database or LDAP queries  
- 🔄 **100% availability** - no external dependencies
- 📊 **Immediate response** - perfect for high-frequency authorization checks

### Strategy Ordering Patterns

Multi-Strategy ERS supports flexible strategy ordering based on your performance and data authority requirements:

**JWT Claims First (Performance-Optimized)**:
```yaml
mapping_strategies:
  # Fast path: Use JWT if it has rich organizational data
  - name: "jwt_fast_path"
    provider: "jwt_claims"
    conditions:
      jwt_claims:
        - claim: "department"
          operator: "exists"
        - claim: "clearance"
          operator: "exists"
        
  # Fallback: Database enrichment for lean JWTs
  - name: "database_enrichment"
    provider: "primary_db"
    conditions:
      jwt_claims:
        - claim: "email"
          operator: "exists"
```

**Database First (Authority-Optimized)**:
```yaml  
mapping_strategies:
  # Authoritative: Always get latest data from system of record
  - name: "database_authoritative"
    provider: "primary_db"
    conditions:
      jwt_claims:
        - claim: "email"
          operator: "exists"
        
  # Fallback: JWT when database unavailable
  - name: "jwt_fallback"
    provider: "jwt_claims"
    conditions:
      jwt_claims:
        - claim: "email"
          operator: "exists"
```

**Hybrid (Context-Sensitive)**:
```yaml
mapping_strategies:
  # High-frequency users: JWT first for performance
  - name: "frequent_users_fast"
    provider: "jwt_claims"
    conditions:
      jwt_claims:
        - claim: "user_tier"
          operator: "equals"
          values: ["premium"]
          
  # Admin users: Database first for latest permissions
  - name: "admin_users_authoritative"  
    provider: "primary_db"
    conditions:
      jwt_claims:
        - claim: "groups"
          operator: "contains"
          values: ["admin"]
```

## Future Enhancements

**Additional Provider Types**:
- HTTP API providers for REST/GraphQL endpoints
- NoSQL providers (MongoDB, DynamoDB, Cassandra)
- Key-value stores (Consul, etcd, Vault)
- File-based providers (CSV, JSON, XML)

**Advanced Features**:
- **Parallel Strategy Evaluation**: Execute multiple strategies concurrently and merge results
- **Result Caching**: Configurable caching layer with TTL and invalidation policies
- **Metrics and Monitoring**: Detailed per-strategy and per-provider performance metrics
- **Dynamic Configuration**: Hot-reload configuration changes without service restart
- **Strategy Templates**: Reusable strategy templates for common patterns

**Enterprise Integration**:
- **Audit Logging**: Comprehensive audit trail for all strategy selections and data access
- **Rate Limiting**: Per-strategy and per-provider rate limiting for resource protection
- **Circuit Breakers**: Advanced circuit breaker patterns for provider resilience
- **Load Balancing**: Provider-level load balancing for high availability deployments

This implementation provides a robust, secure, and flexible foundation for unified access to any organizational data source, enabling OpenTDF's fine-grained authorization system to leverage the full spectrum of enterprise identity and context data.