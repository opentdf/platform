# Multi-Strategy Entity Resolution Service (PREVIEW)

> **⚠️ Preview Status**: This service is in preview. APIs and configurations may change.

The Multi-Strategy Entity Resolution Service enables unified access to heterogeneous identity systems through intelligent strategy selection based on JWT context. It consolidates SQL, LDAP, and JWT Claims providers into a single service with advanced data transformation capabilities.

## Stability Status
- **Service**: 🚧 Preview (V2 only)
- **SQL Provider**: 🚧 Preview  
- **LDAP Provider**: 🚧 Preview
- **Claims Provider**: ✅ Stable (delegates to stable Claims ERS)

## Overview

### Key Features

- **🔀 Multiple Backends**: SQL, LDAP, and JWT Claims in one service
- **🧠 Intelligent Routing**: Dynamic strategy selection based on JWT context
- **🔄 Cross-Backend Failover**: Automatic failover between different identity systems  
- **⚡ Data Transformations**: 16 transformation types for data normalization
- **📊 Field-Agnostic Design**: No hardcoded assumptions about field names or schemas
- **🚀 Performance Optimization**: JWT-first routing for zero-latency resolution

### Architecture

```
JWT Request → Strategy Matcher → Provider Selection → Data Transformation → Normalized Claims
     ↓              ↓                    ↓                     ↓                    ↓
   Context      Condition         SQL/LDAP/Claims        csv_to_array         Standard
  Analysis      Evaluation         Execution            ldap_dn_to_cn         Format
```

## Quick Start

### 1. Basic Configuration

```yaml
services:
  entityresolution:
    mode: "multi-strategy"
    failure_strategy: "continue"  # Try all strategies until one succeeds
    
    providers:
      jwt_claims:
        type: claims
      primary_db:
        type: sql
        connection:
          driver: postgres
          host: localhost
          port: 5432
          database: identity_db
          username: ers_user
          password: ers_password
      corporate_ldap:
        type: ldap
        connection:
          host: ldap.company.com
          port: 636
          use_tls: true
          bind_dn: "cn=service,ou=apps,dc=company,dc=com"
          bind_password: "secret"
```

### 2. Strategy Configuration

```yaml
    mapping_strategies:
      # Fast path: Use JWT if it has rich data
      - name: jwt_fast_path
        provider: jwt_claims
        entity_type: subject
        conditions:
          jwt_claims:
            - claim: department
              operator: exists
            - claim: groups
              operator: exists
        output_mapping:
          - source_claim: email
            claim_name: primary_identifier
          - source_claim: groups
            claim_name: group_memberships
            transformation: csv_to_array
            
      # Fallback: Database lookup for enrichment  
      - name: database_lookup
        provider: primary_db
        entity_type: subject
        conditions:
          jwt_claims:
            - claim: email
              operator: exists
        query: |
          SELECT email, department, string_agg(g.name, ',') as groups
          FROM users u
          LEFT JOIN user_groups ug ON u.id = ug.user_id  
          LEFT JOIN groups g ON ug.group_id = g.id
          WHERE u.email = $1
          GROUP BY u.email, u.department
        input_mapping:
          - jwt_claim: email
            parameter: email
            required: true
        output_mapping:
          - source_column: email
            claim_name: primary_identifier
          - source_column: department
            claim_name: organizational_unit
          - source_column: groups
            claim_name: group_memberships
            transformation: csv_to_array
```

## Data Transformations

### Common Transformations (All Providers)

| Transformation | Input | Output | Use Case |
|---------------|-------|---------|----------|
| `csv_to_array` | `"admin,user,finance"` | `["admin", "user", "finance"]` | Legacy CSV data |
| `array` | `"single_value"` | `["single_value"]` | Normalize to arrays |
| `string` | `123` | `"123"` | Type conversion |
| `lowercase` | `"ADMIN"` | `"admin"` | Case normalization |
| `uppercase` | `"admin"` | `"ADMIN"` | Case normalization |

### SQL-Specific Transformations

| Transformation | Input | Output | Use Case |
|---------------|-------|---------|----------|
| `postgres_array` | `"{apple,banana,cherry}"` | `["apple", "banana", "cherry"]` | PostgreSQL arrays |

### LDAP-Specific Transformations

| Transformation | Input | Output | Use Case |
|---------------|-------|---------|----------|
| `ldap_dn_to_cn_array` | `["CN=Users,OU=Groups", "CN=Admins,OU=Groups"]` | `["Users", "Admins"]` | Extract common names |
| `ldap_dn_to_cn` | `"CN=John Doe,OU=Users"` | `"John Doe"` | Single DN extraction |
| `ldap_attribute_values` | Multi-valued LDAP attribute | `["value1", "value2"]` | LDAP multi-values |
| `ad_group_name` | `"CN=Domain Users,CN=Groups"` | `"Domain Users"` | Active Directory groups |

### Claims-Specific Transformations  

| Transformation | Input | Output | Use Case |
|---------------|-------|---------|----------|
| `jwt_extract_scope` | `"read write admin"` | `["read", "write", "admin"]` | OAuth2 scopes |
| `jwt_normalize_groups` | `"finance,admin"` or `"finance admin"` | `["finance", "admin"]` | Various group formats |

## Strategy Selection

### Condition Operators

- **`exists`**: Check if JWT claim exists
- **`equals`**: Exact value match (case-insensitive)
- **`contains`**: Check if claim contains any of the specified values
- **`regex`**: Regular expression matching

### Example Strategy Patterns

#### Performance-Optimized (JWT First)
```yaml
mapping_strategies:
  - name: jwt_fast_path
    provider: jwt_claims
    conditions:
      jwt_claims:
        - claim: groups
          operator: exists
    # Zero-latency resolution
    
  - name: database_fallback  
    provider: primary_db
    conditions:
      jwt_claims:
        - claim: email
          operator: exists
    # Database enrichment when JWT lacks data
```

#### Authority-Optimized (Database First)
```yaml
mapping_strategies:
  - name: database_authoritative
    provider: primary_db
    conditions:
      jwt_claims:
        - claim: email
          operator: exists
    # Always get latest data from system of record
    
  - name: jwt_fallback
    provider: jwt_claims  
    conditions:
      jwt_claims:
        - claim: email
          operator: exists
    # Fallback when database unavailable
```

#### Context-Sensitive Routing
```yaml
mapping_strategies:
  - name: internal_users_jwt
    provider: jwt_claims
    conditions:
      jwt_claims:
        - claim: aud
          operator: contains
          values: ["internal"]
    # Fast path for internal users
    
  - name: external_users_ldap
    provider: corporate_ldap
    conditions:
      jwt_claims:
        - claim: aud
          operator: contains  
          values: ["external", "partner"]
    # LDAP lookup for external users
```

## Failure Strategies

The failure strategy determines how Multi-Strategy ERS handles failures when executing strategies. This is a **global setting** that applies to all strategy execution in the service.

### Global Failure Strategy Options

#### `fail-fast` (Default)
- **Behavior**: Stop immediately when **any** strategy fails
- **Use Case**: When you want strict error handling and immediate failure notification
- **Result**: Returns error on first strategy failure, no fallback attempts

#### `continue` 
- **Behavior**: Try **all matching strategies** until one succeeds
- **Use Case**: When you want resilient failover with multiple fallback options
- **Result**: Only fails if **all** matching strategies fail

```yaml
services:
  entityresolution:
    failure_strategy: "continue"  # Global setting for entire service
    # OR
    failure_strategy: "fail-fast"  # Default - immediate failure
```

### Failure Strategy Behavior Examples

#### Example 1: fail-fast Strategy
```yaml
services:
  entityresolution:
    failure_strategy: "fail-fast"  # Default
    
mapping_strategies:
  - name: primary_db
    provider: main_database
    conditions: [...]
    
  - name: backup_db  
    provider: backup_database
    conditions: [...]  # Same conditions as primary
```

**Scenario**: Primary database is down
- ✅ **Request matches both strategies** (same conditions)
- ❌ **Primary strategy fails** (database connection error)
- 🛑 **Service immediately returns error** (fail-fast behavior)
- ❌ **Backup strategy never attempted**

#### Example 2: continue Strategy  
```yaml
services:
  entityresolution:
    failure_strategy: "continue"  # Resilient failover
    
mapping_strategies:
  - name: primary_db
    provider: main_database
    conditions: [...]
    
  - name: backup_db
    provider: backup_database  
    conditions: [...]  # Same conditions as primary
```

**Scenario**: Primary database is down
- ✅ **Request matches both strategies** (same conditions)
- ❌ **Primary strategy fails** (database connection error)
- ➡️ **Continue to next strategy** (continue behavior)  
- ✅ **Backup strategy succeeds** (returns data)
- ✅ **Request succeeds with backup data**

### Common Failure Scenarios

#### Scenario 1: Database Connection Failure
```yaml
failure_strategy: "continue"  # Enable failover

strategies:
  - name: primary_database
    provider: main_db
    # ❌ Database server is down
    
  - name: backup_database  
    provider: backup_db
    # ✅ Backup server is healthy
```
**Result**: Request succeeds using backup database

#### Scenario 2: Missing JWT Claims
```yaml
failure_strategy: "continue"  # Enable fallback

strategies:
  - name: jwt_fast_path
    provider: jwt_claims
    conditions:
      - claim: "groups"
        operator: "exists"
    # ❌ JWT missing 'groups' claim - condition fails
    
  - name: database_enrichment
    provider: user_db
    conditions:
      - claim: "email" 
        operator: "exists"
    # ✅ JWT has 'email' claim - condition matches
```
**Result**: Falls back to database lookup when JWT lacks required claims

#### Scenario 3: No Matching Strategies
```yaml
# JWT contains: {"sub": "user123", "aud": ["unknown"]}

strategies:
  - name: internal_users
    conditions:
      - claim: "aud"
        operator: "contains"
        values: ["internal"]  # ❌ No match
        
  - name: external_users  
    conditions:
      - claim: "aud"
        operator: "contains" 
        values: ["external"]  # ❌ No match
```
**Result**: Error - "no matching strategies found" (regardless of failure_strategy)

### Failover Patterns

#### Linear Failover (JWT → SQL → LDAP)
```yaml
failure_strategy: "continue"  # Required for failover

mapping_strategies:
  - name: jwt_primary
    provider: jwt_claims
    conditions: [...same conditions...]
    
  - name: sql_secondary  
    provider: primary_db
    conditions: [...same conditions...]
    
  - name: ldap_tertiary
    provider: corporate_ldap
    conditions: [...same conditions...]
```

**Execution Flow**:
1. Try JWT claims first (fastest)
2. If JWT fails → Try SQL database  
3. If SQL fails → Try LDAP directory
4. If LDAP fails → Return error (all strategies exhausted)

#### Contextual Failover
```yaml
mapping_strategies:
  - name: employees_primary_db
    provider: primary_db
    conditions:
      jwt_claims:
        - claim: employee_id
          operator: exists
          
  - name: employees_ldap_backup
    provider: corporate_ldap
    conditions:
      jwt_claims:
        - claim: employee_id
          operator: exists
        - claim: backup_mode
          operator: equals
          values: ["true"]
```

### Failure Strategy Best Practices

#### When to Use `fail-fast` (Default)
✅ **Use fail-fast when:**
- **Development/Testing**: Quick feedback on configuration errors
- **Strict Requirements**: System must fail if primary data source is unavailable
- **Single Provider**: Only one strategy/provider configured (no fallback needed)
- **Critical Operations**: Better to fail than use potentially stale backup data

❌ **Avoid fail-fast when:**
- **High Availability Required**: System must stay operational during provider outages
- **Multiple Providers**: You have backup/fallback providers configured

#### When to Use `continue`
✅ **Use continue when:**
- **High Availability**: System must remain operational during provider failures
- **Graceful Degradation**: Acceptable to use backup/cached data during outages
- **Multiple Providers**: You have primary → backup → fallback chains configured
- **Production Environments**: Resilience is more important than strict consistency

❌ **Avoid continue when:**
- **Data Consistency Critical**: Using stale backup data could cause security issues
- **Single Provider**: No fallback options available (continue won't help)

### Configuration Examples

#### Production: High Availability Setup
```yaml
services:
  entityresolution:
    failure_strategy: "continue"  # Resilient failover
    
    providers:
      primary_db:
        type: sql
        connection: {...}
      backup_db:
        type: sql  
        connection: {...}  # Different server
      jwt_fallback:
        type: claims       # Always available
        
    mapping_strategies:
      # Try database first (authoritative)
      - name: primary_database
        provider: primary_db
        conditions: [...]
        
      # Fallback to backup database  
      - name: backup_database
        provider: backup_db
        conditions: [...]  # Same conditions
        
      # Ultimate fallback using JWT
      - name: jwt_claims_fallback
        provider: jwt_fallback
        conditions: [...]  # Same conditions
```

#### Development: Fast Feedback Setup  
```yaml
services:
  entityresolution:
    failure_strategy: "fail-fast"  # Quick error detection
    
    providers:
      dev_db:
        type: sql
        connection: {...}
        
    mapping_strategies:
      - name: single_strategy
        provider: dev_db
        conditions: [...]
        
# Fails immediately if database is misconfigured
# Provides clear error messages for development
```

### Important Notes

⚠️ **Key Behaviors:**
- **Strategy Selection**: failure_strategy only affects **strategy execution**, not **strategy matching**
- **No Matching Strategies**: Always returns error regardless of failure_strategy setting
- **Global Setting**: failure_strategy applies to **all strategies** in the service
- **Condition vs Execution**: Unmatched conditions ≠ execution failure

🔍 **Troubleshooting:**
- **"No matching strategies"**: Check JWT claim conditions, not failure_strategy
- **Immediate failures**: Verify failure_strategy is set to "continue" for failover
- **Backup never used**: Ensure backup strategies have identical conditions to primary

## Configuration Reference

### Provider Types

#### SQL Provider
```yaml
providers:
  my_db:
    type: sql
    connection:
      driver: postgres          # postgres, mysql, sqlite
      host: localhost
      port: 5432
      database: identity_db
      username: ers_user
      password: ers_password
      ssl_mode: require
      max_open_connections: 25
      max_idle_connections: 5
      connection_max_lifetime: 1h
      query_timeout: 30s
```

#### LDAP Provider  
```yaml
providers:
  my_ldap:
    type: ldap
    connection:
      host: ldap.company.com
      port: 636
      use_tls: true
      bind_dn: "cn=service,ou=apps,dc=company,dc=com"
      bind_password: "secret"
      timeout: 30s
      connection_pool_size: 10
```

#### Claims Provider
```yaml
providers:
  my_claims:
    type: claims
    # No connection configuration needed
```

### Mapping Strategy Properties

```yaml
mapping_strategies:
  - name: "strategy_name"
    provider: "provider_name"
    entity_type: "subject"     # or "environment"
    conditions:
      jwt_claims:
        - claim: "claim_name"
          operator: "exists"    # exists, equals, contains, regex
          values: ["value1"]    # for equals, contains, regex
    query: "SELECT ..."        # SQL only
    ldap_search:               # LDAP only
      base_dn: "ou=users,dc=company,dc=com"
      filter: "(&(objectClass=person)(uid={username}))"
      scope: "subtree"
      attributes: ["uid", "cn", "memberOf"]
    input_mapping:
      - jwt_claim: "email"
        parameter: "email"     # SQL parameter or LDAP template variable
        required: true
    output_mapping:
      - source_column: "email"         # SQL
        source_attribute: "mail"       # LDAP  
        source_claim: "email"          # Claims
        claim_name: "primary_identifier"
        transformation: "csv_to_array"
```

## Performance Characteristics

| Strategy Pattern | Latency | Throughput | Availability |
|-----------------|---------|------------|--------------|
| **JWT-First** | <1ms | Very High | 100% |
| **Database-First** | 5-50ms | High | 99.9% |
| **LDAP-First** | 10-100ms | Medium | 99.5% |
| **Cross-Backend Failover** | Variable | Medium | 99.99% |

## Best Practices

### 1. Strategy Ordering
- **Put fastest strategies first** (JWT Claims → SQL → LDAP)
- **Order by data freshness requirements** (Database → JWT fallback)
- **Consider failure probability** (most reliable first)

### 2. Condition Design  
- **Be specific with conditions** to avoid strategy conflicts
- **Use audience claims** to differentiate user types
- **Test condition logic** with realistic JWT tokens

### 3. Transformation Usage
- **Use common transformations** when possible for consistency
- **Apply transformations at output** to normalize data formats
- **Document transformation choices** in configuration comments

### 4. Security Considerations
- **Use parameterized queries** for all SQL providers
- **Enable TLS/SSL** for all external connections  
- **Limit connection pool sizes** to prevent resource exhaustion
- **Monitor failed authentication attempts**

## Testing

### Integration Testing
```bash
# Test multi-strategy functionality
cd service/entityresolution/integration
go test -v -run TestMultiStrategy

# Test specific provider combinations
go test -v -run TestMultiStrategy_SQL
go test -v -run TestMultiStrategy_LDAP  
go test -v -run TestMultiStrategy_Claims
```

### Strategy Testing
Create test scenarios for different JWT contexts:
```go
func TestStrategySelectorWithInternalJWT(t *testing.T) {
    jwt := map[string]interface{}{
        "aud": []string{"internal"},
        "email": "user@company.com", 
        "department": "Engineering",
    }
    // Should select jwt_fast_path strategy
}

func TestFailoverFromSQLToLDAP(t *testing.T) {
    // Simulate SQL failure, verify LDAP fallback
}
```

## Migration from Single-Backend ERS

### From SQL ERS
1. **Configure SQL provider** with existing connection details
2. **Create fallback strategy** using JWT Claims provider
3. **Add transformations** to handle data format differences
4. **Test with production-like JWT tokens**

### From LDAP ERS  
1. **Configure LDAP provider** with existing connection details
2. **Add LDAP-specific transformations** for DN handling
3. **Create JWT fallback** for high availability
4. **Verify attribute mapping** matches existing behavior

### From Claims ERS
1. **Keep existing JWT strategy** as primary
2. **Add database provider** for data enrichment
3. **Configure intelligent routing** based on JWT completeness
4. **Test performance impact** of database lookups

## Troubleshooting

### Common Issues

1. **No matching strategy found**
   - Check JWT claim conditions
   - Verify claim names match exactly
   - Test with debug logging enabled

2. **Strategy selection not working**
   - Review strategy order in configuration
   - Verify condition operators and values
   - Check for overlapping conditions

3. **Transformation failures**
   - Ensure transformation is supported by provider
   - Verify input data format matches expectations
   - Check for null/empty values

4. **Connection failures**
   - Verify provider connection settings
   - Test connectivity from application server
   - Check authentication credentials

### Debug Mode
```yaml
# Enable detailed logging
logger:
  level: debug
  
# Test configuration
services:
  entityresolution:
    mode: multi-strategy
    # Add test strategies with simple conditions
```

## Examples

See [`example-config.yaml`](./example-config.yaml) for a comprehensive configuration example demonstrating:
- Multiple provider types (SQL, LDAP, Claims)
- Strategy-based routing patterns
- Data transformation usage
- Cross-backend failover scenarios
- Health check configuration

For implementation details and architecture decisions, see the [Multi-Strategy ERS ADR](../../../adr/decisions/2025-07-31-multi-strategy-entity-resolution-service.md).