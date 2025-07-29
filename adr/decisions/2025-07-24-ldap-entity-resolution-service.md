---
status: 'proposed'
date: '2025-07-24'
tags:
 - entity-resolution
 - ldap
 - active-directory
 - authentication
 - configuration
driver: '@jrschumacher'
consulted:
  - '@elizabethhealy'
  - '@damorris25'
  - '@biscoe916'
---
# LDAP Entity Resolution Service Implementation

## Context and Problem Statement

Organizations need to integrate OpenTDF with LDAP-based identity systems including Active Directory, OpenLDAP, and other directory services to extract rich organizational context for authorization decisions. **LDAP ERS serves as the critical bridge between directory services and OpenTDF's authorization system**, transforming directory attributes into claims that drive SubjectMapping evaluation and fine-grained access control.

Current ERS implementations require either:

1. **Keycloak Integration**: Additional infrastructure and potential security concerns with admin APIs, often missing rich organizational context
2. **Custom ERS Development**: Significant development effort for each directory service

**The Key Insight**: LDAP directories contain authoritative organizational context (department, clearance level, project assignments, cost centers) that IdPs often don't expose. LDAP ERS extracts this rich context directly from the source of truth, enabling fine-grained authorization policies based on any organizational attribute.

## Decision Drivers

* **Authorization Integration**: Rich organizational attribute extraction that feeds directly into SubjectMapping evaluation via JSONPath selectors
* **Security**: LDAPS by default, read-only operations, minimal credential requirements
* **Organizational Context**: Access to authoritative directory attributes often unavailable in downstream IdPs
* **Flexibility**: Configuration-driven attribute mapping that supports any organizational schema needed for policy decisions
* **Performance**: Efficient searches with proper filtering and connection management
* **Maintainability**: Single implementation supporting multiple LDAP vendors (Active Directory, OpenLDAP, etc.)

## Considered Options

* **Option 1**: Basic LDAP ERS with fixed attribute mappings
* **Option 2**: Flexible LDAP ERS with configurable mappings and search strategies
* **Option 3**: Active Directory specific ERS with AD optimizations

## Decision Outcome

Chosen option: "**Option 2: Flexible LDAP ERS with configurable mappings**", because it provides maximum deployment flexibility while maintaining simplicity and security.

### Consequences

* 🟩 **Good**, because extracts rich organizational context that directly feeds SubjectMapping evaluation and authorization decisions
* 🟩 **Good**, because supports any organizational attribute schema through flexible configuration (department, clearance, projects, etc.)
* 🟩 **Good**, because eliminates need for IdP-specific integrations in many cases while providing richer context
* 🟩 **Good**, because provides secure, read-only access to authoritative identity sources
* 🟩 **Good**, because enables fine-grained authorization policies based on organizational structure and context
* 🟨 **Neutral**, because requires LDAP knowledge and understanding of JSONPath selectors for advanced configurations
* 🟥 **Bad**, because may not optimize for specific directory server features

## Implementation Specification

### Core Architecture

**Directory Structure**:
```
service/entityresolution/ldap/
├── ldap_entity_resolution.go       # Main ERS implementation
├── config.go                      # Configuration structures
├── connection.go                  # LDAP connection management
├── mapper.go                      # Entity mapping logic
├── search.go                      # LDAP search operations
└── v2/ldap_entity_resolution.go   # V2 API implementation
```

**Dependencies**:
- `go-ldap/ldap/v3`: Mature LDAP client library with TLS support
- Standard OpenTDF ERS interfaces and service registration

### Configuration Schema

```yaml
services:
  entityresolution:
    mode: "ldap"
    connection:
      # Multiple servers for failover
      servers: 
        - "ldaps://primary.ad.corp:636"
        - "ldaps://backup.ad.corp:636"
      
      # Authentication
      auth_method: "simple"  # simple, anonymous
      bind_dn: "cn=svc-opentdf,ou=service-accounts,dc=corp,dc=com"
      bind_password: "secret"
      
      # TLS Configuration
      tls_verify: true
      tls_ca_file: "/path/to/ca.pem"        # Optional
      tls_cert_file: "/path/to/client.pem"  # Optional for mTLS
      tls_key_file: "/path/to/client.key"   # Optional for mTLS
      
      # Connection Management
      timeout: "30s"
      connection_pool_size: 10
      
    search:
      # Multiple base DNs for comprehensive search
      base_dns:
        - "ou=users,dc=corp,dc=com"
        - "ou=service-accounts,dc=corp,dc=com"
        - "ou=external-users,dc=corp,dc=com"
      
      # Search scope: base, onelevel, subtree
      scope: "subtree"
      
      # Size and time limits
      size_limit: 1000
      time_limit: "60s"
      
    # Single search strategy - simple and predictable
    search:
      base_dn: "ou=users,dc=corp,dc=com"  # Single authoritative source
      scope: "subtree"
      # Find users by email (most common lookup pattern)
      filter: "(&(objectClass=person)(mail={value}))"
      
    # Rich organizational attribute extraction and mapping for authorization
    attribute_mappings:
      - ldap: "mail"
        attr: "email"
      - ldap: "sAMAccountName"
        attr: "username"
      - ldap: "displayName"
        attr: "display_name"
      - ldap: "department"
        attr: "department"           # → .department selector in SubjectMappings
      - ldap: "title"
        attr: "title"                # → .title selector
      - ldap: "memberOf"
        attr: "groups"              # → .groups[] selector (after processing)
      - ldap: "clearanceLevel"
        attr: "security_clearance"  # → .security_clearance selector
      - ldap: "projectCodes"
        attr: "authorized_projects" # → .authorized_projects[] selector  
      - ldap: "costCenter"
        attr: "cost_center"         # → .cost_center selector
      - ldap: "managerDN"
        attr: "manager"             # → .manager selector (after DN resolution)
      - ldap: "employeeType"
        attr: "employee_type"       # → .employee_type selector
      - ldap: "telephoneNumber"
        attr: "phone"               # → .phone selector
        
    # Group membership processing (optional enhancement)
    groups:
      enabled: true
      expand_nested: true
      max_depth: 10
        
    # Health check configuration
    health_check:
      enabled: true
      interval: "60s"
      bind_test: true
```

### Core Implementation

**Service Interface Implementation**:
```go
type LDAPEntityResolutionService struct {
    entityresolution.UnimplementedEntityResolutionServiceServer
    config LDAPConfig
    logger *logger.Logger
    connPool *ldap.ConnPool  // Future: connection pooling
    trace.Tracer
}

func (s *LDAPEntityResolutionService) ResolveEntities(
    ctx context.Context, 
    req *connect.Request[entityresolution.ResolveEntitiesRequest],
) (*connect.Response[entityresolution.ResolveEntitiesResponse], error) {
    // Implementation details below
}
```

**Simplified Entity Resolution Flow**:
1. **JWT Claim Extraction**: Extract configured claim value from JWT token
2. **LDAP Connection**: Establish secure connection with failover support  
3. **Single Search Execution**: Execute single configured LDAP filter with claim value
4. **Attribute Mapping**: Map LDAP attributes to consistent claim names for authorization
5. **Group Processing**: Optionally expand and flatten group memberships
6. **Response Construction**: Build EntityRepresentation with mapped attributes

**Search Implementation**:
```go
type LDAPConfig struct {
    Search struct {
        BaseDN string `mapstructure:"base_dn"`
        Filter string `mapstructure:"filter"`  // Single search filter
        Scope  string `mapstructure:"scope"`
    } `mapstructure:"search"`
    AttributeMappings []AttributeMapping `mapstructure:"attribute_mappings"`
}

type AttributeMapping struct {
    LDAP string `mapstructure:"ldap"`  // LDAP attribute name
    Attr string `mapstructure:"attr"`  // Claim name for authorization
}

func (s *LDAPEntityResolutionService) searchEntity(
    conn *ldap.Conn,
    mapping EntityMapping,
    entityValue string,
) ([]*ldap.Entry, error) {
    // Construct search filter with value substitution
    filter := strings.ReplaceAll(mapping.SearchFilter, "{value}", ldap.EscapeFilter(entityValue))
    
    // Execute search across all configured base DNs
    var allEntries []*ldap.Entry
    for _, baseDN := range s.config.Search.BaseDNs {
        searchReq := ldap.NewSearchRequest(
            baseDN,
            ldap.ScopeWholeSubtree,
            ldap.NeverDerefAliases,
            s.config.Search.SizeLimit,
            int(s.config.Search.TimeLimit.Seconds()),
            false,
            filter,
            s.config.Output.Attributes,
            nil,
        )
        
        result, err := conn.Search(searchReq)
        if err != nil {
            s.logger.Error("LDAP search failed", "base_dn", baseDN, "error", err)
            continue
        }
        allEntries = append(allEntries, result.Entries...)
    }
    
    return allEntries, nil
}
```

### Security Features

**Connection Security**:
- LDAPS (LDAP over TLS) by default on port 636
- TLS certificate verification enabled by default
- Support for custom CA certificates
- Optional mutual TLS (mTLS) for enhanced security

**Authentication Methods**:
- **Simple Bind**: Username/password authentication
- **Anonymous Bind**: For publicly readable directories
- **Future**: SASL authentication mechanisms

**Input Validation**:
- LDAP injection prevention through proper escaping
- Input sanitization for search filters
- Configuration validation on startup

### Error Handling and Resilience

**Connection Management**:
- Multi-server failover support
- Connection timeout and retry logic
- Health check integration
- Graceful degradation on partial failures

**Search Error Handling**:
- Continue search on individual base DN failures
- Log detailed error information for troubleshooting
- Return partial results when possible
- Proper error codes for different failure scenarios

### Performance Considerations

**Search Optimization**:
- Indexed attribute searches (mail, sAMAccountName)
- Appropriate search scope limitation
- Size and time limits to prevent resource exhaustion
- Future: Connection pooling for high-throughput scenarios

**Group Expansion**:
- Configurable nested group depth limits
- Efficient memberOf attribute processing
- Optional group expansion to balance performance vs completeness

### Testing Strategy

**Unit Tests**:
- Configuration parsing and validation
- LDAP filter construction and escaping
- Attribute mapping logic
- Error handling scenarios

**Integration Tests**:
- Test with OpenLDAP test containers
- Active Directory integration tests
- Multi-server failover testing
- TLS configuration validation

**Performance Tests**:
- Load testing with concurrent requests
- Large directory performance benchmarks
- Memory usage analysis

## Validation

Implementation success will be measured by:
- Successfully resolving entities from OpenLDAP and Active Directory with rich organizational attributes
- Single entity type per ERS providing predictable, consistent output schemas
- End-to-end authorization flow validation: LDAP attributes → flattening → SubjectMapping evaluation → access decisions
- Security audit confirming secure connection handling and proper attribute extraction
- Performance benchmarks meeting production requirements with attribute-heavy queries
- Integration test coverage > 80%

## Multi-Instance Deployment Pattern

**Single Entity Type Per ERS**: Each LDAP ERS instance handles one entity type for predictable results and clear authorization context.

### User ERS Configuration
```yaml
# Primary user ERS - handles human users by email lookup
services:
  entityresolution_users:
    mode: "ldap"
    connection:
      servers: ["ldaps://primary.ad.corp:636", "ldaps://backup.ad.corp:636"]
      auth_method: "simple"
      bind_dn: "cn=svc-opentdf,ou=service-accounts,dc=corp,dc=com"
      bind_password: "secret"
    search:
      base_dn: "ou=users,dc=corp,dc=com"
      filter: "(&(objectClass=person)(mail={value}))"
    attribute_mappings:
      - ldap: "department"
        attr: "department" 
      - ldap: "clearanceLevel"
        attr: "security_clearance"
      - ldap: "memberOf"
        attr: "groups"
```

### Service Account ERS Configuration  
```yaml
# Service account ERS - handles service principals
services:
  entityresolution_services:
    mode: "ldap"
    connection:
      servers: ["ldaps://primary.ad.corp:636"]
      auth_method: "simple"
      bind_dn: "cn=svc-opentdf,ou=service-accounts,dc=corp,dc=com"
      bind_password: "secret"
    search:
      base_dn: "ou=computers,dc=corp,dc=com"
      filter: "(&(objectClass=computer)(servicePrincipalName=*{value}*))"
    attribute_mappings:
      - ldap: "operatingSystem"
        attr: "os_type"
      - ldap: "location"
        attr: "deployment_zone"
      - ldap: "servicePrincipalName"
        attr: "service_name"
```

**Benefits**:
- ✅ **Predictable Output**: Each ERS has consistent, known attribute schema
- ✅ **Authorization Clarity**: SubjectMappings know exactly what selectors are available
- ✅ **Simple Configuration**: No complex routing or entity type detection within ERS
- ✅ **Deployment Flexibility**: Different entity types can use different LDAP servers, credentials, or search strategies

## Authorization Integration Flow

The complete flow demonstrating how LDAP attributes become authorization decisions:

### Example Scenario
**User**: `alice@corp.com` requests access to a classified document  
**LDAP Entry**:
```ldap
dn: cn=alice,ou=users,dc=corp,dc=com
mail: alice@corp.com
sAMAccountName: alice
department: Engineering
clearanceLevel: Secret
memberOf: cn=developers,ou=groups,dc=corp,dc=com
memberOf: cn=team-leads,ou=groups,dc=corp,dc=com
projectCodes: proj-alpha,proj-beta
costCenter: CC-1001
```

### Integration Steps

1. **ERS Resolution**: LDAP ERS extracts and maps attributes
   ```json
   {
     "email": "alice@corp.com",
     "department": "Engineering",
     "security_clearance": "Secret", 
     "groups": ["developers", "team-leads"],
     "authorized_projects": ["proj-alpha", "proj-beta"],
     "cost_center": "CC-1001"
   }
   ```

2. **Attribute Flattening**: Converts to JSONPath selectors for SubjectMapping evaluation
   ```
   .email → "alice@corp.com"
   .department → "Engineering"
   .security_clearance → "Secret" 
   .groups[] → "developers", "team-leads"
   .authorized_projects[] → "proj-alpha", "proj-beta"
   .cost_center → "CC-1001"
   ```

3. **SubjectMapping Evaluation**: Policy conditions match against flattened attributes
   ```yaml
   # Classified document access policy
   conditions:
     - subject_external_selector_value: ".department"
       operator: "IN"
       subject_external_values: ["Engineering", "Research"]
     - subject_external_selector_value: ".security_clearance"
       operator: "IN" 
       subject_external_values: ["Secret", "TopSecret"]
     - subject_external_selector_value: ".authorized_projects[]"
       operator: "IN"
       subject_external_values: ["proj-alpha"]
   ```

4. **Access Decision**: All conditions match → **PERMIT** access to classified document

This demonstrates how LDAP organizational context directly drives fine-grained authorization decisions through the OpenTDF policy system.

## More Information

**Active Directory Specific Considerations**:
- Support for Global Catalog searches (port 3268/3269) for forest-wide queries
- Proper handling of AD-specific attributes (objectGUID, objectSid, userAccountControl)
- Forest and domain trust considerations for multi-domain environments
- Schema extensions for custom organizational attributes (clearanceLevel, projectCodes)

**Authorization Policy Examples**:
```yaml
# Department-based access
conditions:
  - subject_external_selector_value: ".department"
    operator: "IN"
    subject_external_values: ["Finance", "Accounting"]

# Project-based access with security clearance
conditions:
  - subject_external_selector_value: ".authorized_projects[]"
    operator: "IN"
    subject_external_values: ["proj-classified-alpha"]
  - subject_external_selector_value: ".security_clearance"
    operator: "IN"
    subject_external_values: ["TopSecret"]

# Role and group-based access
conditions:
  - subject_external_selector_value: ".groups[]"
    operator: "IN"
    subject_external_values: ["executives", "board-members"]
```

**Future Enhancements**:
- Connection pooling for improved performance under load
- Attribute caching with configurable TTL for frequently accessed entities
- Metrics and monitoring integration for ERS performance and authorization latency
- Support for SASL authentication mechanisms (Kerberos, DIGEST-MD5)
- Advanced group filtering and DN resolution for manager hierarchies
- Configuration templates for common organizational schemas

This implementation provides a robust, secure, and flexible foundation for extracting rich organizational context from LDAP directories and seamlessly integrating it with OpenTDF's fine-grained authorization system.