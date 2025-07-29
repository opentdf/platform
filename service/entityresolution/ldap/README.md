# LDAP Entity Resolution Service

The LDAP Entity Resolution Service provides entity resolution capabilities by connecting to LDAP/Active Directory servers. It supports the v1 protocol for both `ResolveEntities` and `CreateEntityChainFromJwt` methods.

> 📋 **For general ERS information and configuration patterns, see [`../README.md`](../README.md)**

## LDAP-Specific Features

- **Multi-server failover support**: Configure multiple LDAP servers for high availability
- **Secure connections**: LDAPS by default with TLS verification  
- **Flexible attribute mapping**: Map LDAP attributes to entity properties
- **Group membership queries**: Retrieve user group memberships
- **StartTLS support**: Upgrade plain connections to TLS
- **Active Directory integration**: Native support for AD schema and attributes

## Configuration

Configure the LDAP ERS by setting the mode to `ldap` in your service configuration:

```yaml
services:
  entityresolution:
    mode: ldap
    # LDAP connection settings
    servers:
      - ldap.example.com
      - ldap-backup.example.com
    port: 636
    use_tls: true
    insecure_tls: false
    start_tls: false
    
    # Authentication
    bind_dn: "cn=service-account,ou=systems,dc=example,dc=com"
    bind_password: "your-service-account-password"
    
    # Search settings
    base_dn: "dc=example,dc=com"
    user_filter: "(uid={username})"
    email_filter: "(mail={email})"
    client_id_filter: "(cn={client_id})"
    group_search_base: "ou=groups,dc=example,dc=com"
    group_filter: "(member={dn})"
    
    # Attribute mapping
    attribute_mapping:
      username: "uid"
      email: "mail"
      display_name: "displayName"
      groups: "memberOf"
      client_id: "cn"
      additional:
        - "department"
        - "employeeNumber"
    
    # Feature flags
    include_groups: true
    inferid:
      from:
        email: true
        username: true
        clientid: false
    
    # Timeouts
    connect_timeout: "10s"
    read_timeout: "30s"
```

## Configuration Options

### Connection Settings

- `servers`: List of LDAP server hostnames/IPs (required)
- `port`: LDAP port (default: 636 for LDAPS, 389 for LDAP)
- `use_tls`: Enable TLS/LDAPS (default: true)
- `insecure_tls`: Skip TLS certificate verification (default: false)
- `start_tls`: Use StartTLS for non-TLS connections (default: false)

### Authentication

- `bind_dn`: Distinguished name for binding to LDAP
- `bind_password`: Password for the bind DN

### Search Settings

- `base_dn`: Base DN for searches (required)
- `user_filter`: Filter for username searches (default: "(uid={username})")
- `email_filter`: Filter for email searches (default: "(mail={email})")  
- `client_id_filter`: Filter for client ID searches (default: "(cn={client_id})")
- `group_search_base`: Base DN for group searches
- `group_filter`: Filter for group membership searches (default: "(member={dn})")

### Attribute Mapping

Maps LDAP attributes to entity properties:

- `username`: LDAP attribute for username (default: "uid")
- `email`: LDAP attribute for email (default: "mail")
- `display_name`: LDAP attribute for display name (default: "displayName")
- `groups`: LDAP attribute for group membership (default: "memberOf")
- `client_id`: LDAP attribute for client ID (default: "cn")
- `additional`: List of additional LDAP attributes to include

### Feature Flags

- `include_groups`: Include group information in results (default: true)
- `inferid`: Configure entity inference when entities are not found
  - `from.email`: Infer email entities (default: false)
  - `from.username`: Infer username entities (default: false)
  - `from.clientid`: Infer client ID entities (default: false)

### Timeouts

- `connect_timeout`: Connection timeout (default: "10s")
- `read_timeout`: Read timeout (default: "30s")

## LDAP-Specific Usage

### LDAP Filter Customization

Configure LDAP search filters for different entity types:

```yaml
# Standard OpenLDAP filters
user_filter: "(uid={username})"
email_filter: "(mail={email})"

# Active Directory filters  
user_filter: "(sAMAccountName={username})"
email_filter: "(mail={email})"

# Custom filters with multiple attributes
user_filter: "(|(uid={username})(cn={username}))"
```

### Group Membership Queries

Configure group searches to include user group memberships:

```yaml
group_search_base: "ou=groups,dc=example,dc=com"
group_filter: "(member={dn})"        # Direct membership
# or
group_filter: "(memberUid={username})" # POSIX groups
```

## LDAP Security Considerations

### Connection Security
- **LDAPS (TLS)**: Enabled by default on port 636
- **StartTLS**: Upgrade plain LDAP connections to TLS
- **Certificate Validation**: Verify LDAP server certificates (disable only for testing)

### LDAP Injection Prevention
All user inputs are properly escaped in LDAP filters:
```yaml
# Safe - uses parameterized filters
user_filter: "(uid={username})"

# Unsafe - never construct filters manually
# filter := fmt.Sprintf("(uid=%s)", username) // DON'T DO THIS
```

### Service Account Security
- Use dedicated service accounts with minimal required permissions
- Regularly rotate service account passwords
- Monitor service account usage in LDAP server logs

## LDAP Troubleshooting

### Connection Issues
1. **Port accessibility**: Test with `telnet ldap.example.com 636`
2. **TLS certificate issues**: Check certificate validity and trust chain
3. **Bind DN permissions**: Ensure service account can read required attributes
4. **Base DN validation**: Verify base DN exists and is accessible

### LDAP Filter Issues
```bash
# Test filters manually with ldapsearch
ldapsearch -x -H ldaps://ldap.example.com:636 \
  -D "cn=service-account,ou=systems,dc=example,dc=com" \
  -W -b "dc=example,dc=com" \
  "(uid=alice)"
```

### Schema Compatibility
- **OpenLDAP**: Uses `uid`, `mail`, `cn`, `memberOf`
- **Active Directory**: Uses `sAMAccountName`, `mail`, `displayName`, `memberOf`
- **Custom schemas**: Adjust attribute mapping to match your directory

### Performance Optimization
- **Indexed attributes**: Ensure search attributes are indexed on LDAP server
- **Connection limits**: Monitor LDAP server connection limits
- **Search scope**: Use most specific base DN possible to reduce search scope

## Examples

### Active Directory Configuration

```yaml
services:
  entityresolution:
    mode: ldap
    servers:
      - ad.company.com
    port: 636
    use_tls: true
    bind_dn: "CN=svc-opentdf,OU=Service Accounts,DC=company,DC=com"
    bind_password: "service-password"
    base_dn: "DC=company,DC=com"
    user_filter: "(sAMAccountName={username})"
    email_filter: "(mail={email})"
    attribute_mapping:
      username: "sAMAccountName"
      email: "mail"
      display_name: "displayName"
      groups: "memberOf"
```

### OpenLDAP Configuration

```yaml
services:
  entityresolution:
    mode: ldap
    servers:
      - ldap.company.com
    port: 636
    use_tls: true
    bind_dn: "cn=opentdf,ou=services,dc=company,dc=com"
    bind_password: "service-password"
    base_dn: "dc=company,dc=com"
    user_filter: "(uid={username})"
    email_filter: "(mail={email})"
    attribute_mapping:
      username: "uid"
      email: "mail"  
      display_name: "cn"
      groups: "memberOf"
```