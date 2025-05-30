# OpenTDF Platform Authorization Documentation

## Introduction

The OpenTDF Platform uses a sophisticated authorization mechanism to control access to various endpoints and resources. This document explains how the authorization system works, how to configure it, and how to leverage advanced features such as UserInfo enrichment and DPoP token security.

## Authorization System Overview

The OpenTDF Platform uses [Casbin](https://casbin.org/) as its authorization engine. Casbin provides a flexible and powerful policy-based access control system that allows fine-grained control over who can access what resources.

The authorization layer consists of two main components:

1. **Authentication (AuthN)**: Verifies that users are who they claim to be through tokens
2. **Authorization (AuthZ)**: Determines what authenticated users are allowed to do

The Casbin enforcer acts as a gatekeeper for API routes, evaluating permissions based on:
- The user's role or identity (extracted from tokens and/or UserInfo)
- The resource being accessed
- The action being performed (read, write, delete, etc.)

### Scope of Authorization

The platform's authorization layer specifically controls access to platform endpoints and resources. It does not manage Key Access Server (KAS) access control directly. The authorization system determines if a user can interact with specific routes, but KAS has its own mechanisms for controlling access to protected data.

## UserInfo Enrichment

### What is UserInfo Enrichment?

UserInfo enrichment allows the platform to use strictly compliant access tokens that don't contain subject attribute claims by retrieving additional user information from the identity provider.

This feature is particularly useful in scenarios where:
- The access tokens are kept minimal for security reasons
- Subject attributes are stored separately from access tokens
- Compliance with specific standards is required

### How UserInfo Enrichment Works

When enabled, the platform will:

1. Receive a client's access token
2. Extract the token's issuer and subject
3. Exchange the token for UserInfo from the identity provider
4. Cache the UserInfo to avoid repeated calls
5. Use the combined information from both the token and UserInfo for authorization decisions

### Benefits of UserInfo Enrichment

- **Improved Security**: Allows for smaller, more focused access tokens
- **Better Compliance**: Supports strictly compliant access tokens that follow the principle of least privilege
- **Enhanced Authorization**: Makes richer user context available for authorization decisions

## DPoP (Demonstrating Proof of Possession)

### What is DPoP?

DPoP is a security mechanism that provides proof that the client possesses a particular key pair associated with a token. It prevents token theft and replay attacks by binding tokens to specific key pairs.

### How DPoP Works in OpenTDF Platform

When DPoP is enabled:

1. The client generates a key pair and includes the public key in the token request
2. The identity provider includes a confirmation (`cnf`) claim in the token that references the public key
3. For each API call, the client creates a signed DPoP proof JWT that includes:
   - The HTTP method (`htm`)
   - The target URI (`htu`)
   - A hash of the access token (`ath`)
   - A timestamp (`iat`)
4. The server validates this proof before processing the request

### Benefits of DPoP

- **Enhanced Security**: Prevents token theft and replay attacks
- **Better Token Binding**: Cryptographically binds tokens to specific clients
- **Improved Authentication Assurance**: Provides stronger guarantees that the token holder is legitimate

## Authorization Configuration

### Casbin Policy Structure

The platform uses a Role-Based Access Control (RBAC) model with Casbin. The policy consists of:

- **Role definitions**: Define roles like `admin`, `standard`, and `unknown`
- **Policy rules**: Specify what actions each role can perform on which resources
- **Matchers**: Define how policy rules are matched against requests

The default Casbin model configuration is:

```properties
[request_definition]
r = sub, res, act

[policy_definition]
p = sub, res, act, eft

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = g(r.sub, p.sub) && keyMatch(r.res, p.res) && keyMatch(r.act, p.act)
```

### Policy Rules Format

Policy rules in OpenTDF Platform follow this format:

```
p, <subject>, <resource>, <action>, <effect>
```

Where:
- `<subject>`: The role or user (e.g., `role:admin`, `role:standard`)
- `<resource>`: The resource being accessed (e.g., `policy.*`, `/attributes*`)
- `<action>`: The action being performed (e.g., `read`, `write`, `*`)
- `<effect>`: The effect of the rule (`allow` or `deny`)

Role assignments use this format:

```
g, <user/group>, <role>
```

For example:
- `g, opentdf-admin, role:admin`
- `g, alice@example.com, role:standard`

### Configuration Options

The authorization system can be configured through the following options:

| Option | Description | Default |
|--------|-------------|---------|
| `auth.enabled` | Enable/disable authentication and authorization | `true` |
| `auth.enforceDPoP` | Enforce DPoP token validation | `false` |
| `auth.enrichUserInfo` | Enable UserInfo enrichment | `false` |
| `auth.policy.username_claim` | Claim to extract username from token | `preferred_username` |
| `auth.policy.groups_claim` | Claims to extract group/role info (supports multiple) | `realm_access.roles` |
| `auth.policy.extension` | Additional policy rules to extend the default policy | |
| `auth.policy.csv` | Custom policy to replace the default policy | |
| `auth.policy.model` | Custom Casbin model | |

Example configuration in YAML:

```yaml
server:
  auth:
    enabled: true
    enforceDPoP: true
    enrichUserInfo: true
    audience: "http://localhost:8080"
    issuer: "http://keycloak:8888/auth/realms/opentdf"
    client_id: "opentdf-platform"     # Used for token exchange
    client_secret: "your-secret-here"  # Used for token exchange
    policy:
      username_claim: "email"
      groups_claim:
        - "realm_access.roles"
        - "groups"
      extension: |
        p, role:standard, custom.service.DoSomething, read, allow
        g, opentdf-admin, role:admin
        g, opentdf-standard, role:standard
        g, alice@example.com, role:admin
```

### Overriding Default Policy

You can replace the default policy by providing a custom policy in the `csv` field:

```yaml
server:
  auth:
    policy:
      csv: |
        p, role:admin, *, *, allow
        p, role:standard, policy:attributes, read, allow
        p, role:standard, policy:subject-mappings, read, allow
        g, opentdf-admin, role:admin
        g, opentdf-standard, role:standard
```

### Extending Default Policy

If you want to keep the default policy but add additional rules, use the `extension` field:

```yaml
server:
  auth:
    policy:
      extension: |
        p, role:standard, custom.service.*, read, allow
        g, marketing-group, role:standard
```

## Keycloak Integration

Keycloak is a recommended identity provider for OpenTDF Platform. This section describes how to configure Keycloak to work with the platform's authorization features.

### Configuring the Platform Client ID

As mentioned in the implementation notes, you'll need to create a dedicated client for the platform:

1. Create a new client in Keycloak with the ID `opentdf-platform`
2. Configure it to support **Direct Access Grants** (Client Authentication ON)
3. Set up appropriate permissions to ensure it's not overprivileged
4. Configure the client mappers to ensure that group claims are included in the token and UserInfo:
   - Add a mapper for `realm_access.roles` to the ID token and UserInfo
   - Add any other needed user attributes

```yaml
# Platform client configuration in opentdf.yaml
server:
  auth:
    client_id: "opentdf-platform"
    client_secret: "your-client-secret"
    enrichUserInfo: true
```

### Configuring the Public Client ID

For the public-facing client that end-user applications will use:

1. Create or update the client with the ID `opentdf-public`
2. Enable **Front Channel Logout** for proper session management
3. Add an **Audience Mapper** to include the Platform Client ID as an audience:
   - Create a new mapper of type "Audience"
   - Set the "Included Client Audience" to `opentdf-platform`
   - Set "Add to ID token" to ON

```yaml
# Reference to public client in opentdf.yaml
server:
  auth:
    public_client_id: "opentdf-public"
```

### Quick Start: Enabling UserInfo Enrichment with Keycloak

To enable UserInfo enrichment:

1. Ensure your Keycloak realm has appropriate user attributes and roles defined
2. Configure your Platform Client ID with the necessary mappers
3. Enable UserInfo enrichment in the OpenTDF Platform configuration:

```yaml
server:
  auth:
    enrichUserInfo: true
    client_id: "opentdf-platform"     # Required for token exchange
    client_secret: "your-secret-here" # Required for token exchange
    policy:
      groups_claim:
        - "realm_access.roles"        # Claims to extract from token and UserInfo
        - "groups"                    # Optional additional claim paths
```

4. Make sure the UserInfo endpoint in Keycloak is properly configured and accessible

## Advanced Authorization Features

### Role Mapping

You can map external roles to OpenTDF roles using the Casbin grouping syntax:

```
g, external-role-name, role:admin
g, another-external-role, role:standard
g, user@example.com, role:admin
```

This allows you to integrate with existing role structures in your identity provider.

### Multiple Group Claims

The platform supports extracting roles from multiple claim paths in both tokens and UserInfo:

```yaml
policy:
  groups_claim:
    - "realm_access.roles"
    - "resource_access.my-client.roles"
    - "groups"
```

This provides flexibility when working with different identity providers and token structures.

## Conclusion

The OpenTDF Platform's authorization system provides robust, flexible security controls that can be tailored to your organization's needs. By leveraging UserInfo enrichment and DPoP, you can enhance security while maintaining compatibility with modern identity standards.

For more details on Casbin policies, refer to the [Casbin documentation](https://casbin.org/docs/overview). For Keycloak configuration, see the [Keycloak documentation](https://www.keycloak.org/documentation).
