# Configuration Guide

This guide provides details about the configuration setup for our application, including logger, services (specifically entitlements), and server configurations.

- [Logger Configuration](#logger-configuration)
- [Server Configuration](#server-configuration)
- [Database Configuration](#database-configuration)
- [OPA Configuration](#opa-configuration)
-[Services Configuration](#services-configuration)
  - [Entitlements](#entitlements)
    - [LDAP Provider](#ldap-provider)
    - [Keycloak Provider](#keycloak-provider)

## Logger Configuration

The logger configuration is used to define how the application logs its output.

- `level`: The logging level, set to `debug` for detailed logging information.
- `type`: The format of the log output, set to `text`.
- `output`: The output destination for logs, set to `stdout` to log to the standard output.

Example:

```yaml
logger:
  level: debug
  type: text
  output: stdout
```

## Server Configuration

The server configuration is used to define how the application runs its server.

- `grpc`: The configuration for the grpc server.
  - `port`: The port number for the grpc server.
  - `reflection`: Whether to enable reflection for the grpc server.
- `http`: The configuration for the http server.
  - `port`: The port number for the http server.

Example:

```yaml
server:
  grpc:
    port: 9001 
    reflection: true
  http:
    port: 8081
```

## Database Configuration

The database configuration is used to define how the application connects to its database.

- `host`: The host address for the database.
- `port`: The port number for the database.
- `user`: The username for the database.
- `password`: The password for the database.

Example:

```yaml
db:
  host: localhost
  port: 5432
  user: postgres
  password: changeme
```

## OPA Configuration

- `embedded`: Whether to use the embedded OPA Bundle server or not. This is only used for local development.
- `path`: The path to the OPA configuration file.

Example:

```yaml
opa:
  embedded: true # Only for local development
  path: ./opa/opa.yaml
```

## Services Configuration

### Entitlements

This section configures the entitlements providers.

- `providers`: A list of providers to use for entitlements.

Example:

```yaml
services:
  entitlements:
    providers:
    ...
```

#### LDAP Provider

- `type`: Specifies the type of provider, here it's ldap.
- `name`: A unique name for the provider.
- `ldap`: LDAP specific configuration.
  - `baseDN`: The base Distinguished Name for LDAP queries.
  - `host`: LDAP server host address.
  - `port`: Port number for LDAP server.
  - `bindUsername`: Username for binding to the LDAP server.
  - `bindPassword`: Password for binding, fetched from environment or k8s secret.
    - `fromEnv`: Fetches the secret from an environment variable.
    - `fromK8sSecret`: Fetches the secret from a k8s secret.
  - `attributeFilters`: Defines attributes to exclude in queries.
    - `exclude`: A list of attributes to exclude.
    - `include`: A list of attributes to include.

Example:

```yaml
services:
  entitlements:
    providers:
      - type: ldap
        name: ad-1
        ldap:  
          baseDN: "dc=dev,dc=virtruqa,dc=com"
          host: ""
          port: 389
          bindUsername: ""
          bindPassword:
            fromEnv: "LDAP_BIND_PASSWORD"
          attributeFilters:
            exclude:
              - "objectSid"
              - "objectGUID"
              - "msExchMailboxGuid"
              - "msExchMailboxSecurityDescriptor"
```

#### Keycloak Provider

- `type`: Specifies the type of provider, here it's keycloak.
- `name`: A unique name for the provider.
- `keycloak`: Keycloak specific configuration.
  - `host`: Keycloak server host address.
  - `realm`: Keycloak realm name.
  - `clientId`: Keycloak client id.
  - `clientSecret`: Keycloak client secret, fetched from environment or k8s secret.
    - `fromEnv`: Fetches the secret from an environment variable.
    - `fromK8sSecret`: Fetches the secret from a k8s secret.
  - `attributeFilters`: Defines attributes to exclude in queries.
    - `exclude`: A list of attributes to exclude.
    - `include`: A list of attributes to include.

Example:

```yaml
services:
  entitlements:
    providers:
      - type: keycloak
        name: keycloak-1
        keycloak:
          host: "https://keycloak.example.com/auth"
          realm: "example"
          clientId: "example"
          clientSecret:
            fromEnv: "KEYCLOAK_CLIENT_SECRET"
```
