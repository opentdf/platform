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
  - `enabled`: Whether to enable the http server. (default: true)
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
- `sslmode`: The ssl mode for the database (default: prefer).
Example:

```yaml
db:
  host: localhost
  port: 5432
  user: postgres
  password: changeme
  sslmode: require
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
