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

- `level`: The logging level, set to `debug` for detailed logging information. `(default: info)`
- `type`: The format of the log output. Valid values are `json` or `text` `(default: json)`
- `output`: The output destination for logs. Only `stdout` is supported. `(default: stdout)`

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
  - `port`: The port number for the grpc server. `(default: 9000)`
  - `reflection`: Whether to enable reflection for the grpc server. `(default: true)`
- `http`: The configuration for the http server.
  - `enabled`: Whether to enable the http server. `(default: true)`
  - `port`: The port number for the http server. `(default: 8080)`
- `tls`: The configuration for the tls server.
  - `enabled`: Enable tls. `(default: false)`
  - `cert`: The path to the tls certificate.
  - `key`: The path to the tls key.
- `auth`: The configuration for your trusted IDP.
  - `enabled`: Enable authentication. `(default: true)`
  - `audience`: The audience for the IDP.
  - `issuer`: The issuer for the IDP.
  - `clients`: A list of client id's that are allowed

Example:

```yaml
server:
  grpc:
    port: 9001 
    reflection: true
  http:
    port: 8081
  tls:
    enabled: true
    cert: /path/to/cert
    key: /path/to/key
  auth:
    enabled: true
    audience: https://example.com
    issuer: https://example.com
    clients:
      - client_id
      - client_id2
```

## Database Configuration

The database configuration is used to define how the application connects to its database.

- `host`: The host address for the database. `(default: localhost)`
- `port`: The port number for the database. `(default: 5432)`
- `database`: The name of the database. `(default: opentdf)`
- `user`: The username for the database. `(default: postgres)`
- `password`: The password for the database. `(default: changeme)`
- `sslmode`: The ssl mode for the database `(default: prefer)`
- `schema`: The schema for the database. `(default: opentdf)`
- `runMigration`: Whether to run the database migration or not. `(default: true)`
Example:

```yaml
db:
  host: localhost
  port: 5432
  database: opentdf
  user: postgres
  password: changeme
  sslmode: require
  schema: opentdf
  runMigration: false
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