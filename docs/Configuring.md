# Platform Configuration

This guide provides details about the configuration setup for the platform, including the logger, services , and server configurations.

The platform leverages [viper](https://github.com/spf13/viper) to help load configuration.

- [Platform Configuration](#platform-configuration)
  - [Logger Configuration](#logger-configuration)
  - [Server Configuration](#server-configuration)
  - [Database Configuration](#database-configuration)
  - [Services Configuration](#services-configuration)
    - [Key Access Server (KAS)](#key-access-server-kas)
    - [Authorization](#authorization)

## Deployment Mode

The platform is designed as a modular monolith, meaning that all services are built into and run from the same binary. However, these services can be grouped and run together based on specific needs. The available service groups are:

- all: Runs every service that is registered within the platform.
- core: Runs essential services, including policy, authorization, and wellknown services.
- kas: Runs the Key Access Server (KAS) service.



| Field    | Description  | Default  | Environment Variable |
| -------- | -------------| -------- | -------------------- |
| `mode`   | Drives which services to run. Following modes are supported. (all, core, kas) | `all` | OPENTDF_MODE |

## SDK Configuration

The sdk configuration is used when operating the service in mode `kas`. When running in mode `core` or `all` an in-process communication is leveraged over an in-memory grpc server.

Root level key `sdk_config`

| Field    | Description  | Default  | Environment Variable |
| -------- | -------------| -------- | -------------------- |
| `core.endpoint` | The core platform endpoint to connect to |  | OPENTDF_SDK_CONFIG_ENDPOINT |
| `core.plaintext` | Use a plaintext grpc connection | `false` | OPENTDF_SDK_CONFIG_PLAINTEXT |
| `core.insecure` | Use an insecure tls connection | `false` |  |
| `entityresolution.endpoint` | The entityresolution endpoint to connect to |  |  |
| `entityresolution.plaintext` | Use a plaintext ERS grpc connection | `false` |  |
| `entityresolution.insecure` | Use an insecure tls connection | `false` |  |
| `client_id` | OAuth client id |  | OPENTDF_SDK_CONFIG_CLIENT_ID |
| `client_secret` |  The clients credentials | | OPENTDF_SDK_CONFIG_CLIENT_SECRET |

## Logger Configuration

The logger configuration is used to define how the application logs its output.

Root level key `logger`

| Field    | Description                      | Default  | Environment Variable |
| -------- | -------------------------------- | -------- | -------------------- |
| `level`  | The logging level.               | `info`   | OPENTDF_LOGGER_LEVEL  |
| `type`   | The format of the log output.    | `json`   | OPENTDF_LOGGER_TYPE   |
| `output` | The output destination for logs. | `stdout` | OPENTDF_LOGGER_OUTPUT |

Example:

```yaml
logger:
  level: debug
  type: text
  output: stdout
```

## Server Configuration

The server configuration is used to define how the application runs its server.

Root level key `server`

| Field                   | Description                                                                                                   | Default | Environment Variable                 |
|-------------------------|---------------------------------------------------------------------------------------------------------------|---------|--------------------------------------|
| `auth.audience`         | The audience for the IDP.                                                                                     |         | OPENTDF_SERVER_AUTH_AUDIENCE         |
| `auth.issuer`           | The issuer for the IDP.                                                                                       |         | OPENTDF_SERVER_AUTH_ISSUER           |
| `auth.policy`           | The Casbin policy for enforcing authorization on endpoints. Described [below](#casbin-endpoint-authorization) |         |                                      |
| `auth.cache_refresh`    | Interval in which the IDP jwks should be refreshed                                                            | `15m`   | OPENTDF_SERVER_AUTH_CACHE_REFRESH    |
| `auth.dpopskew`         | The amount of time drift allowed between when the client generated a dpop proof and the server time.          | `1h`    | OPENTDF_SERVER_AUTH                  |
| `auth.skew`             | The amount of time drift allowed between a tokens `exp` claim and the server time.                            | `1m`    | OPENTDF_SERVER_AUTH_SKEW             |
| `auth.public_client_id` | The oidc client id. This is leveraged by otdfctl.                                                             |         | OPENTDF_SERVER_AUTH_PUBLIC_CLIENT_ID |
| `auth.enforceDPoP`      | If true, DPoP bindings on Access Tokens are enforced.                                                         | `false` | OPENTDF_SERVER_AUTH_ENFORCEDPOP      |
| `cryptoProvider`        | A list of public/private keypairs and their use. Described [below](#crypto-provider)                          | empty   |                                      |
| `enable_pprof`          | Enable golang performance profiling                                                                           | `false` | OPENTDF_SERVER_ENABLE_PPROF          |
| `grpc.reflection`       | The configuration for the grpc server.                                                                        | `true`  | OPENTDF_SERVER_GRPC_REFLECTION       |
| `host`                  | The host address for the server.                                                                              | `""`    | OPENTDF_SERVER_HOST                  |
| `port`                  | The port number for the server.                                                                               | `9000`  | OPENTDF_SERVER_PORT                  |
| `tls.enabled`           | Enable tls.                                                                                                   | `false` | OPENTDF_SERVER_TLS_ENABLED           |
| `tls.cert`              | The path to the tls certificate.                                                                              |         | OPENTDF_SERVER_TLS_CERT              |
| `tls.key`               | The path to the tls key.                                                                                      |         | OPENTDF_SERVER_TLS_KEY               |

Example:

```yaml
server:
  grpc:
    reflection: true
  port: 8081
  tls:
    enabled: true
    cert: /path/to/cert
    key: /path/to/key
  auth:
    enabled: true
    audience: https://example.com
    issuer: https://example.com
  cryptoProvider:
    standard:
      keys:
        - kid: r1
          alg: rsa:2048
          private: kas-private.pem
          cert: kas-cert.pem
        - kid: e1
          alg: ec:secp256r1
          private: kas-ec-private.pem
          cert: kas-ec-cert.pem
```

### Crypto Provider

To configure the Key Access Server,
you must define a set of one or more public keypairs
and a method for loading and using them.

The crypto provider is implemented as an interface,
allowing multiple implementations.

Root level key `cryptoProvider`

Environment Variable: `OPENTDF_SERVER_CRYPTOPROVIDER_STANDARD='[{"alg":"rsa:2048","kid":"k1","private":"kas-private.pem","cert":"kas-cert.pem"}]'`

| Field                               | Description                                                               | Default    |
| ----------------------------------- | ------------------------------------------------------------------------- | ---------- |
| `cryptoProvider.type`               | The type of crypto provider to use.                                       | `standard` |
| `cryptoProvider.standard.*.alg`     | An enum for the associated crypto type. E.g. `rsa:2048` or `ec:secp256r1` |            |
| `cryptoProvider.standard.*.kid`     | A short, globally unique, stable identifier for this keypair.             |            |
| `cryptoProvider.standard.*.private` | Path to the private key as a PEM file.                                    |            |
| `cryptoProvider.standard.*.cert`    | (Optional) Path to a public cert for the keypair.                         |            |

## Database Configuration

The database configuration is used to define how the application connects to its database.

Root level key `db`

| Field                                  | Description                                      | Default     | Environment Variables                           |
| -------------------------------------- | ------------------------------------------------ | ----------- | ----------------------------------              |
| `host`                                 | The host address for the database.               | `localhost` | OPENTDF_DB_HOST                                 |
| `port`                                 | The port number for the database.                | `5432`      | OPENTDF_DB_PORT                                 |
| `database`                             | The name of the database.                        | `opentdf`   | OPENTDF_DB_DATABASE                             |
| `user`                                 | The username for the database.                   | `postgres`  | OPENTDF_DB_USER                                 |
| `password`                             | The password for the database.                   | `changeme`  | OPENTDF_DB_PASSWORD                             |
| `sslmode`                              | The ssl mode for the database                    | `prefer`    | OPENTDF_DB_SSLMODE                              |
| `schema`                               | The schema for the database.                     | `opentdf`   | OPENTDF_DB_SCHEMA                               |
| `runMigration`                         | Whether to run the database migration or not.    | `true`      | OPENTDF_DB_RUNMIGRATION                         |
| `connect_timeout_seconds`              | Connection timeout duration (seconds).           | `15`         | OPENTDF_DB_CONNECT_TIMEOUT_SECONDS              |
| `pool`                                 | Pool configuration settings.                     |             |                                                 |
| `pool.max_connection_count`            | Maximum number of connections per pool.          | `4`         | OPENTDF_DB_POOL_MAX_CONNECTION_COUNT            |
| `pool.min_connection_count`            | Minimum number of connections per pool.          | `0`         | OPENTDF_DB_POOL_MIN_CONNECTION_COUNT            |
| `pool.max_connection_lifetime_seconds` | Maximum seconds per connection lifetime.         | `3600`      | OPENTDF_DB_POOL_MAX_CONNECTION_LIFETIME_SECONDS |
| `pool.min_idle_connections_count`      | Minimum number of idle connections per pool.     | `0`         | OPENTDF_DB_POOL_MIN_IDLE_CONNECTIONS_COUNT      |
| `pool.max_connection_idle_seconds`     | Maximum seconds allowed for idle connection.     | `1800`      | OPENTDF_DB_POOL_MAX_CONNECTION_IDLE_SECONDS     |
| `pool.health_check_period_seconds`     | Interval seconds per health check.               | `60`        | OPENTDF_DB_POOL_HEALTH_CHECK_PERIOD_SECONDS     |




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
  connect_timeout_seconds: 15
  pool:
    max_connection_count: 4
    min_connection_count: 0
    max_connection_lifetime_seconds: 3600
    min_idle_connections_count: 0
    max_connection_idle_seconds: 1800
    health_check_period_seconds: 60
```

### Tracing Configuration

| Field | Description | Default | Environment Variable |
| ----- | ----------- | ------- | ------------------- |
| `trace.enabled` | Enable distributed tracing | `false` | OPENTDF_SERVER_TRACE_ENABLED |
| `trace.provider.name` | Tracing provider (file or otlp) | `otlp` | OPENTDF_SERVER_TRACE_PROVIDER_NAME |

For file provider:
- `trace.provider.file.path`: Path to trace file output
- `trace.provider.file.prettyPrint`: Enable pretty-printed JSON
- `trace.provider.file.maxSize`: Maximum file size in MB
- `trace.provider.file.maxBackups`: Maximum number of backup files
- `trace.provider.file.maxAge`: Maximum age of files in days
- `trace.provider.file.compress`: Enable compression of trace files

For OTLP provider:
- `trace.provider.otlp.protocol`: Protocol to use (grpc or http/protobuf)
- `trace.provider.otlp.endpoint`: Endpoint URL for the collector
- `trace.provider.otlp.insecure`: Whether to use an insecure connection
- `trace.provider.otlp.headers`: Headers to include in OTLP requests

## Services Configuration

Root level key `services`

### Key Access Server (KAS)

Root level key `kas`

Environment Variable: `OPENTDF_SERVICES_KAS_KEYRING='[{"kid":"k1","alg":"rsa:2048"},{"kid":"k2","alg":"ec:secp256r1"}]'`

| Field              | Description                                                                     | Default  |
| ------------------ | ------------------------------------------------------------------------------- | -------- |
| `keyring.*.kid`    | Which key id this is binding                                                    |          |
| `keyring.*.alg`    | (Optional) Associated algorithm. (Allows reusing KID with different algorithms) |          |
| `keyring.*.legacy` | Indicates this may be used for TDFs with no key ID; default if all unspecified. | inferred |

Example:

```yaml
services:
  kas:
    enabled: true
    keyring:
      - kid: e2
        alg: ec:secp256r1
      - kid: e1
        alg: ec:secp256r1
        legacy: true
      - kid: r2f
        alg: rsa:2048
      - kid: r1
        alg: rsa:2048
        legacy: true
```

### Authorization

Root level key `authorization`

| Field     | Description              | Default | Environment Variables |
| --------- | ------------------------ | ------- | --------------------- |
| `rego.path` | Path to rego policy file | Leverages embedded rego policy | OPENTDF_SERVICES_AUTHORIZATION_REGO_PATH |
| `rego.query` | Rego query to execute in policy | `data.opentdf.entitlements.attributes` | OPENTDF_SERVICES_AUTHORIZATION_REGO_QUERY |

Example:

```yaml
services:
  authorization:
    rego:
      path: /path/to/policy.rego
      query: data.opentdf.entitlements.attributes
```

### Policy

Root level key `policy`

| Field                        | Description                                            | Default | Environment Variables                              |
| ---------------------------- | ------------------------------------------------------ | ------- | -------------------------------------------------- |
| `list_request_limit_default` | Policy List request limit default when not provided    | 1000    | OPENTDF_SERVICES_POLICY_LIST_REQUEST_LIMIT_DEFAULT |
| `list_request_limit_max`     | Policy List request limit maximum enforced by services | 2500    | OPENTDF_SERVICES_POLICY_LIST_REQUEST_LIMIT_MAX     |

Example:

```yaml
services:
  policy:
    list_request_limit_default: 1000
    list_request_limit_max: 2500
```

### Casbin Endpoint Authorization

OpenTDF uses Casbin to manage authorization policies. This document provides an overview of how to configure and manage the default authorization policy in OpenTDF.

#### Key Aspects of Authorization Configuration

2. **Username Claim**: The claim in the OIDC token that should be used to extract a username.
3. **Group Claim**: The claim in the OIDC token that should be used to find the group claims.
4. **Map (Deprecated)**: Mapping between policy roles and IdP roles.
4. **Extension**: Policy that will extend the builtin policy
4. **CSV**: The authorization policy in CSV format. This will override the builtin policy.
5. **Model**: The Casbin policy model. This should only be set if you have a deep understanding of how casbin works.

#### Configuration in opentdf-example.yaml

Below is an example configuration snippet from
opentdf-example.yaml:

```yaml
server:
  auth:
    enabled: true
    enforceDPoP: false
    public_client_id: 'opentdf-public'
    audience: 'http://localhost:8080'
    issuer: http://keycloak:8888/auth/realms/opentdf
    policy:
      
      ## Deprecated
      ## Dot notation is used to access nested claims (i.e. realm_access.roles)
      claim: "realm_access.roles"

      ## Dot notation is used to access the username claim
      username_claim: "email"

      ## Dot notation is used to access the groups claim
      group_claim: "realm_access.roles"
      
      ## Deprecated: Use standard casbin policy groupings (g, <user/group>, <role>)
      ## Maps the external role to the OpenTDF role
      ## Note: left side is used in the policy, right side is the external role
      map:
        standard: opentdf-standard
        admin: opentdf-admin

      ## Policy that will extend the builtin policy.
      extension: |
        p, role:admin, *, *, allow
        p, role:standard, policy:attributes, read, allow
        p, role:standard, policy:subject-mappings, read, allow
        g, opentdf-admin, role:admin
        g, alice@opentdf.io, role:standard

      ## Custom policy (see examples https://github.com/casbin/casbin/tree/master/examples)
      ## This will overwrite the builtin policy. Use with caution. 
      csv: |
        p, role:admin, *, *, allow
        p, role:standard, policy:attributes, read, allow
        p, role:standard, policy:subject-mappings, read, allow
        p, role:standard, policy:resource-mappings, read, allow
        p, role:standard, policy:kas-registry, read, allow
        p, role:unknown, entityresolution.EntityResolutionService.ResolveEntities, write, allow
        p, role:unknown, kas.AccessService/Rewrap, *, allow

      ## Custom model (see https://casbin.org/docs/syntax-for-models/)
      ## Avoid setting this unless you have a deep understanding of how casbin works. 
      model: |
        [request_definition]
        r = sub, res, act, obj
        
        [policy_definition]
        p = sub, res, act, obj, eft
        
        [role_definition]
        g = _, _
        
        [policy_effect]
        e = some(where (p.eft == allow)) && !some(where (p.eft == deny))
        
        [matchers]
        m = g(r.sub, p.sub) && globOrRegexMatch(r.res, p.res) && globOrRegexMatch(r.act, p.act) && globOrRegexMatch(r.obj, p.obj)
```

#### Role Permissions

- **Admin**: Can perform all operations.
- **Standard User**: Can read.
- **Public Endpoints**: Accessible without specific roles.

#### Managing Authorization Policy

Admins can manage the authorization policy directly in the YAML configuration file. For detailed configuration options, refer to the [Casbin documentation](https://casbin.org/docs/en/syntax-for-models).
