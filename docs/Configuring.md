# Platform Configuration

This guide provides details about the configuration setup for the platform, including the logger, services , and server configurations.

The platform leverages [viper](https://github.com/spf13/viper) to help load configuration.

- [Platform Configuration](#platform-configuration)
  - [Deployment Mode](#deployment-mode)
    - [Service Negation](#service-negation)
  - [SDK Configuration](#sdk-configuration)
  - [Logger Configuration](#logger-configuration)
  - [Server Configuration](#server-configuration)
    - [CORS Configuration](#cors-configuration)
      - [Additive Configuration](#additive-configuration)
      - [Programmatic Configuration](#programmatic-configuration)
    - [Crypto Provider](#crypto-provider)
    - [Tracing Configuration](#tracing-configuration)
  - [Database Configuration](#database-configuration)
  - [Security Configuration](#security-configuration)
  - [Services Configuration](#services-configuration)
    - [Key Access Server (KAS)](#key-access-server-kas)
    - [Authorization](#authorization)
      - [Shared Keys (v1 \& v2)](#shared-keys-v1--v2)
      - [Authorization v1 Only](#authorization-v1-only)
      - [Authorization v2 Only](#authorization-v2-only)
      - [Example: Authorization v1](#example-authorization-v1)
      - [Example: Authorization v2](#example-authorization-v2)
    - [Entity Resolution](#entity-resolution)
      - [Shared Keys (v1 \& v2)](#shared-keys-v1--v2-1)
      - [Entity Resolution v1 Only](#entity-resolution-v1-only)
      - [Entity Resolution v2 Only](#entity-resolution-v2-only)
      - [Example: Entity Resolution v1](#example-entity-resolution-v1)
      - [Example: Entity Resolution v2](#example-entity-resolution-v2)
    - [Policy](#policy)
    - [Casbin Endpoint Authorization](#casbin-endpoint-authorization)
      - [Key Aspects of Authorization Configuration](#key-aspects-of-authorization-configuration)
      - [Configuration in opentdf-example.yaml](#configuration-in-opentdf-exampleyaml)
      - [Role Permissions](#role-permissions)
      - [Managing Authorization Policy](#managing-authorization-policy)
  - [Cache Configuration](#cache-configuration)

## Deployment Mode

The platform is designed as a modular monolith, meaning that all services are built into and run from the same binary. However, these services can be grouped and run together based on specific needs. The available service groups are:

- all: Runs every service that is registered within the platform.
- core: Runs essential services, including policy, authorization, and wellknown services.
- kas: Runs the Key Access Server (KAS) service.

### Service Negation

You can exclude specific services from any mode using the negation syntax `-servicename`:

- **Syntax**: `mode: <base-mode>,-<service1>,-<service2>`
- **Constraint**: At least one positive mode must be specified (negation-only modes like `-kas` will result in an error)
- **Available services**: `policy`, `authorization`, `kas`, `entityresolution`, `wellknown`

**Examples:**
```yaml
# Run all services except Entity Resolution Service
mode: all,-entityresolution

# Run core services except Policy Service  
mode: core,-policy

# Run all services except both KAS and Entity Resolution
mode: all,-kas,-entityresolution
```

| Field  | Description                                                                                                                                          | Default | Environment Variable |
| ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | -------------------- |
| `mode` | Drives which services to run. Supported modes: `all`, `core`, `kas`. Use `-servicename` to exclude specific services (e.g., `all,-entityresolution`) | `all`   | OPENTDF_MODE         |

## SDK Configuration

The sdk configuration is used when operating the service in mode `kas`. When running in mode `core` or `all` an in-process communication is leveraged over an in-memory grpc server.

Root level key `sdk_config`

| Field                        | Description                                 | Default | Environment Variable             |
| ---------------------------- | ------------------------------------------- | ------- | -------------------------------- |
| `core.endpoint`              | The core platform endpoint to connect to    |         | OPENTDF_SDK_CONFIG_ENDPOINT      |
| `core.plaintext`             | Use a plaintext grpc connection             | `false` | OPENTDF_SDK_CONFIG_PLAINTEXT     |
| `core.insecure`              | Use an insecure tls connection              | `false` |                                  |
| `entityresolution.endpoint`  | The entityresolution endpoint to connect to |         |                                  |
| `entityresolution.plaintext` | Use a plaintext ERS grpc connection         | `false` |                                  |
| `entityresolution.insecure`  | Use an insecure tls connection              | `false` |                                  |
| `client_id`                  | OAuth client id                             |         | OPENTDF_SDK_CONFIG_CLIENT_ID     |
| `client_secret`              | The clients credentials                     |         | OPENTDF_SDK_CONFIG_CLIENT_SECRET |

## Logger Configuration

The logger configuration is used to define how the application logs its output.

Root level key `logger`

| Field    | Description                              | Default  | Environment Variable  |
| -------- | ---------------------------------------- | -------- | --------------------- |
| `level`  | The logging level.                       | `info`   | OPENTDF_LOGGER_LEVEL  |
| `type`   | The format of the log output.            | `json`   | OPENTDF_LOGGER_TYPE   |
| `output` | Stream output for logs, stderr or stdout | `stdout` | OPENTDF_LOGGER_OUTPUT |

Example:

```yaml
logger:
  level: debug
  type: text
  output: stderr
```

## Server Configuration

The server configuration is used to define how the application runs its server.

Root level key `server`

| Field                   | Description                                                                                                   | Default | Environment Variable                 |
| ----------------------- | ------------------------------------------------------------------------------------------------------------- | ------- | ------------------------------------ |
| `auth.audience`         | The audience for the IDP.                                                                                     |         | OPENTDF_SERVER_AUTH_AUDIENCE         |
| `auth.issuer`           | The issuer for the IDP.                                                                                       |         | OPENTDF_SERVER_AUTH_ISSUER           |
| `auth.policy`           | The Casbin policy for enforcing authorization on endpoints. Described [below](#casbin-endpoint-authorization) |         |                                      |
| `auth.cache_refresh`    | Interval in which the IDP jwks should be refreshed                                                            | `15m`   | OPENTDF_SERVER_AUTH_CACHE_REFRESH    |
| `auth.dpopskew`         | The amount of time drift allowed between when the client generated a dpop proof and the server time.          | `1h`    | OPENTDF_SERVER_AUTH                  |
| `auth.skew`             | The amount of time drift allowed between a tokens `exp` claim and the server time.                            | `1m`    | OPENTDF_SERVER_AUTH_SKEW             |
| `auth.public_client_id` | [DEPRECATED] The oidc client id. This is leveraged by otdfctl.                                                |         | OPENTDF_SERVER_AUTH_PUBLIC_CLIENT_ID |
| `auth.enforceDPoP`      | If true, DPoP bindings on Access Tokens are enforced.                                                         | `false` | OPENTDF_SERVER_AUTH_ENFORCEDPOP      |
| `cryptoProvider`        | A list of public/private keypairs and their use. Described [below](#crypto-provider)                          | empty   |                                      |
| `enable_pprof`          | Enable golang performance profiling                                                                           | `false` | OPENTDF_SERVER_ENABLE_PPROF          |
| `grpc.reflection`       | The configuration for the grpc server.                                                                        | `true`  | OPENTDF_SERVER_GRPC_REFLECTION       |
| `public_hostname`       | The public facing hostname for the server.                                                                    |         | OPENTDF_SERVER_PUBLIC_HOSTNAME       |
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

### CORS Configuration

Root level key `server.cors`

| Field                      | Description                                       | Default                                                                                                                                                                          | Environment Variable                         |
| -------------------------- | ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| `enabled`                  | Enable CORS for the server                        | `true`                                                                                                                                                                           | OPENTDF_SERVER_CORS_ENABLED                  |
| `allowedorigins`           | List of allowed origins (`*` for any)             | `[]`                                                                                                                                                                             | OPENTDF_SERVER_CORS_ALLOWEDORIGINS           |
| `allowedmethods`           | List of allowed HTTP methods                      | `["GET","POST","PATCH","DELETE","OPTIONS"]`                                                                                                                                      | OPENTDF_SERVER_CORS_ALLOWEDMETHODS           |
| `allowedheaders`           | List of allowed request headers                   | `["Accept","Accept-Encoding","Authorization","Connect-Protocol-Version","Content-Length","Content-Type","Dpop","X-CSRF-Token","X-Requested-With","X-Rewrap-Additional-Context"]` | OPENTDF_SERVER_CORS_ALLOWEDHEADERS           |
| `exposedheaders`           | List of response headers browsers can access      | `[]`                                                                                                                                                                             | OPENTDF_SERVER_CORS_EXPOSEDHEADERS           |
| `allowcredentials`         | Whether credentials are included in CORS requests | `true`                                                                                                                                                                           | OPENTDF_SERVER_CORS_ALLOWCREDENTIALS         |
| `maxage`                   | Maximum age (seconds) of preflight cache          | `3600`                                                                                                                                                                           | OPENTDF_SERVER_CORS_MAXAGE                   |
| `additionalmethods`        | Additional methods to append to defaults          | `[]`                                                                                                                                                                             | OPENTDF_SERVER_CORS_ADDITIONALMETHODS        |
| `additionalheaders`        | Additional headers to append to defaults          | `[]`                                                                                                                                                                             | OPENTDF_SERVER_CORS_ADDITIONALHEADERS        |
| `additionalexposedheaders` | Additional exposed headers to append              | `[]`                                                                                                                                                                             | OPENTDF_SERVER_CORS_ADDITIONALEXPOSEDHEADERS |

#### Additive Configuration

The `additional*` fields allow operators to extend the default lists without replacing them entirely:

```yaml
server:
  cors:
    enabled: true
    # Add custom headers without copying all defaults
    additionalheaders:
      - X-Custom-Header
      - X-Another-Header
```

To completely replace defaults, use the base fields directly:

```yaml
server:
  cors:
    allowedheaders:
      - Authorization
      - Content-Type
      # Only these headers will be allowed
```

#### Programmatic Configuration

For applications embedding the OpenTDF platform, CORS can also be configured programmatically using functional options. These are applied after YAML/environment configuration and follow the same additive semantics:

```go
import "github.com/opentdf/platform/service/pkg/server"

err := server.Start(
    server.WithConfigFile("opentdf.yaml"),
    // Add custom headers for your application
    server.WithAdditionalCORSHeaders("X-Custom-Header", "X-App-Version"),
    // Add custom methods if needed
    server.WithAdditionalCORSMethods("CUSTOM"),
    // Expose additional response headers to browsers
    server.WithAdditionalCORSExposedHeaders("X-Request-Id", "X-Trace-Id"),
)
```

**Configuration Precedence:**

1. **Defaults** - Built-in default values
2. **YAML/Environment** - Operator configuration via `server.cors.*` fields
3. **Programmatic Options** - Developer overlays via `WithAdditionalCORS*` functions

All layers are additive. Deduplication is handled automatically (case-insensitive for headers per RFC 7230, case-sensitive for methods per RFC 7231).

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

### Tracing Configuration

Root level key `server.trace`

| Field                        | Description                     | Default | Environment Variable               |
| ---------------------------- | ------------------------------- | ------- | ---------------------------------- |
| `server.trace.enabled`       | Enable distributed tracing      | `false` | OPENTDF_SERVER_TRACE_ENABLED       |
| `server.trace.provider.name` | Tracing provider (file or otlp) | `otlp`  | OPENTDF_SERVER_TRACE_PROVIDER_NAME |

For file provider:
- `server.trace.provider.file.path`: Path to trace file output
- `server.trace.provider.file.prettyPrint`: Enable pretty-printed JSON
- `server.trace.provider.file.maxSize`: Maximum file size in MB
- `server.trace.provider.file.maxBackups`: Maximum number of backup files
- `server.trace.provider.file.maxAge`: Maximum age of files in days
- `server.trace.provider.file.compress`: Enable compression of trace files

For OTLP provider:
- `server.trace.provider.otlp.protocol`: Protocol to use (grpc or http/protobuf)
- `server.trace.provider.otlp.endpoint`: Endpoint URL for the collector
- `server.trace.provider.otlp.insecure`: Whether to use an insecure connection
- `server.trace.provider.otlp.headers`: Headers to include in OTLP requests

Example:

```yaml
server:
  trace:
    enabled: true
    provider:
      name: otlp
      otlp:
        protocol: grpc
        endpoint: "localhost:4317"
        insecure: true
```

## Database Configuration

The database configuration is used to define how the application connects to its database.

Root level key `db`

| Field                                  | Description                                   | Default     | Environment Variables                           |
| -------------------------------------- | --------------------------------------------- | ----------- | ----------------------------------------------- |
| `host`                                 | The host address for the database.            | `localhost` | OPENTDF_DB_HOST                                 |
| `port`                                 | The port number for the database.             | `5432`      | OPENTDF_DB_PORT                                 |
| `database`                             | The name of the database.                     | `opentdf`   | OPENTDF_DB_DATABASE                             |
| `user`                                 | The username for the database.                | `postgres`  | OPENTDF_DB_USER                                 |
| `password`                             | The password for the database.                | `changeme`  | OPENTDF_DB_PASSWORD                             |
| `sslmode`                              | The ssl mode for the database                 | `prefer`    | OPENTDF_DB_SSLMODE                              |
| `schema`                               | The schema for the database.                  | `opentdf`   | OPENTDF_DB_SCHEMA                               |
| `runMigration`                         | Whether to run the database migration or not. | `true`      | OPENTDF_DB_RUNMIGRATION                         |
| `connect_timeout_seconds`              | Connection timeout duration (seconds).        | `15`        | OPENTDF_DB_CONNECT_TIMEOUT_SECONDS              |
| `pool`                                 | Pool configuration settings.                  |             |                                                 |
| `pool.max_connection_count`            | Maximum number of connections per pool.       | `4`         | OPENTDF_DB_POOL_MAX_CONNECTION_COUNT            |
| `pool.min_connection_count`            | Minimum number of connections per pool.       | `0`         | OPENTDF_DB_POOL_MIN_CONNECTION_COUNT            |
| `pool.max_connection_lifetime_seconds` | Maximum seconds per connection lifetime.      | `3600`      | OPENTDF_DB_POOL_MAX_CONNECTION_LIFETIME_SECONDS |
| `pool.min_idle_connections_count`      | Minimum number of idle connections per pool.  | `0`         | OPENTDF_DB_POOL_MIN_IDLE_CONNECTIONS_COUNT      |
| `pool.max_connection_idle_seconds`     | Maximum seconds allowed for idle connection.  | `1800`      | OPENTDF_DB_POOL_MAX_CONNECTION_IDLE_SECONDS     |
| `pool.health_check_period_seconds`     | Interval seconds per health check.            | `60`        | OPENTDF_DB_POOL_HEALTH_CHECK_PERIOD_SECONDS     |




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

## Security Configuration

Root level key `security`

| Field               | Description                                                                                     | Default |
| ------------------- | ----------------------------------------------------------------------------------------------- | ------- |
| `unsafe.clock_skew` | Platform-wide maximum tolerated clock skew for token verification (Go duration, use cautiously) | `1m`    |

> **Warning:** Increasing `unsafe.clock_skew` weakens token freshness guarantees. Only raise this value temporarily while you correct clock drift.

## Services Configuration

Root level key `services`

### Key Access Server (KAS)

Root level key `kas`

Environment Variable: `OPENTDF_SERVICES_KAS_KEYRING='[{"kid":"k1","alg":"rsa:2048"},{"kid":"k2","alg":"ec:secp256r1"}]'`

| Field                    | Description                                                                     | Default  |
| ------------------------ | ------------------------------------------------------------------------------- | -------- |
| `keyring.*.kid`          | Which key id this is binding                                                    |          |
| `keyring.*.alg`          | (Optional) Associated algorithm. (Allows reusing KID with different algorithms) |          |
| `keyring.*.legacy`       | Indicates this may be used for TDFs with no key ID; default if all unspecified. | inferred |
| `preview.ec_tdf_enabled` | Whether tdf based ecc support is enabled.                                       | `false`  |
| `preview.key_management` | Whether new key management features are enabled.                                | `false`  |
| `root_key`               | Key needed when new key_management functionality is enabled.                    |          |

Example:

```yaml
security:
  unsafe:
    # Increase only when diagnosing clock drift issues
    # clock_skew: 90s

services:
  kas:
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

> **Note:** Both Authorization v1 and v2 use the same configuration section, but some keys are version-specific. See below for details.

#### Shared Keys (v1 & v2)

| Field                                             | Description | Default | Environment Variables |
| ------------------------------------------------- | ----------- | ------- | --------------------- |
| *(none currently; all keys are version-specific)* |             |         |                       |

#### Authorization v1 Only

| Field        | Description              | Default                                | Environment Variables                     |
| ------------ | ------------------------ | -------------------------------------- | ----------------------------------------- |
| `rego.path`  | Path to rego policy file | Leverages embedded rego policy         | OPENTDF_SERVICES_AUTHORIZATION_REGO_PATH  |
| `rego.query` | Rego query to execute    | `data.opentdf.entitlements.attributes` | OPENTDF_SERVICES_AUTHORIZATION_REGO_QUERY |

#### Authorization v2 Only

| Field                                       | Description                                                    | Default | Environment Variables |
| ------------------------------------------- | -------------------------------------------------------------- | ------- | --------------------- |
| `entitlement_policy_cache.enabled`          | Enable the entitlement policy cache                            | `false` |                       |
| `entitlement_policy_cache.refresh_interval` | How often to refresh the entitlement policy cache (e.g. `30s`) |         |                       |

#### Example: Authorization v1

```yaml
services:
  authorization:
    rego:
      path: /path/to/policy.rego
      query: data.opentdf.entitlements.attributes
```

#### Example: Authorization v2

```yaml
services:
  authorization:
    entitlement_policy_cache:
      enabled: false
      refresh_interval: 30s
```

### Entity Resolution

Root level key `entityresolution`

> **Note:** Both Entity Resolution v1 and v2 use the same configuration section. All configuration keys are shared between v1 and v2, except `cache_expiration`, which is only used in v2.

#### Shared Keys (v1 & v2)

| Field                   | Description                                                                                    | Default    | Environment Variable                                    |
| ----------------------- | ---------------------------------------------------------------------------------------------- | ---------- | ------------------------------------------------------- |
| `mode`                  | The mode in which to run ERS (`keycloak` or `claims`)                                          | `keycloak` | OPENTDF_SERVICES_ENTITYRESOLUTION_MODE                  |
| `url`                   | Endpoint URL for the entity resolution service (specific to `keycloak` mode)                   | `""`       | OPENTDF_SERVICES_ENTITYRESOLUTION_URL                   |
| `clientid`              | Keycloak client ID for authentication (specific to `keycloak` mode)                            | `""`       | OPENTDF_SERVICES_ENTITYRESOLUTION_CLIENTID              |
| `clientsecret`          | Keycloak client secret for authentication(specific to `keycloak` mode)                         | `""`       | OPENTDF_SERVICES_ENTITYRESOLUTION_CLIENTSECRET          |
| `realm`                 | Keycloak realm for authentication (specific to `keycloak` mode)                                |            | OPENTDF_SERVICES_ENTITYRESOLUTION_REALM                 |
| `legacykeycloak`        | Enables legacy Keycloak compatibility (`/auth` as base endpoint) (specific to `keycloak` mode) | `false`    | OPENTDF_SERVICES_ENTITYRESOLUTION_LEGACYKEYCLOAK        |
| `inferid.from.email`    | Infer entity IDs from email addresses (specific to `keycloak` mode)                            | `false`    | OPENTDF_SERVICES_ENTITYRESOLUTION_INFERID_FROM_EMAIL    |
| `inferid.from.username` | Infer entity IDs from usernames (specific to `keycloak` mode)                                  | `false`    | OPENTDF_SERVICES_ENTITYRESOLUTION_INFERID_FROM_USERNAME |
| `inferid.from.clientid` | Infer entity IDs from client IDs (specific to `keycloak` mode)                                 | `false`    | OPENTDF_SERVICES_ENTITYRESOLUTION_INFERID_FROM_CLIENTID |

#### Entity Resolution v1 Only

| Field              | Description | Default | Environment Variables |
| ------------------ | ----------- | ------- | --------------------- |
| *(none currently)* |             |         |                       |

#### Entity Resolution v2 Only

| Field              | Description                                                                                                            | Default  | Environment Variable |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------- | -------- | -------------------- |
| `cache_expiration` | Cache duration for entity resolution results (e.g., `30s`). Disabled if not set or zero. (specific to `keycloak` mode) | disabled |                      |

#### Example: Entity Resolution v1

```yaml
services:
  entityresolution:
    url: http://localhost:8888/auth
    clientid: "tdf-entity-resolution"
    clientsecret: "secret"
    realm: "opentdf"
    legacykeycloak: true
    inferid:
      from:
        email: true
        username: true
```

#### Example: Entity Resolution v2

```yaml
services:
  entityresolution:
    url: http://localhost:8888/auth
    clientid: "tdf-entity-resolution"
    clientsecret: "secret"
    realm: "opentdf"
    legacykeycloak: true
    inferid:
      from:
        email: true
        username: true
    cache_expiration: 30s
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
    # public_client_id: 'opentdf-public' # DEPRECATED
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

      # Dot notation is used to access the claim the represents the idP client ID 
      client_id_claim: # azp
      
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

## Cache Configuration

The platform supports a cache manager to improve performance for frequently accessed data. You can configure the cache backend and its resource usage.

Root level key `cache`

| Field                | Description                                  | Default |
| -------------------- | -------------------------------------------- | ------- |
| `ristretto.max_cost` | Maximum cost for the cache (e.g. 100mb, 1gb) | `1gb`   |

Example:

```yaml
cache:
  ristretto:
    max_cost: 1gb              # Maximum cost (i.e. 1mb, 1gb) for the cache (default: 1gb)
```
