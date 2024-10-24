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
| `endpoint` | The core platform endpoint to connect to |  | OPENTDF_SDK_CONFIG_ENDPOINT |
| `plaintext` | Use a plaintext grpc connection | `false` | OPENTDF_SDK_CONFIG_PLAINTEXT |
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

| Field                 | Description                                                       | Default | Environment Variable |
| --------------------- | ----------------------------------------------------------------- | ------- | -------------------- |
| `auth.audience`       | The audience for the IDP.                                         |         | OPENTDF_SERVER_AUTH_AUDIENCE |
| `auth.issuer`         | The issuer for the IDP.                                           |         | OPENTDF_SERVER_AUTH_ISSUER |
| `auth.cache_refresh`  | Interval in which the IDP jwks should be refreshed                | `15m`   | OPENTDF_SERVER_AUTH_CACHE_REFRESH |
| `auth.dpopskew`       | The amount of time drift allowed between when the client generated a dpop proof and the server time. | `1h` | OPENTDF_SERVER_AUTH |
| `auth.skew`           | The amount of time drift allowed between a tokens `exp` claim and the server time. | `1m` | OPENTDF_SERVER_AUTH_SKEW |
| `auth.public_client_id` | The oidc client id. This is leveraged by otdfctl.               |         | OPENTDF_SERVER_AUTH_PUBLIC_CLIENT_ID |
| `auth.enforceDPoP`    | If true, DPoP bindings on Access Tokens are enforced.             | `false` | OPENTDF_SERVER_AUTH_ENFORCEDPOP |
| `cryptoProvider`      | A list of public/private keypairs and their use. Described [below](#crypto-provider) | empty   | |
| `enable_pprof`        | Enable golang performance profiling                               | `false` | OPENTDF_SERVER_ENABLE_PPROF    |
| `grpc.reflection`     | The configuration for the grpc server.                            | `true`  | OPENTDF_SERVER_GRPC_REFLECTION |
| `host`                | The host address for the server.                                  | `""`    | OPENTDF_SERVER_HOST  |
| `port`                | The port number for the server.                                   | `9000`  | OPENTDF_SERVER_PORT  |
| `tls.enabled`         | Enable tls.                                                       | `false` | OPENTDF_SERVER_TLS_ENABLED |
| `tls.cert`            | The path to the tls certificate.                                  |         | OPENTDF_SERVER_TLS_CERT |
| `tls.key`             | The path to the tls key.                                          |         | OPENTDF_SERVER_TLS_KEY  |

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

| Field          | Description                                   | Default     | Environment Variables |
| -------------- | --------------------------------------------- | ----------- | --------------------- |
| `host`         | The host address for the database.            | `localhost` | OPENTDF_DB_HOST       |
| `port`         | The port number for the database.             | `5432`      | OPENTDF_DB_PORT       |
| `database`     | The name of the database.                     | `opentdf`   | OPENTDF_DB_DATABASE   |
| `user`         | The username for the database.                | `postgres`  | OPENTDF_DB_USER       |
| `password`     | The password for the database.                | `changeme`  | OPENTDF_DB_PASSWORD   |
| `sslmode`      | The ssl mode for the database                 | `prefer`    | OPENTDF_DB_SSLMODE    |
| `schema`       | The schema for the database.                  | `opentdf`   | OPENTDF_DB_SCHEMA     |
| `runMigration` | Whether to run the database migration or not. | `true`      | OPENTDF_DB_RUNMIGRATION |

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

| Field                     | Description                                            | Default                                | Environment Variables                           |
| ------------------------- | ------------------------------------------------------ | -------------------------------------- | ----------------------------------------------- |
| `listrequestlimitdefault` | Policy List request limit default when not provided    | 1000                                   | OPENTDF_SERVICES_POLICY_LISTREQUESTLIMITDEFAULT |
| `listrequestlimitmax`     | Policy List request limit maximum enforced by services | 2500                                   | OPENTDF_SERVICES_POLICY_LISTREQUESTLIMITMAX     |

Example:

```yaml
services:
  policy:
    listrequestlimitdefault: 1000
    listrequestlimitmax: 2500
```