# Configuration Guide

This guide provides details about the configuration setup for our application, including logger, services (specifically entitlements), and server configurations.

- [Configuration Guide](#configuration-guide)
  - [Logger Configuration](#logger-configuration)
  - [Server Configuration](#server-configuration)
  - [Database Configuration](#database-configuration)
  - [OPA Configuration](#opa-configuration)
  - [Services Configuration](#services-configuration)
    - [Key Access Server (KAS)](#key-access-server-kas)
    - [Policy](#policy)
    - [Authorization](#authorization)

## Logger Configuration

The logger configuration is used to define how the application logs its output.

| Field    | Description                      | Default  |
| -------- | -------------------------------- | -------- |
| `level`  | The logging level.               | `info`   |
| `type`   | The format of the log output.    | `json`   |
| `output` | The output destination for logs. | `stdout` |

Example:

```yaml
logger:
  level: debug
  type: text
  output: stdout
```

## Server Configuration

The server configuration is used to define how the application runs its server.

| Field                 | Description                                                       | Default |
| --------------------- | ----------------------------------------------------------------- | ------- |
| `port`                | The port number for the server.                                   | `9000`  |
| `host`                | The host address for the server.                                  | `""`    |
| `grpc.reflection`     | The configuration for the grpc server.                            | `true`  |
| `tls.enabled`         | Enable tls.                                                       | `false` |
| `tls.cert`            | The path to the tls certificate.                                  |         |
| `tls.key`             | The path to the tls key.                                          |         |
| `auth.audience`       | The audience for the IDP.                                         |         |
| `auth.issuer`         | The issuer for the IDP.                                           |         |
| `auth.enforceDPoP`    | If true, DPoP bindings on Access Tokens are enforced.             | `false` |
| `auth.cryptoProvider` | A list of public/private keypairs and their use. Described below. | empty   |

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
We currently only intend to support `standard` as part of our open source offering,
with the `hsm` variant a proof of concept alternative using PKCS#11.

| Field                               | Description                                                               | Default    |
| ----------------------------------- | ------------------------------------------------------------------------- | ---------- |
| `cryptoProvider.type`               | The type of crypto provider to use.                                       | `standard` |
| `cryptoProvider.standard.*.alg`     | An enum for the associated crypto type. E.g. `rsa:2048` or `ec:secp256r1` |            |
| `cryptoProvider.standard.*.kid`     | A short, globally unique, stable identifier for this keypair.             |            |
| `cryptoProvider.standard.*.private` | Path to the private key as a PEM file.                                    |            |
| `cryptoProvider.standard.*.cert`    | (Optional) Path to a public cert for the keypair.                         |            |
| `cryptoProvider.standard.*.public`  | (Optional) Path to a public key as a PEM file.                            |            |

## Database Configuration

The database configuration is used to define how the application connects to its database.

| Field          | Description                                   | Default     |
| -------------- | --------------------------------------------- | ----------- |
| `host`         | The host address for the database.            | `localhost` |
| `port`         | The port number for the database.             | `5432`      |
| `database`     | The name of the database.                     | `opentdf`   |
| `user`         | The username for the database.                | `postgres`  |
| `password`     | The password for the database.                | `changeme`  |
| `sslmode`      | The ssl mode for the database                 | `prefer`    |
| `schema`       | The schema for the database.                  | `opentdf`   |
| `runMigration` | Whether to run the database migration or not. | `true`      |

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

### Key Access Server (KAS)

| Field              | Description                                                                     | Default  |
| ------------------ | ------------------------------------------------------------------------------- | -------- |
| `enabled`          | Enable the Key Access Server                                                    | `true`   |
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

### Policy

| Field     | Description               | Default |
| --------- | ------------------------- | ------- |
| `enabled` | Enable the Policy Service | `true`  |

Example:

```yaml
services:
  policy:
    enabled: true
```

### Authorization

| Field     | Description              | Default |
| --------- | ------------------------ | ------- |
| `enabled` | Enable the Authorization | `true`  |
| `ersurl`  | The location to the entity resolution service | |
| `clientid` | Client Credentials Client ID | |
| `clientsecret` | Client Credentials Secret | |
| `tokenendpoint` | OAuth 2 Token Endpoint (Will be removed at a later time) | |
| `rego.path` | Path to rego policy file | Leverages embedded rego policy |
| `rego.query` | Rego query to execute in policy | `data.opentdf.entitlements.attributes` |
