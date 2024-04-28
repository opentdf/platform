# OpenTDF Platform (Fork of)

- [Configuration](#configuration)
- [Development](#development)

## Configuration

This guide provides details about the configuration setup for our application, including logger, services (specifically entitlements), and server configurations.

- [Logger Configuration](#logger)
- [Server Configuration](#server)
- [Database Configuration](#database)
- [OPA Configuration](#opa)
- [Services Configuration](#services)

### Certificates

1. Install HashiCorp Vault on your local machine:
```shell
brew tap hashicorp/tap
brew install hashicorp/tap/vault
```
2. Enable the LDAP auth method in Vault.
Start a new session with the Vault container using the Vault root token:
```shell
export VAULT_TOKEN="myroot"
export VAULT_ADDR="http://localhost:8200"
vault auth enable ldap
vault write auth/ldap/config \
    url="ldap://openldap" \
    binddn="cn=admin,dc=example,dc=com" \
    bindpass="admin" \
    userattr="cn" \
    userdn="ou=users,dc=example,dc=com" \
    groupdn="ou=groups,dc=example,dc=com" \
    insecure_tls=true
```
3. Add a role that maps to LDAP groups and enable the PKI secrets engine:
```shell
vault write auth/ldap/groups/developers policies=default
vault secrets enable pki
vault secrets tune -max-lease-ttl=87600h pki
```
4.  Generate the root certificate (outside container):
```shell
export VAULT_TOKEN="myroot"
export VAULT_ADDR="http://localhost:8200"
vault write -field=certificate pki/root/generate/internal \
    common_name="root" \
    ttl=87600h > CA_cert.crt
```
5. Configure the issuing certificate URLs
```shell
export VAULT_TOKEN="myroot"
export VAULT_ADDR="http://localhost:8200"
vault write pki/config/urls \
    issuing_certificates="http://localhost:8200/v1/pki/ca" \
    crl_distribution_points="http://localhost:8200/v1/pki/crl"
```
6. Create a role to determine what the engine will issue:
```shell
export VAULT_TOKEN="myroot"
export VAULT_ADDR="http://localhost:8200"
vault write pki/roles/example-dot-com \
    allowed_domains="example.com" \
    allow_subdomains=true \
    max_ttl="768h"
```
7. Now you can issue certificates with the following command:
```shell
vault write -format=json pki/issue/example-dot-com common_name="localhost" ttl="768h" > server.json
cat server.json | jq -r '.data.certificate' > server.crt
cat server.json | jq -r '.data.private_key' > server.key
cat server.json | jq -r '.data.ca_chain[]' > ca.crt
```
or
```shell
vault write -format=json pki/issue/example-dot-com common_name="pep.example.com" ttl="768h" > pep.json
cat pep.json | jq -r '.data.certificate' > pep.crt
cat pep.json | jq -r '.data.private_key' > pep.key
```


### Logger

The logger configuration is used to define how the application logs its output.

| Field | Description | Default |
| --- | --- | --- |
| `level` | The logging level. | `info` |
| `type` | The format of the log output. | `json` |
| `output` | The output destination for logs. | `stdout` |

Example:

```yaml
logger:
  level: debug
  type: text
  output: stdout
```

### Server

The server configuration is used to define how the application runs its server.

| Field | Description | Default |
| --- | --- | --- |
| `port` | The port number for the server. | `9000` |
| `host` | The host address for the server. | `""` |
| `grpc.reflection` | The configuration for the grpc server. | `true` |
| `tls.enabled` | Enable tls. | `false` |
| `tls.cert` | The path to the tls certificate. | |
| `tls.key` | The path to the tls key. | |
| `auth.audience` | The audience for the IDP. | |
| `auth.issuer` | The issuer for the IDP. | |
| `auth.clients` | A list of client id's that are allowed. | |

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
    clients:
      - client_id
      - client_id2
```

### Database

The database configuration is used to define how the application connects to its database.

| Field | Description | Default |
| --- | --- | --- |
| `host` | The host address for the database. | `localhost` |
| `port` | The port number for the database. | `5432` |
| `database` | The name of the database. | `opentdf` |
| `user` | The username for the database. | `postgres` |
| `password` | The password for the database. | `changeme` |
| `sslmode` | The ssl mode for the database | `prefer` |
| `schema` | The schema for the database. | `opentdf` |
| `runMigration` | Whether to run the database migration or not. | `true` |

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

### OPA

| Field | Description | Default |
| --- | --- | --- |
| `embedded` | Whether to use the embedded OPA Bundle server or not. This is only used for local development. | `false` |
| `path` | The path to the OPA configuration file. | `./opa/opa.yaml` |

Example:

```yaml
opa:
  embedded: true # Only for local development
  path: ./opa/opa.yaml
```

### Services

### Key Access Server (KAS)

| Field | Description | Default |
| --- | --- | --- |
| `enabled` | Enable the Key Access Server | `true` |

Example:

```yaml
services:
  kas:
    enabled: true
```

### Policy

| Field | Description | Default |
| --- | --- | --- |
| `enabled` | Enable the Policy Service | `true` |

Example:

```yaml
services:
  policy:
    enabled: true
```

### Authorization

| Field | Description | Default |
| --- | --- | --- |
| `enabled` | Enable the Authorization


## Development

### Prerequisites

#### Required

- Go (_see go.mod for specific version_)
- Container runtime
  - [Docker](https://www.docker.com/get-started/)
  - [Podman](https://podman.io/docs/installation)
- Compose - used to manage multi-container applications
  - [Docker Compose](https://docs.docker.com/compose/install/)
  - [Podman Compose](https://github.com/containers/podman-compose)

#### Optional

- [Buf](https://buf.build/docs/ecosystem/cli-overview) is used for managing protobuf files
  - install with `go install github.com/bufbuild/buf/cmd/buf`
- [grpcurl](https://github.com/fullstorydev/grpcurl) is used for testing gRPC services
  - install with `go install github.com/fullstorydev/grpcurl/cmd/grpcurl`
- [golangci-lint](https://golangci-lint.run/) is used for ensuring good coding practices
  - install with `brew install golangci-lint`
- [softHSM](https://github.com/opendnssec/SoftHSMv2) is used to emulate hardware security (aka `PKCS #11`)

On macOS, these can be installed with [brew](https://docs.brew.sh/Installation)

`brew install buf grpcurl openssl pkcs11-tools softhsm golangci-lint`

### Run

> [!NOTE]
> Migrations are handled automatically by the server. This can be disabled via the config file, as
> needed. They can also be run manually using the `migrate` command
> (`make go.work`;`go run github.com/arkavo-org/opentdf-platform/service migrate up`).

1. `docker-compose up`
2. Create an OpenTDF config file: `opentdf.yaml`
   1. The `opentdf-example.yaml` file is a good starting point, but you may need to modify it to match your environment.
   2. The `opentdf-example-no-kas.yaml` file configures the platform to run insecurely without KAS and without endpoint auth.
3. Provision keycloak `go run github.com/arkavo-org/opentdf-platform/service provision keycloak`
4. Configure KAS keys and your HSM with `.github/scripts/hsm-init-temporary-keys.sh`
5. Run the server `go run github.com/arkavo-org/opentdf-platform/service start`
6. The server is now running on `localhost:8080` (or the port specified in the config file)

Note: support was added to provision a set of fixture data into the database.
Run `go run github.com/arkavo-org/opentdf-platform/service provision fixtures -h` for more information.

### Generation

Our native gRPC service functions are generated from `proto` definitions using [Buf](https://buf.build/docs/introduction).

The `Makefile` provides command scripts to invoke `Buf` with the `buf.gen.yaml` config, including OpenAPI docs, grpc docs, and the
generated code.

For convenience, the `make pre-build` script checks if you have the necessary dependencies for `proto -> gRPC` generation.

## Services

### Key Access Service (KAS)

A KAS controls access to TDF protected content.

#### Configuration

To enable KAS, you must have a working `PKCS #11` library on your system.
For development, we use [the SoftHSM library](https://www.softhsm.org/),
which presents a `PKCS #11` interface to on CPU cryptography libraries.

```
export OPENTDF_SERVER_CRYPTOPROVIDER_HSM_PIN=12345
export OPENTDF_SERVER_CRYPTOPROVIDER_HSM_MODULEPATH=/opt/homebrew/Cellar/softhsm/2.6.1//lib/softhsm/libsofthsm2.so
export OPENTDF_SERVER_CRYPTOPROVIDER_HSM_KEYS_EC_LABEL=kas-ec
export OPENTDF_SERVER_CRYPTOPROVIDER_HSM_KEYS_RSA_LABEL=kas-rsa

pkcs11-tool --module $OPENTDF_SERVER_CRYPTOPROVIDER_HSM_MODULEPATH \
            --login --pin ${OPENTDF_SERVER_CRYPTOPROVIDER_HSM_PIN} \
            --write-object kas-private.pem --type privkey \
            --label kas-rsa
pkcs11-tool --module $OPENTDF_SERVER_CRYPTOPROVIDER_HSM_MODULEPATH \
            --login --pin ${OPENTDF_SERVER_CRYPTOPROVIDER_HSM_PIN} \
            --write-object kas-cert.pem --type cert \
            --label kas-rsa

pkcs11-tool --module $OPENTDF_SERVER_CRYPTOPROVIDER_HSM_MODULEPATH \
            --login --pin ${OPENTDF_SERVER_CRYPTOPROVIDER_HSM_PIN} \
            --write-object ec-private.pem --type privkey \
            --label kas-ec
pkcs11-tool --module $OPENTDF_SERVER_CRYPTOPROVIDER_HSM_MODULEPATH \
            --login --pin ${OPENTDF_SERVER_CRYPTOPROVIDER_HSM_PIN} \
            --write-object ec-cert.pem --type cert \
            --label kas-ec
```

To see how to generate key pairs that KAS can use, review the [the temp keys init script](.github/scripts/hsm-init-temporary-keys.sh).

### Policy

The policy service is responsible for managing policy configurations. It provides a gRPC API for
creating, updating, and deleting policy configurations. [Docs](https://github.com/arkavo-org/opentdf-platform/tree/main/docs)
