# OpenTDF

![Vulnerability Check](https://github.com/opentdf/platform/actions/workflows/vulnerability-check.yaml/badge.svg?branch=main)

## Documentation

<!-- Broken
- [Home](https://opentdf.github.io/platform)
-->

- [Configuration](./docs/configuration.md)
- [Development](#development)
- [Policy Config Schema](./service/migrations/20240212000000_schema_erd.md)
- [Policy Config Testing Diagram](./service/integration/testing_diagram.png)

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

- [Air](https://github.com/cosmtrek/air) is used for hot-reload development
  - install with `go install github.com/cosmtrek/air`
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
> (`make go.work`;`go run github.com/opentdf/platform/service migrate up`).

1. `docker-compose up`
2. Create an OpenTDF config file: `opentdf.yaml`
   1. The `opentdf-example.yaml` file is a good starting point, but you may need to modify it to match your environment.
   2. The `opentdf-example-no-kas.yaml` file configures the platform to run insecurely without KAS and without endpoint auth.
3. Provision keycloak `go run github.com/opentdf/platform/service provision keycloak`
4. Configure KAS keys and your HSM with `.github/scripts/hsm-init-temporary-keys.sh`
5. Run the server `go run github.com/opentdf/platform/service start`
   1. _Alt_ use the hot-reload development environment `air`
6. The server is now running on `localhost:8080` (or the port specified in the config file)

Note: support was added to provision a set of fixture data into the database.
Run `go run github.com/opentdf/platform/service provision fixtures -h` for more information.

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
export OPENTDF_SERVER_CRYPTOPROVIDER_HSM_MODULEPATH=/lib/softhsm/libsofthsm2.so
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
creating, updating, and deleting policy configurations. [Docs](https://github.com/opentdf/platform/tree/main/docs)

### How To Add a New Go Module

Within this repo, todefine a new, distinct [go module](https://go.dev/ref/mod),
for example to provide shared functionality between several existing modules,
or to define new and unique functionality
follow these steps.
For this example, we will call our new module `lib/foo`.

```sh
mkdir -p lib/foo
cd lib/foo
go mod init github.com/opentdf/platform/lib/foo
```

In this folder, create your go code as usual.

#### Add a README.md and a LICENSE File

A README is recommended to assist with orientation to use of your package.
Remember, this will be published to https://pkg.go.dev/ as part of the module documentation.

Make sure to add a LICENSE file to your module to support automated license checks.
Feel free to copy the existing (BSD-clear) LICENSE file for most new modules.

#### Replace Directives

If you need to import any monorepo-local modules,
add replace directives as follows (for the SDK) to your `lib/foo/go.mod`:

```go.mod
replace (
 github.com/opentdf/platform/protocol/go => ../../protocol/go
 github.com/opentdf/platform/sdk => ../../sdk
)
```

If any monorepo-local modules need to import your new module,
add a your module folder to their replace directives,
e.g. in `sdk/go.mod`:

```go.mod
replace (
 github.com/opentdf/platform/protocol/go => ../../protocol/go
 github.com/opentdf/platform/lib/foo => ../lib/foo
)
```

#### Updating the Makefile

1. Add your module to the `MODS` variable:

   ```Makefile
   MODS=protocol/go sdk . examples lib/foo
   ```

2. _If required_ If your project does not generate a built artifact,
   add a phony binary target to the `.PHONY` declaration.

   ```Makefile
   .PHONY: ...existing phony targets... lib/foo/foo
   ```

3. Add your build target to the `build` phony target.

   ```Makefile
   build: ...existing targets... lib/foo/foo
   ```

4. Add your build target and rule

   ```Makefile
   lib/foo/foo: go.work $(shell find lib/foo)
   	(cd lib/foo && go build ./...)
   ```

#### Updating the Docker Images

Add any required `COPY` directives to `./Dockerfile`:

```Dockerfile
COPY lib/foo/ lib/foo/
```

#### Updating the Workflow Files

1. Add your new `go.mod` directory to the `.github/workflows/checks.yaml`'s `go` job's `matrix.strategry.directory` line.
2. Add the module to the `license` job in the `checks` workflow as well, especially if you declare _any_ dependencies.
3. Do the same for any other workflows that should be running on your folder, such as `vuln-check` and `lint`.
