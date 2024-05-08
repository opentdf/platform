# OpenTDF

![Vulnerability Check](https://github.com/opentdf/platform/actions/workflows/vulnerability-check.yaml/badge.svg?branch=main)

## Documentation

- [Configuration](./docs/configuration.md)
- [Development](#development)
- [Policy Config Schema](./service/migrations/20240212000000_schema_erd.md)
- [Policy Config Testing Diagram](./service/integration/testing_diagram.png)

## Running the Platform Locally

### Setting up pre-requisites

1. Initialize KAS Keys ```.github/scripts/init-temp-keys.sh -o kas-keys```
2. Stand up the local Postgres database and Keycloak instances using `docker-compose up -d --wait`.
3. Copy the `opentdf-example.yaml` file to `opentdf.yaml` and update the [configuration](./docs/configuration.md) as needed.
Bootstrap Keycloak

   ```sh
      docker run --network opentdf_platform \
         -v "$(pwd)/opentdf.yaml:/home/nonroot/.opentdf/opentdf.yaml" \
         -it registry.opentdf.io/platform:nightly provision keycloak -e http://keycloak:8888/auth
   ```
4. Start the platform

   Exposes the server at localhost:8080
   ```sh
   docker run --network opentdf_platform \
      -p "127.0.0.1:8080:8080" \
      -v "$(pwd)/kas-keys/:/keys/" \
      -v "$(pwd)/opentdf.yaml:/home/nonroot/.opentdf/opentdf.yaml" \
      -it registry.opentdf.io/platform:nightly start
   ```

## Development

### Prerequisites

- [Go](https://go.dev/) (_see go.mod for specific version_)
- Container runtime
  - [Docker](https://www.docker.com/get-started/)
  - [Podman](https://podman.io/docs/installation)
- Compose - used to manage multi-container applications
  - [Docker Compose](https://docs.docker.com/compose/install/)
  - [Podman Compose](https://github.com/containers/podman-compose)
- [Buf](https://buf.build/docs/ecosystem/cli-overview) is used for managing protobuf files.
  Required for developing services.
- _Optional_ [Air](https://github.com/cosmtrek/air) is used for hot-reload development
- _Optional_ [golangci-lint](https://golangci-lint.run/) is used for ensuring good coding practices
  - install with `brew install golangci-lint`
- _Optional_ [grpcurl](https://github.com/fullstorydev/grpcurl) is used for testing gRPC services

On macOS, these can be installed with [brew](https://docs.brew.sh/Installation)

```sh
brew install buf go golangci-lint goose grpcurl openssl
```

### Run

> [!NOTE]
> Migrations are handled automatically by the server. This can be disabled via the config file, as
> needed. They can also be run manually using the `migrate` command
> (`go run github.com/opentdf/platform/service migrate up`).

1.  Configure KAS and Keycloak keys: `.github/scripts/init-temp-keys.sh`. Creates temporary keys for the local KAS and Keycloak Certificate Exchange. 
2. `docker-compose up`. Starts both the local Postgres database (contains the ABAC policy configuration data) and Keycloak (the local IdP).
   1. Note: You will have to add the ``localhost.crt`` as a trusted certificate to do TLS authentication at ``localhost:8443``.
3. Create an OpenTDF config file: `opentdf.yaml`
   1. The `opentdf-dev.yaml` file is the more secure starting point, but you will likely need to modify it to match your environment. This configuration is recommended as it is more secure but it does require valid development keypairs.
   2. The `opentdf-example-no-kas.yaml` file is simpler to run but less secure. This file configures the platform to startup without a KAS instances and without endpoint authentication.
4. Provision keycloak: `go run github.com/opentdf/platform/service provision keycloak`. Updates the local Keycloak configuration for local testing and development by creating a realm, roles, a client, and users.
5. Run the server: `go run github.com/opentdf/platform/service start`. Runs the OpenTDF platform capabilities as a monolithic service.
   1. _Alt_ use the hot-reload development environment `air`
6. The server is now running on `localhost:8080` (or the port specified in the config file)

Note: support was added to provision a set of fixture data into the database.
Run `go run github.com/opentdf/platform/service provision fixtures -h` for more information.

### Provisioning Custom Keycloak and Policy Data

To provision a custom Keycloak setup, create a yaml following the format of [the sample Keycloak config](service/cmd/keycloak_data.yaml). You can create different realms with separate users, clients, roles, and groups. Run the provisioning with `go run ./service provision keycloak-from-config -f <path-to-your-yaml-file>`.

### Generation

Our native gRPC service functions are generated from `proto` definitions using [Buf](https://buf.build/docs/introduction).

The `Makefile` provides command scripts to invoke `Buf` with the `buf.gen.yaml` config, including OpenAPI docs, grpc docs, and the
generated code.

For convenience, the `make toolcheck` script checks if you have the necessary dependencies for `proto -> gRPC` generation.

## Services

### Key Access Service (KAS)

A KAS controls access to TDF protected content.

#### Configuration

To enable KAS, you must have stable asymmetric keypairs configured.
[The temp keys init script](.github/scripts/init-temp-keys.sh) will generate two development keys.

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
go work use .
```

In this folder, create your go code as usual.

#### Add a README.md and a LICENSE File

A README is recommended to assist with orientation to use of your package.
Remember, this will be published to <https://pkg.go.dev/> as part of the module documentation.

Make sure to add a LICENSE file to your module to support automated license checks.
Feel free to copy the existing (BSD-clear) LICENSE file for most new modules.

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
   lib/foo/foo: $(shell find lib/foo)
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
