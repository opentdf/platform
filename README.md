# OpenTDF

![Vulnerability Check](https://github.com/opentdf/platform/actions/workflows/vulnerability-check.yaml/badge.svg?branch=main)

> [!NOTE]
> It is advised to familiarize yourself with the [terms and concepts](../README.md#terms-and-concepts) used in the
> OpenTDF platform.

## Documentation

- [Configuration](./docs/configuration.md)
- [Development](#development)
- [Policy Config Schema](./service/migrations/20240212000000_schema_erd.md)
- [Policy Config Testing Diagram](./service/integration/testing_diagram.png)

### Prerequisites for Project Consumers & Contributors

- [Go](https://go.dev/) (_see go.mod for specific version_)
- Container runtime
  - [Docker](https://www.docker.com/get-started/)
  - [Podman](https://podman.io/docs/installation)
- Compose - used to manage multi-container applications
  - [Docker Compose](https://docs.docker.com/compose/install/)
  - [Podman Compose](https://github.com/containers/podman-compose)
- [Buf](https://buf.build/docs/ecosystem/cli-overview) is used for managing protobuf files.
  Required for developing services.

On macOS, these can be installed with [brew](https://docs.brew.sh/Installation)

```sh
brew install buf go
```

#### Optional tools

- _Optional_ [Air](https://github.com/cosmtrek/air) is used for hot-reload development
  - install with `go install github.com/cosmtrek/air@latest`  
- _Optional_ [golangci-lint](https://golangci-lint.run/) is used for ensuring good coding practices
  - install with `brew install golangci-lint`
- _Optional_ [grpcurl](https://github.com/fullstorydev/grpcurl) is used for testing gRPC services
  - install with `brew install grpcurl`
- _Optional_ [openssl](https://www.openssl.org/) is used for generating certificates
  - install with `brew install openssl`

## Audience

There are two primary audiences for this project. Consumers and Contributors

1. Consuming
Consumers of the OpenTDF platform should begin their journey [here](./Consuming.md).

2. Contributing
To contribute to the OpenTDF platform, you'll need bit more set setup and should start [here](./Contributing.md).

## Additional info for Project Consumers & Contributors

## For Consumers

The OpenTDF service is the main entry point for the OpenTDF platform. [See service documentation](./service/README.md)
for more information.

### Quick Start

<!-- START copy ./service/README.md#quick-start -->

> [!WARNING]
> This quickstart guide is intended for development and testing purposes only. The OpenTDF platform team does not
> provide recommendations for production deployments.

To get started with the OpenTDF platform make sure you are running the same Go version found in the `go.mod` file.

<!-- markdownlint-disable MD034 github embedded sourcecode -->
https://github.com/opentdf/platform/blob/main/service/go.mod#L3

Start the required infrastructure with [compose-spec](https://compose-spec.io).

```sh
# Note this might be `podman compose` on some systems
docker compose -f docker-compose.yml up
```

Copy the configuration file from the example and update it with your own values.

```sh
cp opentdf-example.yaml opentdf.yaml
```

Provision default configurations.

```sh
# Provision keycloak with the default configuration.
go run ./service provision keycloak
# Generate the temporary keys for KAS
./.github/scripts/init-temp-keys.sh
```

Run the OpenTDF platform service.

```sh
go run ./service start
```
<!-- END copy ./service/README#quick-start -->

## For Contributors

This section is focused on the development of the OpenTDF platform.

### Libraries

Libraries `./lib` are shared libraries that are used across the OpenTDF platform. These libraries are used to provide
common functionality between the various sub-modules of the platform monorepo. Specifically, these libraries are shared
between the services and the SDKs.

### Services

Services `./services` are the core building blocks of the OpenTDF platform. Generally, each service is one or more gRPC services that
are scoped to a namespace. The essence of the service is that it takes a modular binary architecture approach enabling
multiple deployment models.

### SDKs

SDKs `./sdk` are the contracts which the platform uses to ensure that developers and services can interact with the
platform. The SDKs contain a native Go SDK and generated Go service SDKs. A full list of SDKs can be found at
[github.com/opentdf](https://github.com/opentdf).

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

---

## Terms and Concepts

Common terms used in the OpenTDF platform.

**Service** is the core service of the OpenTDF platform as well as the sub-services that make up the platform. The main
service follows a modular binary architecture, while the sub-services are gRPC services with HTTP gateways.

**Policy** is the set of rules that govern access to the platform.

**OIDC** is the OpenID Connect protocol used solely for authentication within the OpenTDF platform.

- **IdP** - Identity Provider. This is the service that authenticates the user.
- **Keycloak** is the turn-key OIDC provider used within the platform for proof-of-value, but should be replaced with a
  production-grade OIDC provider or deployment.

**Attribute Based Access Control** (ABAC) is the policy-based access control model used within the OpenTDF platform.

- PEP - A Policy Enforcement Point. This is a service that enforces access control policies.
- PDP - A Policy Decision Point. This is a service that makes access control decisions.

**Entities** are the main actors within the OpenTDF platform. These include people and systems.

- Person Entity (PE) - A person entity is a person that is interacting with the platform.
- Non Person Entity (NPE) - A non-person entity is a service or system that is interacting with the platform.

**SDKs** are the contracts which the platform uses to ensure that developers and services can interact with the platform.

- SDK - The native Go OpenTDF SDK (other languages are outside the platform repo).
  - A full list of SDKs can be found at [github.com/opentdf](https://github.com/opentdf).
- Service SDK - The SDK generated from the service proto definitions.
  - The proto definitions are maintained by each service.
