# OpenTDF Platform Service

The OpenTDF Platform Service is the main entry point for the OpenTDF platform. It provides the scaffolding for running
OpenTDF and ensures that all required services are configured and running as expected.

> [!NOTE]
> It is advised to familiarize yourself with the [terms and concepts](../README.md#terms-and-concepts) used in the
> OpenTDF platform.

## Quick Start

> [!WARNING]
> This quickstart guide is intended for development and testing purposes only. The OpenTDF platform team does not
> provide recommendations for production deployments.

To get started with the OpenTDF platform make sure you are running the same Go version found in the `go.mod` file.

<!-- markdownlint-disable MD034 github embedded sourcecode -->
https://github.com/opentdf/platform/blob/main/service/go.mod#L3

Start the required infrastructure with [compose-spec](https://compose-spec.io).

```sh
# Note this might be `podman compose` on some systems
docker compose -f docker-compose.yaml up
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

## Services

Services are the core building block of the platform. Generally, each service is one or more gRPC services that scoped
to a namespace.

- *Core Services*
  - Health - Provides rollup health checks for the platform based on the services running.
  - Well Known - Provides well-known endpoints for the platform.
- Authorization - Validates the entity has the correct entitlements based on the policy.
  - Entity Resolution - Resolves entity authorization using connected services (i.e. IdP).
- Key Access (KAS) - Controls access to TDF protected content.
- Policy - Manages the policy for the TDF platform.

## Development

### Generation

Our native gRPC service functions are generated from `proto` definitions using [Buf](https://buf.build/docs/introduction).

The `Makefile` provides command scripts to invoke `Buf` with the `buf.gen.yaml` config, including OpenAPI docs, grpc docs, and the
generated code.

For convenience, the `make toolcheck` script checks if you have the necessary dependencies for `proto -> gRPC` generation.

### Provisioning Custom Keycloak and Policy Data

To provision a custom Keycloak setup, create a yaml following the format of [the sample Keycloak config](service/cmd/keycloak_data.yaml). You can create different realms with separate users, clients, roles, and groups. Run the provisioning with `go run ./service provision keycloak -f <path-to-your-yaml-file>`.

## Developing a new platform service

This guide will help you to develop a new service within the platform. The platform is focused on a modular binary
architecture, so the goal of the service is isolation while also getting the benefits of a shared platform.

### Structure

OpenTDF services are located under the `service` directory. Each service should have a unique directory name which is
expected to relate to the service namespace.

### Service Namespace

A service namespace is a unique identifier for the service. It is used to identify the service in the platform and to
enable multiple gRPC services to be rolled up into a single service.

The namespace should be a unique identifier for the service. It should be a single word, all lowercase, and should not
contain any special characters. It should be the same as the directory name for the service.

### Registration

Services are registered with the platform by implementing the `serviceregistry.IService` interface, and
calling the `serviceregistry.RegisterService` function.

<!-- markdownlint-disable MD034 github embedded sourcecode -->
https://github.com/opentdf/platform/blob/service/v0.5.2/service/pkg/serviceregistry/serviceregistry.go#L69-L80

Notice that `serviceregistry.RegisterService` is called in `server.Start`.

<!-- markdownlint-disable MD034 github embedded sourcecode -->
https://github.com/opentdf/platform/blob/service/v0.5.2/service/pkg/server/start.go#L147-L157

Services will be started if the deployed mode is `all` (the default) or the service name is given
in the `mode`.  Note that `mode` may contain a comma-separated list of services (see below).

<!-- markdownlint-disable MD034 github embedded sourcecode -->
https://github.com/opentdf/platform/blob/service/v0.5.2/opentdf-example.yaml#L11

<!-- markdownlint-disable MD034 github embedded sourcecode -->
https://github.com/opentdf/platform/blob/service/v0.5.2/opentdf-ers-mode.yaml#L3

The mode can be given as a list of strings as well, for instance `core,foo,bar` as 
shown below:

```yaml
mode: core,foo,bar
```

It's important that the service name matches the Namespace of the service.  Optionally, you can
also specify configuration for the service in the `opentdf.yaml` file.  The configuration
is not required, but it is recommended to provide a default configuration for the service.

For example, the `opentdf.yaml` file for a new service called `myservice` might include:

```yaml
services:
  myservice:
    enabled: true
    foo: bar
```