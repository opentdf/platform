# OpenTDF Enhancements POC

![CI](https://github.com/opentdf/platform/actions/workflows/checks.yaml/badge.svg?branch=main)

![lint](https://github.com/opentdf/platform/actions/workflows/lint-all.yaml/badge.svg?branch=main)

![Vulnerability Check](https://github.com/opentdf/platform/actions/workflows/vulnerability-check.yaml/badge.svg?branch=main)

## Documentation

- [Home](https://opentdf.github.io/platform)
- [Configuration](./docs/configuration.md)
- [Development](#development)
- [Policy Config Schema](./migrations/20240212000000_schema_erd.md)
- [Policy Config Testing Diagram](./integration/testing_diagram.png)

## Development

### Prerequisites

#### Required

- Go (*see go.mod for specific version*)
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

On macOS, these can be installed with [brew](https://docs.brew.sh/Installation)

`brew install buf grpcurl goose softhsm`

### Run

> [!NOTE]
> Migrations are handled automatically by the server. This can be disabled via the config file, as
> needed. They can also be run manually using the `migrate` command (`go run . migrate -h`).

1. `docker-compose up`
2. Create a OpenTDF config file `cp example-opentdf.yaml opentdf.yaml`
   1. The example file is a good starting point, but you may need to modify it to match your environment.
3. Provision keycloak `go run . provision keycloak`
4. Run the server `go run . start`
   1. *Alt* use the hot-reload development environment `air`
5. The server is now running
   1. The gRPC server will be available at `localhost:9000` (or the port specified in the config file)
   2. The REST server will be available at `localhost:8080` (or the port specified in the config file)

Note: support was added to provision a set of fixture data into the database. Run `go run . provision fixtures -h` for more information.

### Test

```bash
  grpcurl -plaintext localhost:9000 list

  authorization.AuthorizationService
  grpc.reflection.v1.ServerReflection
  grpc.reflection.v1alpha.ServerReflection
  kasregistry.KeyAccessServerRegistryService
  policy.attributes.AttributesService
  policy.namespaces.NamespaceService
  policy.resourcemapping.ResourceMappingService
  policy.subjectmapping.SubjectMappingService

  grpcurl -plaintext localhost:9000 list policy.attributes.AttributesService

  policy.attributes.AttributesService.AssignKeyAccessServerToAttribute
  policy.attributes.AttributesService.AssignKeyAccessServerToValue
  policy.attributes.AttributesService.CreateAttribute
  policy.attributes.AttributesService.CreateAttributeValue
  policy.attributes.AttributesService.DeactivateAttribute
  policy.attributes.AttributesService.DeactivateAttributeValue
  policy.attributes.AttributesService.GetAttribute
  policy.attributes.AttributesService.GetAttributeValue
  policy.attributes.AttributesService.GetAttributesByValueFqns
  policy.attributes.AttributesService.ListAttributeValues
  policy.attributes.AttributesService.ListAttributes
  policy.attributes.AttributesService.RemoveKeyAccessServerFromAttribute
  policy.attributes.AttributesService.RemoveKeyAccessServerFromValue
  policy.attributes.AttributesService.UpdateAttribute
  policy.attributes.AttributesService.UpdateAttributeValue
```

Create Attribute

```bash
grpcurl -plaintext -d @ localhost:9000 attributes.v1.AttributesService/CreateAttribute <<EOM
{
    "definition": {
        "name": "relto",
        "rule":"ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF",
        "values": [
            {
                "value": "test1"
            },
            {
                "value": "test2"
            }
        ],
        "descriptor": {
            "labels": [
                {
                    "key": "test2",
                    "value": "test2"
                },
                {
                    "key": "test3",
                    "value": "test3"
                }
            ],
            "description": "this is a test attribute",
            "namespace": "virtru.com",
            "name": "attribute1",
            "type":"POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION"
        }
    }
}

EOM
```

List Attributes

```bash
grpcurl -plaintext localhost:9000 attributes.v1.AttributesService/ListAttributes
```

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
export OPENTDF_SERVER_HSM_PIN=12345
export OPENTDF_SERVER_HSM_MODULEPATH=/lib/softhsm/libsofthsm2.so
export OPENTDF_SERVER_HSM_KEYS_EC_LABEL=kas-ec
export OPENTDF_SERVER_HSM_KEYS_RSA_LABEL=kas-rsa

pkcs11-tool --module $PKCS11_MODULE_PATH \
            --login --pin ${OPENTDF_SERVER_HSM_PIN} \
            --write-object kas-private.pem --type privkey \
            --label kas-rsa
pkcs11-tool --module $PKCS11_MODULE_PATH \
            --login --pin ${OPENTDF_SERVER_HSM_PIN} \
            --write-object kas-cert.pem --type cert \
            --label kas-rsa

pkcs11-tool --module $PKCS11_MODULE_PATH \
            --login --pin ${OPENTDF_SERVER_HSM_PIN} \
            --write-object ec-private.pem --type privkey \
            --label kas-ec
pkcs11-tool --module $PKCS11_MODULE_PATH \
            --login --pin ${OPENTDF_SERVER_HSM_PIN} \
            --write-object ec-cert.pem --type cert \
            --label kas-ec
```

To see how to generate key pairs that KAS can use, review the [the temp keys init script](.github/scripts/hsm-init-temporary-keys.sh).

### Policy

The policy service is responsible for managing policy configurations. It provides a gRPC API for
creating, updating, and deleting policy configurations.

#### Attributes

##### Namespaces

##### Definitions

##### Values

#### Attribute FQNs

Attribute FQNs are a unique string identifier for an attribute (and its respective parts) that is
used to reference the attribute in policy configurations. Specific places where this will be used:

- TDF attributes
- Key Access Server (KAS) to determine key release
