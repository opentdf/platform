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

Docker [install instructions](https://www.docker.com/get-started/)

[Air](https://github.com/cosmtrek/air) install with go 1.18 or higher:

`go install github.com/cosmtrek/air@v1.49.0`

Install buf, grpcurl and goose:
- [Buf](https://buf.build/docs/ecosystem/cli-overview)
- [grpcurl](https://github.com/fullstorydev/grpcurl)
- [goose](https://github.com/pressly/goose)

On macOS, these can be installed with [brew](https://docs.brew.sh/Installation)

`brew install buf grpcurl goose`

### Run

1. `docker-compose up`

2. `goose -dir=./migrations postgres "postgres://postgres:changeme@localhost:5432/opentdf" up`

3. `cp example-opentdf.yaml opentdf.yaml` and update the values

4. `air`

This should bring up a grpc server on port **9000** and http server on port **8080** (see [example-opentdf.yaml](https://github.com/opentdf/platform/blob/main/example-opentdf.yaml#L38-L43)). Air will watch for changes and restart the server.

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
